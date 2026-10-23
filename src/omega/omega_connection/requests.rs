use super::*;

impl OmegaConnection {
    pub async fn await_response(
        &self,
        cv: &CommunicationValue,
        timeout_duration: Option<Duration>,
    ) -> Result<CommunicationValue, String> {
        let budget = timeout_duration.unwrap_or(Duration::from_secs(10));
        tokio::time::timeout(budget, self.await_response_bounded(cv, budget))
            .await
            .map_err(|_| {
                "Omega total request budget exceeded; mutation outcome may be uncertain".to_string()
            })?
    }

    pub(crate) fn redemption_publication(
        &self,
        request: &CommunicationValue,
        stage: &str,
    ) -> Result<Option<String>, String> {
        let journal = super::super::MutationJournal::open(&self.mutation_journal_path)?;
        let id = journal.lookup_redemption(request)?;
        if let Some(id) = &id {
            journal.mark_publication(id, stage)?;
        }
        Ok(id)
    }

    pub(crate) fn finish_redemption_publication(&self, id: &str) -> Result<(), String> {
        super::super::MutationJournal::open(&self.mutation_journal_path)?
            .mark_publication(id, "activated")
    }

    pub(super) async fn reconcile_redemption(
        &self,
        request: &CommunicationValue,
    ) -> Result<CommunicationValue, String> {
        let invitation = request
            .get_data(DataType::InvitationId)
            .as_number()
            .filter(|id| *id > 0)
            .ok_or("redemption has no invitation target")?;
        let iota = request
            .get_data(DataType::IotaId)
            .as_number()
            .filter(|id| *id > 0)
            .ok_or("redemption has no Iota target")?;
        let key = request
            .get_data(DataType::PublicKey)
            .as_str()
            .and_then(|key| mtp::crypto::PublicKeyBundle::from_base64(key).ok())
            .ok_or("redemption has no valid public key")?;
        let status_request = CommunicationValue::new(CommunicationType::GetUserInvitationStatus)
            .add_typed_default(DataType::InvitationId, DataValue::SignedNumber(invitation))
            .add_typed_default(DataType::IotaId, DataValue::SignedNumber(iota));
        let status =
            Box::pin(self.await_response(&status_request, Some(Duration::from_secs(10)))).await?;
        if !status.is_type(CommunicationType::GetUserInvitationStatus)
            || status.get_data(DataType::InvitationId).as_number() != Some(invitation)
            || status.get_data(DataType::IotaId).as_number() != Some(iota)
            || !matches!(
                status.get_data(DataType::InvitationState).as_str(),
                Some("provisioning" | "redeemed")
            )
        {
            return Err(
                "redemption remains uncertain; authoritative status does not prove completion"
                    .into(),
            );
        }
        let user = status
            .get_data(DataType::UserId)
            .as_number()
            .and_then(|user| u64::try_from(user).ok())
            .filter(|user| *user > 0)
            .ok_or("authoritative redemption status has no user")?;
        let lookup = CommunicationValue::new(CommunicationType::GetUserData)
            .with_sender(self.omikron_id)
            .add_typed_default(DataType::UserId, DataValue::UnsignedNumber(user.into()));
        let account = Box::pin(self.await_response(&lookup, Some(Duration::from_secs(10)))).await?;
        let registered_key = account
            .get_data(DataType::PublicKey)
            .as_str()
            .and_then(|value| mtp::crypto::PublicKeyBundle::from_base64(value).ok())
            .ok_or("authoritative redemption account has no public key")?;
        if !account.is_type(CommunicationType::GetUserData)
            || account.get_data(DataType::UserId).as_number() != Some(user.into())
            || key.try_as_bytes().map_err(|error| error.to_string())?
                != registered_key
                    .try_as_bytes()
                    .map_err(|error| error.to_string())?
        {
            return Err(
                "authoritative redemption account does not match the intended public key".into(),
            );
        }
        let mut response = CommunicationValue::new(CommunicationType::RedeemUserInvitation)
            .with_id(request.require_id().map_err(|error| error.to_string())?);
        for kind in [
            DataType::InvitationId,
            DataType::IotaId,
            DataType::UserId,
            DataType::InvitationState,
            DataType::InvitationRevision,
        ] {
            if let Some(value) = status.get_data(kind) {
                response = response.add_typed_default(kind, value.clone());
            }
        }
        Ok(response)
    }

    pub(super) async fn await_response_bounded(
        &self,
        cv: &CommunicationValue,
        budget: Duration,
    ) -> Result<CommunicationValue, String> {
        let _permit = self
            .request_slots
            .acquire()
            .await
            .map_err(|_| "Omega request queue is unavailable".to_string())?;

        if !self.circuit_breaker.lock().await.allow_request() {
            return Err("Omega circuit breaker is open".to_string());
        }

        let result = self.await_response_inner(cv, Some(budget)).await;
        let mut breaker = self.circuit_breaker.lock().await;
        if result.is_ok() {
            breaker.record_success();
        } else {
            breaker.record_failure();
        }
        result
    }

    pub(super) async fn await_response_inner(
        &self,
        cv: &CommunicationValue,
        timeout_duration: Option<Duration>,
    ) -> Result<CommunicationValue, String> {
        let original_id = cv
            .require_id()
            .map_err(|error| format!("request is missing correlation id: {error}"))?;
        #[cfg(test)]
        let scripted = self.test_requests.lock().unwrap().clone();
        #[cfg(test)]
        let wait_for_connection = scripted.is_none();
        #[cfg(not(test))]
        let wait_for_connection = true;
        if wait_for_connection {
            self.await_connection(timeout_duration).await?;
        }

        // Omega uses the request type for data responses, and explicit Success
        // for acknowledgements. These mappings belong to the Omega consumer.
        let request_type = cv
            .get_comm_type_enum()
            .ok_or("unmapped Omega request type")?;
        let allowed_success = match request_type {
            CommunicationType::UserConnected
            | CommunicationType::IotaConnected
            | CommunicationType::StateSubscribe
            | CommunicationType::SyncClientIotaStatus
            | CommunicationType::DeleteUser
            | CommunicationType::DeleteIota
            | CommunicationType::UserDisconnected
            | CommunicationType::IotaDisconnected
            | CommunicationType::ClientChanged
            | CommunicationType::ChangeUserData
            | CommunicationType::CompleteRegisterUser
            | CommunicationType::RevokeUserInvitation
            | CommunicationType::AttachUserComplete
            | CommunicationType::DeleteUserCredentialComplete
            | CommunicationType::EraseHostedUserDataAck
            | CommunicationType::AcknowledgeIotaUserProvision
            | CommunicationType::ReleaseUserFromIota
            | CommunicationType::Relay => vec![CommunicationType::Success],
            CommunicationType::AttachUserBegin => vec![CommunicationType::AttachUserChallenge],
            CommunicationType::DeleteUserCredentialBegin => {
                vec![CommunicationType::DeleteUserCredentialChallenge]
            }
            CommunicationType::GetUserData
            | CommunicationType::GetIotaData
            | CommunicationType::GetRegister
            | CommunicationType::CompleteRegisterIota
            | CommunicationType::CreateUserInvitation
            | CommunicationType::ListUserInvitations
            | CommunicationType::RedeemUserInvitation
            | CommunicationType::GetUserInvitationStatus
            | CommunicationType::ShortenLink
            | CommunicationType::GetNotifications
            | CommunicationType::ReadNotification
            | CommunicationType::PushNotification
            | CommunicationType::GetStates => vec![request_type],
            _ => Vec::new(),
        };

        let (tx, rx) = oneshot::channel();
        // Responses are remapped to the requester's original id on delivery.
        let pending = self
            .waiting_tasks
            .reserve_checked(
                move |response| {
                    let _ = tx.send(response.with_id(original_id));
                    true
                },
                tau::ResponseExpectation {
                    allowed_success,
                    allowed_errors: tau::PROTOCOL_ERROR_TYPES.to_vec(),
                },
            )
            .map_err(|error| format!("no Omega request id available: {error}"))?;
        // A cancelled requester must not leave a response callback behind.
        let omega_id = pending.id();

        let timeout = timeout_duration.unwrap_or(Duration::from_secs(10));
        let deadline = tokio::time::Instant::now() + timeout;

        let outbound = cv.clone().with_id(omega_id);
        // Preparation failures cannot have mutated Omega. Persist the intent only
        // once the connection and response waiter are ready, before any send.
        let journal = if super::super::reconciliation::requires_reconciliation(cv) {
            let journal =
                super::super::reconciliation::MutationJournal::open(&self.mutation_journal_path)?;
            let existing = if cv.is_type(CommunicationType::RedeemUserInvitation) {
                journal.lookup_redemption(cv)?
            } else {
                journal.lookup_attempt(
                    cv,
                    "omega",
                    cv.is_type(CommunicationType::CompleteRegisterIota),
                )?
            };
            let id = match existing {
                Some(id) if cv.is_type(CommunicationType::RedeemUserInvitation) => {
                    let response = self.reconcile_redemption(cv).await?;
                    journal.resolve(&id, &response)?;
                    return Ok(response);
                }
                // Omega serializes exact public-key get-or-create and returns
                // the same Iota ID. This is the only direct mutation retry.
                Some(id) if cv.is_type(CommunicationType::CompleteRegisterIota) => id,
                Some(id) => {
                    return Err(format!(
                        "Remote operation {id} remains uncertain; authoritative reconciliation required"
                    ));
                }
                None => journal.begin(cv, "omega", None)?,
            };
            Some((journal, id))
        } else {
            None
        };
        #[cfg(test)]
        if let Some(requests) = scripted {
            let (response, receive) = oneshot::channel();
            requests
                .send((cv.clone(), response))
                .map_err(|_| "test Omega stopped".to_string())?;
            let response = receive
                .await
                .map_err(|_| "test Omega response cancelled".to_string())??;
            if let Some((journal, id)) = &journal {
                journal.resolve(id, &response)?;
            }
            return Ok(response);
        }
        if let Err(error) = tokio::time::timeout_at(deadline, self.try_send_message(&outbound))
            .await
            .map_err(|_| "Request timed out".to_string())?
        {
            return Err(format!("failed to send request: {error}"));
        }
        log_out!(
            0,
            PrintType::Omega,
            "Sent Omega request (request_id={}, original_id={}, type={})",
            omega_id,
            original_id,
            outbound
                .get_comm_type_enum()
                .map(|kind| kind.to_string())
                .unwrap_or_else(|| outbound.get_type().to_string())
        );

        let result = match tokio::time::timeout_at(deadline, rx).await {
            Ok(Ok(response_cv)) => Ok(response_cv),
            Ok(Err(_)) => Err("Channel closed".to_string()),
            Err(_) => Err("Request timed out".to_string()),
        };
        if let (Some((journal, id)), Ok(response)) = (&journal, &result) {
            journal.resolve(id, response)?;
        }
        result
    }
}
