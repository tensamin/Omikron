use super::*;

impl ProvisioningConnection {
    pub(super) async fn abort_password(&self, session: &ProvisioningSession) {
        let request = CommunicationValue::new(CommunicationType::ProvisioningCancel)
            .with_id(rand::random::<u32>().max(1));
        let Ok(message) = build_password_iota_request(&request, session, Vec::new()) else {
            return;
        };
        let Some(account) = &session.account else {
            return;
        };
        if let Some(rho) = self.general.state.rho.get_by_iota(account.iota_id).await {
            let _ = rho
                .get_iota_connection()
                .clone()
                .await_response(&message, Some(Duration::from_secs(2)))
                .await;
        }
    }
    pub(super) async fn password_start(
        &self,
        request: &CommunicationValue,
    ) -> Result<(), &'static str> {
        let id = Self::session_id(request)?;
        let ke1 = request
            .get_data(DataType::OpaqueMessage)
            .and_then(DataValue::as_bytes)
            .ok_or("missing KE1")?;
        if ke1.is_empty()
            || ke1.len() > 16 * 1024
            || iota_opaque::opaque::validate_login_request(&ke1).is_err()
        {
            return Err("invalid KE1");
        }
        let session = self
            .general
            .state
            .provisioning
            .password_start(id, self.general.id())?;
        let account = session.account.as_ref().ok_or("account not bound")?;
        let source = tau::ConnectionFacts::from_mtp(&self.general.mtp_connection)
            .remote_addr
            .map(|address| address.ip());
        let _admission = match self
            .general
            .state
            .provisioning
            .password_admission
            .enter(account.user_id, source)
        {
            Ok(permit) => permit,
            Err(error) => {
                self.terminate_forward(id, ProvisioningFailure::UpstreamUnavailable)
                    .await;
                return Err(error);
            }
        };
        let response = match self.password_forward(request, &session, ke1).await {
            Ok(response) => response,
            Err(error) => {
                self.terminate_forward(id, ProvisioningFailure::UpstreamUnavailable)
                    .await;
                return Err(error);
            }
        };
        if let Ok(failure) = tau::password::Failure::from_frame(&response) {
            let delivered = self.password_delivery(&response, "failure delivery").await;
            self.terminate_forward(
                id,
                if failure.retryable() {
                    ProvisioningFailure::UpstreamUnavailable
                } else {
                    ProvisioningFailure::UpstreamRejected
                },
            )
            .await;
            return delivered;
        }
        if !response.is_type(CommunicationType::PasswordProvisioningResponse)
            || response
                .get_data(DataType::Uuid)
                .and_then(DataValue::as_str)
                != Some(id.to_string().as_str())
            || response
                .get_data(DataType::OpaqueMessage)
                .and_then(DataValue::as_bytes)
                .is_none()
        {
            self.terminate_forward(id, ProvisioningFailure::InvalidUpstreamResponse)
                .await;
            return Err("invalid Iota KE2");
        }
        if self
            .password_delivery(&response, "KE2 delivery")
            .await
            .is_err()
        {
            self.terminate_forward(id, ProvisioningFailure::DeliveryFailed)
                .await;
            return Err("send failed");
        }
        Ok(())
    }

    pub(super) async fn password_finish(
        &self,
        request: &CommunicationValue,
    ) -> Result<(), &'static str> {
        let id = Self::session_id(request)?;
        let ke3 = request
            .get_data(DataType::OpaqueMessage)
            .and_then(DataValue::as_bytes)
            .ok_or("missing KE3")?;
        if ke3.is_empty()
            || ke3.len() > 16 * 1024
            || iota_opaque::opaque::validate_login_finalization(&ke3).is_err()
        {
            return Err("invalid KE3");
        }
        let session = self
            .general
            .state
            .provisioning
            .password_finish(id, self.general.id())?;
        let _admission = match self.general.state.provisioning.password_admission.pending() {
            Ok(permit) => permit,
            Err(error) => {
                self.terminate_forward(id, ProvisioningFailure::UpstreamUnavailable)
                    .await;
                return Err(error);
            }
        };
        let response = match self.password_forward(request, &session, ke3).await {
            Ok(response) => response,
            Err(error) => {
                self.terminate_forward(id, ProvisioningFailure::UpstreamRejected)
                    .await;
                return Err(error);
            }
        };
        if let Ok(failure) = tau::password::Failure::from_frame(&response) {
            let delivered = self.password_delivery(&response, "failure delivery").await;
            self.terminate_forward(
                id,
                if failure.retryable() {
                    ProvisioningFailure::UpstreamUnavailable
                } else {
                    ProvisioningFailure::UpstreamRejected
                },
            )
            .await;
            return delivered;
        }
        if !response.is_type(CommunicationType::ProvisioningCredential)
            || response.receiver() != Some(self.general.id())
            || response.payload().as_encrypted().is_none()
        {
            self.terminate_forward(id, ProvisioningFailure::InvalidUpstreamResponse)
                .await;
            return Err("Iota did not authorize the credential");
        }
        self.general
            .state
            .provisioning
            .password_delivered(id, self.general.id())
            .map_err(|_| "session expired")?;
        if self
            .password_delivery(&response, "credential delivery")
            .await
            .is_err()
        {
            self.terminate_forward(id, ProvisioningFailure::DeliveryFailed)
                .await;
            return Err("send failed");
        }
        Ok(())
    }

    pub(super) async fn password_forward(
        &self,
        request: &CommunicationValue,
        session: &ProvisioningSession,
        opaque: Vec<u8>,
    ) -> Result<CommunicationValue, &'static str> {
        let account = session.account.as_ref().ok_or("account not bound")?;
        let rho = self
            .general
            .state
            .rho
            .get_by_iota(account.iota_id)
            .await
            .ok_or("Iota unavailable")?;
        let message = build_password_iota_request(request, session, opaque)?;
        let started = std::time::Instant::now();
        let response = rho
            .get_iota_connection()
            .clone()
            .await_response(
                &message,
                Some(self.general.state.config.password_upstream_timeout),
            )
            .await
            .map_err(|_| "Iota request failed");
        crate::log!(
            self.general.id() as i64,
            crate::util::logger::PrintType::Client,
            "Password {:?} forwarding took {} ms, completed={}",
            request.get_comm_type_enum(),
            started.elapsed().as_millis(),
            response.is_ok()
        );
        response
    }

    async fn password_delivery(
        &self,
        response: &CommunicationValue,
        stage: &str,
    ) -> Result<(), &'static str> {
        let started = std::time::Instant::now();
        let result = tokio::time::timeout(Duration::from_secs(5), self.sender.send(response)).await;
        crate::log!(
            self.general.id() as i64,
            crate::util::logger::PrintType::Client,
            "Password {} took {} ms",
            stage,
            started.elapsed().as_millis()
        );
        result
            .map_err(|_| "password delivery timed out")?
            .map_err(|_| "password delivery failed")
    }
}

pub(crate) async fn handle_authenticated_login(
    client: &super::super::client_connection::ClientConnection,
    request: &CommunicationValue,
) -> Result<(), &'static str> {
    let participant_id = client.session_id;
    let manager = &client.state.provisioning;
    if !ProvisioningConnection::valid_fields(request) {
        return Err("invalid login fields");
    }
    if request.is_type(CommunicationType::ProvisioningCredential) {
        let session = authorize_qr_credential(manager, participant_id, request)?;
        let contact = session
            .contact
            .and_then(|peer| peer.sender.upgrade())
            .ok_or("contact disconnected")?;
        manager.delivered(session.id, participant_id)?;
        return bounded_send(&contact, request).await;
    }
    let id = ProvisioningConnection::session_id(request)?;
    if request.is_type(CommunicationType::ProvisioningBindAccount) {
        if request.get_data(DataType::UserId).and_then(|value| {
            value
                .as_signed_number()
                .and_then(|id| u64::try_from(id).ok())
                .or_else(|| {
                    value
                        .as_unsigned_number()
                        .and_then(|id| u64::try_from(id).ok())
                })
        }) != Some(client.user_id)
        {
            return Err("claim does not match authenticated user");
        }
        let lookup = CommunicationValue::new(CommunicationType::GetUserData)
            .with_sender(client.state.omega.omikron_id())
            .add_typed_default(
                DataType::UserId,
                DataValue::SignedNumber(client.user_id.into()),
            );
        let response = client
            .state
            .omega
            .clone()
            .await_response(&lookup, Some(Duration::from_secs(20)))
            .await
            .map_err(|_| "account lookup failed")?;
        let string = |field| {
            response
                .get_data(field)
                .and_then(DataValue::as_str)
                .map(str::to_owned)
                .ok_or("invalid account")
        };
        let key = PublicKeyBundle::from_base64(&string(DataType::PublicKey)?)
            .map_err(|_| "invalid account key")?;
        let account = ResolvedAccount {
            user_id: i64::try_from(client.user_id).map_err(|_| "invalid user ID")?,
            username: string(DataType::Username)?,
            principal: string(DataType::Principal)?,
            iota_id: response
                .get_data(DataType::IotaId)
                .and_then(DataValue::as_signed_number)
                .and_then(|value| i64::try_from(value).ok())
                .filter(|value| *value > 0)
                .ok_or("invalid Iota")?,
            public_key: key.clone(),
        };
        let session = manager.claim(
            id,
            ProvisioningParticipant {
                id: participant_id,
                role: ProvisioningRole::Owner,
                temporary_public_key: key,
                sender: Arc::downgrade(&client.sender),
            },
            account.clone(),
        )?;
        let contact = session.contact.ok_or("contact missing")?;
        let sender = contact.sender.upgrade().ok_or("contact disconnected")?;
        let event = account_bound_message(
            id,
            &account,
            &account
                .public_key
                .try_to_base64()
                .map_err(|_| "invalid key")?,
            None,
        );
        let reply = peer_joined_message(id, &contact, request.id())?;
        if deliver_peer_then_reply(
            event,
            reply,
            |event| async move { bounded_send(&sender, &event).await.is_ok() },
            |reply| async move { bounded_send(&client.sender, &reply).await.is_ok() },
        )
        .await
        .is_err()
        {
            manager.remove_participant(participant_id);
            return Err("claim delivery failed");
        }
        return Ok(());
    }
    if request.is_type(CommunicationType::QrProvisioningConfirm) {
        manager.confirm(id, participant_id)?;
    } else if request.is_type(CommunicationType::ProvisioningCancel) {
        let session = manager.snapshot(id, participant_id)?;
        manager.remove_participant(participant_id);
        if let Some(sender) = session.contact.and_then(|peer| peer.sender.upgrade()) {
            let _ = bounded_send(
                &sender,
                &CommunicationValue::new(CommunicationType::ProvisioningCancel)
                    .add_typed_default(DataType::Uuid, DataValue::Str(id.to_string())),
            )
            .await;
        }
    } else {
        return Err("invalid QR operation");
    }
    bounded_send(
        &client.sender,
        &CommunicationValue::new(CommunicationType::Success)
            .with_id(request.id().ok_or("missing request ID")?),
    )
    .await
    .map_err(|_| "reply failed")
}

pub(super) fn build_password_iota_request(
    request: &CommunicationValue,
    session: &ProvisioningSession,
    opaque: Vec<u8>,
) -> Result<CommunicationValue, &'static str> {
    let account = session.account.as_ref().ok_or("account not bound")?;
    let contact = session.contact.as_ref().ok_or("contact not present")?;
    use sha2::{Digest, Sha256};
    let account_fingerprint = Sha256::digest(
        account
            .public_key
            .try_as_bytes()
            .map_err(|_| "invalid account key")?,
    );
    Ok(
        CommunicationValue::new(request.get_comm_type_enum().ok_or("invalid operation")?)
            .with_id(request.id().ok_or("missing request ID")?)
            .add_typed_default(DataType::Uuid, DataValue::Str(session.id.to_string()))
            .add_typed_default(
                DataType::ProvisioningParticipantId,
                DataValue::UnsignedNumber(contact.id.into()),
            )
            .add_typed_default(
                DataType::UserId,
                DataValue::SignedNumber(account.user_id.into()),
            )
            .add_typed_default(
                DataType::IotaId,
                DataValue::SignedNumber(account.iota_id.into()),
            )
            .add_typed_default(
                DataType::PublicKey,
                DataValue::Str(
                    contact
                        .temporary_public_key
                        .try_to_base64()
                        .map_err(|_| "invalid key")?,
                ),
            )
            .add_typed_default(DataType::OpaqueMessage, DataValue::Bytes(opaque))
            .add_typed_default(
                DataType::Sha256,
                DataValue::Bytes(account_fingerprint.to_vec()),
            ),
    )
}
