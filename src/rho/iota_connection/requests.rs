use super::*;

impl IotaConnection {
    pub async fn await_response(
        self: Arc<Self>,
        cv: &CommunicationValue,
        timeout_duration: Option<Duration>,
    ) -> Result<CommunicationValue, String> {
        let receipt_page = relay_router::is_relay_receipt_page(cv);
        let expected = cv
            .type_map()
            .and_then(|map| map.comm_enum_id(cv.get_type().0));
        let timeout = timeout_duration.unwrap_or(Duration::from_secs(10));
        let password_expectation = expected.and_then(tau::password_response_expectation);
        // Read-only forwards can stop without remote reconciliation. Unknown
        // operations default to a durable uncertain intent, never automatic replay.
        let read_only = matches!(
            expected,
            Some(
                CommunicationType::RelayReceiptPage
                    | CommunicationType::AccountStateRequest
                    | CommunicationType::GetChatSecret
                    | CommunicationType::MessageGet
                    | CommunicationType::MessagesGet
                    | CommunicationType::SyncedSettingGet
                    | CommunicationType::SyncedSettingsList
                    | CommunicationType::UserBlobGet
                    | CommunicationType::UserBlobList
                    | CommunicationType::UserAssetUploadStatus
                    | CommunicationType::UserAssetGetChunk
                    | CommunicationType::UserAssetList
                    | CommunicationType::BlockedUsersGet
                    | CommunicationType::ReceiptPolicyGet
                    | CommunicationType::MessageStoragePolicyGet
                    | CommunicationType::PasswordEnrollmentStatus
                    | CommunicationType::CallEnvelopeGet
                    | CommunicationType::CallKeyEnvelopeGet
                    | CommunicationType::CallContactCheck
            )
        );
        // These mutations are replayable by immutable ciphertext or durable
        // operation ID. The call SQLite saga owns retry/reconciliation; a
        // second uncertain-intent journal would block its lost-response retries.
        let replayable_call = matches!(
            expected,
            Some(
                CommunicationType::CallEnvelopeStore
                    | CommunicationType::CallContactAccept
                    | CommunicationType::CallKeyEnvelopeStage
                    | CommunicationType::CallKeyEnvelopeActivate
                    | CommunicationType::CallKeyEnvelopeRevoke
            )
        );
        // OPAQUE exchanges and aborts only consume expiring, single-use state.
        // They do not need durable mutation reconciliation after transport loss.
        let ephemeral_password = matches!(
            expected,
            Some(
                CommunicationType::PasswordEnrollmentStart
                    | CommunicationType::PasswordProvisioningStart
                    | CommunicationType::PasswordProvisioningFinish
                    | CommunicationType::ProvisioningCancel
            )
        );
        let password_mutation = matches!(
            expected,
            Some(
                CommunicationType::PasswordEnrollmentFinish
                    | CommunicationType::PasswordEnrollmentDisable
            )
        );
        let mut reconcile_only = false;
        let journal = if read_only || replayable_call || ephemeral_password {
            None
        } else {
            let journal = crate::omega::MutationJournal::open(&self.mutation_journal_path)?;
            let generation = self
                .state
                .rho
                .get_by_iota(self.iota_id as i64)
                .await
                .and_then(|rho| {
                    cv.sender()
                        .and_then(|user| self.state.rho.user_route_generation(user as i64, &rho))
                });
            let scope = format!("iota:{}", self.iota_id);
            let id =
                if password_mutation && let Some(id) = journal.lookup_attempt(cv, &scope, false)? {
                    reconcile_only = true;
                    id
                } else {
                    journal.begin(cv, &scope, generation)?
                };
            Some((journal, id))
        };
        let mut result = if reconcile_only {
            self.password_mutation_status(cv, timeout).await
        } else {
            self.waiting_tasks
                .exchange(
                    cv,
                    timeout,
                    move |response| {
                        if let Some(expectation) = &password_expectation {
                            return expectation.accepts(response)
                                && (!password_mutation
                                    || response
                                        .get_comm_type_enum()
                                        .is_some_and(tau::is_protocol_error)
                                    || response.payload().as_encrypted().is_some());
                        }
                        if receipt_page && relay_router::is_relay_receipt_page(response) {
                            return true;
                        }
                        let actual = response
                            .type_map()
                            .and_then(|map| map.comm_enum_id(response.get_type().0));
                        actual.is_some() && actual == expected
                            || actual.is_some_and(tau::is_protocol_error)
                            || actual == Some(CommunicationType::Success)
                                && matches!(
                                    expected,
                                    Some(
                                        CommunicationType::Relay
                                            | CommunicationType::ProvisioningCancel
                                            | CommunicationType::AccountStateApplied
                                            | CommunicationType::CallEnvelopeStore
                                            | CommunicationType::CallContactAccept
                                            | CommunicationType::MessageEdit
                                            | CommunicationType::MessageReactionAdd
                                            | CommunicationType::MessageReactionRemove
                                            | CommunicationType::MessageDeleteLive
                                    )
                                )
                            || matches!(
                                (expected, actual),
                                (
                                    Some(CommunicationType::AccountStateRequest),
                                    Some(CommunicationType::AccountStateSnapshot)
                                ) | (
                                    Some(CommunicationType::GetChatSecret),
                                    Some(CommunicationType::ChatSecretResponse)
                                ) | (
                                    Some(CommunicationType::TAuthAuthorize),
                                    Some(CommunicationType::TAuthAuthorizationResult)
                                ) | (
                                    Some(CommunicationType::TAuthExchangeCode),
                                    Some(CommunicationType::TAuthExchangeCodeResponse)
                                )
                            )
                    },
                    |outbound| {
                        let sender = &self.sender;
                        async move { sender.send(&outbound).await }
                    },
                )
                .await
                .map_err(|error| error.to_string())
        };
        if password_mutation
            && !reconcile_only
            && (result.is_err()
                || result.as_ref().is_ok_and(|response| {
                    response
                        .get_comm_type_enum()
                        .is_some_and(tau::is_protocol_error)
                }))
        {
            result = self.password_mutation_status(cv, timeout).await;
        }
        if let (Some((journal, id)), Ok(response)) = (&journal, &result) {
            journal.resolve(id, response)?;
        }
        result
    }

    async fn password_mutation_status(
        &self,
        original: &CommunicationValue,
        timeout: Duration,
    ) -> Result<CommunicationValue, String> {
        let map = original.type_map().ok_or("missing password type map")?;
        let bytes = original
            .clone()
            .without_id()
            .to_bytes()
            .map_err(|error| error.to_string())?;
        if bytes.len() > 512 * 1024 || original.payload().as_encrypted().is_none() {
            return Err("invalid protected password operation".into());
        }
        let mut query =
            CommunicationValue::new_with_type_map(CommunicationType::PasswordEnrollmentStatus, map)
                .add_typed_default(DataType::SecurePayload, DataValue::Bytes(bytes))
                .add_typed_default(DataType::Version, DataValue::Str(map.version.to_string()));
        if let Some(sender) = original.sender() {
            query = query.with_sender(sender);
        }
        let response = self
            .waiting_tasks
            .exchange(
                &query,
                timeout,
                |response| {
                    response.is_type(CommunicationType::PasswordEnrollmentStatus)
                        && response.payload().as_encrypted().is_some()
                        || response
                            .get_comm_type_enum()
                            .is_some_and(tau::is_protocol_error)
                },
                |outbound| async move { self.sender.send(&outbound).await },
            )
            .await
            .map_err(|error| error.to_string())?;
        if !response.is_type(CommunicationType::PasswordEnrollmentStatus)
            || response.payload().as_encrypted().is_none()
        {
            return Err("password mutation outcome remains unresolved".into());
        }
        Ok(match original.id() {
            Some(id) => response.with_id(id),
            None => response.without_id(),
        })
    }

    pub(super) async fn reconcile_password_mutations(&self) -> Result<(), String> {
        let journal = crate::omega::MutationJournal::open(&self.mutation_journal_path)?;
        let pending = journal.password_pending(&format!("iota:{}", self.iota_id))?;
        for (id, original, _historical_generation) in pending {
            journal.password_attempted(&id)?;
            let Some(rho) = self.state.rho.get_by_iota(self.iota_id as i64).await else {
                continue;
            };
            // Routing generations are process-local snapshot counters. A
            // reconnect or unrelated publication must not strand a durable
            // password operation. Check current ownership and destination;
            // Iota independently enforces the receipt's key/auth-generation fence.
            if self.node_id.is_none()
                || !std::ptr::eq(rho.get_iota_connection().as_ref(), self)
                || original.receiver() != Some(self.iota_id)
                || original
                    .sender()
                    .and_then(|user| self.state.rho.user_route_generation(user as i64, &rho))
                    .is_none()
            {
                continue;
            }
            if let Ok(response) = self
                .password_mutation_status(&original, Duration::from_secs(5))
                .await
            {
                journal.resolve(&id, &response)?;
            }
        }
        Ok(())
    }
}
