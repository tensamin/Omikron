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
            )
        );
        let journal = if read_only {
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
            let id = journal.begin(cv, &scope, generation)?;
            Some((journal, id))
        };
        let result = self
            .waiting_tasks
            .exchange(
                cv,
                timeout,
                move |response| {
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
                                        | CommunicationType::AccountStateApplied
                                        | CommunicationType::CallEnvelopeStore
                                        | CommunicationType::CallContactAccept
                                        | CommunicationType::MessageEdit
                                        | CommunicationType::MessageReactionAdd
                                        | CommunicationType::MessageReactionRemove
                                        | CommunicationType::MessageDeleteLive
                                        | CommunicationType::PasswordEnrollmentFinish
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
                            ) | (
                                Some(CommunicationType::PasswordEnrollmentStart),
                                Some(CommunicationType::PasswordEnrollmentResponse)
                            ) | (
                                Some(CommunicationType::PasswordProvisioningStart),
                                Some(CommunicationType::PasswordProvisioningResponse)
                            )
                        )
                },
                |outbound| {
                    let sender = &self.sender;
                    async move { sender.send(&outbound).await }
                },
            )
            .await
            .map_err(|error| error.to_string());
        if let (Some((journal, id)), Ok(response)) = (&journal, &result) {
            journal.resolve(id, response)?;
        }
        result
    }
}
