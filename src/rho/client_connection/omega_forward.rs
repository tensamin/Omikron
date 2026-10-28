use super::*;

impl ClientConnection {
    pub(super) async fn handle_omega_forward(self: Arc<Self>, cv: CommunicationValue) {
        let Ok(request_id) = cv.require_id() else {
            return;
        };
        let delete_user = cv.is_type(CommunicationType::DeleteUser);
        let operation = cv.get_comm_type_enum();
        let started = std::time::Instant::now();
        let updated_key = if cv.is_type(CommunicationType::ChangeUserData) {
            match cv.get_data(DataType::PublicKey) {
                Some(DataValue::Str(key)) => PublicKeyBundle::from_base64(key).ok(),
                _ => None,
            }
        } else {
            None
        };
        match self.await_omega_response(cv).await {
            Ok(response_cv) => {
                let success = response_cv.is_type(CommunicationType::Success);
                if success && let Some(public_key) = updated_key {
                    self.state.omega.cache_authenticated_key(
                        AuthIdentity {
                            kind: AuthIdentityKind::Client,
                            id: self.user_id,
                        },
                        public_key,
                    );
                }
                self.clone().send_message(&response_cv).await;
                if success && delete_user {
                    self.close().await;
                }
            }
            Err(error) => {
                crate::log_event!(
                    self.user_id as i64,
                    PrintType::Client,
                    crate::util::logger::LogLevel::Error,
                    "omega.forward_failed",
                    "operation={:?} message_id={} upstream=omega error_class={} elapsed_ms={} outcome=unknown error={}",
                    operation,
                    request_id,
                    error.code(),
                    started.elapsed().as_millis(),
                    error
                );
                self.send_message(
                    &CommunicationValue::new(CommunicationType::ErrorInternal)
                        .with_id(request_id)
                        .add_typed_default(
                            DataType::ErrorType,
                            DataValue::Str(error.code().into()),
                        ),
                )
                .await;
            }
        }
    }

    pub(super) async fn await_omega_response(
        &self,
        cv: CommunicationValue,
    ) -> Result<CommunicationValue, crate::omega::omega_connection::OmegaRequestError> {
        self.state
            .omega
            .clone()
            .await_response_diagnostic(&cv.with_sender(self.user_id), Some(Duration::from_secs(20)))
            .await
    }

    pub(super) async fn request_set_user_state(
        &self,
        cv: CommunicationValue,
    ) -> Result<CommunicationValue, CommunicationType> {
        let message_id = cv
            .require_id()
            .map_err(|_| CommunicationType::ErrorInvalidData)?;
        if !self.state.omega.is_ready().await {
            return Err(CommunicationType::ErrorInternal);
        }
        let Some(state) = cv
            .get_data(DataType::UserState)
            .as_str()
            .and_then(UserStatus::from_client_preference)
        else {
            return Err(CommunicationType::ErrorInvalidData);
        };
        let Some(_rho) = self.get_rho_connection().await else {
            return Err(CommunicationType::ErrorNoIota);
        };
        let request = CommunicationValue::new(CommunicationType::ChangeUserData)
            .with_id(message_id)
            .with_sender(self.user_id)
            .add_typed_default(DataType::OnlineStatus, DataValue::Str(state.to_string()));
        let response = self
            .state
            .omega
            .await_response_diagnostic(&request, Some(Duration::from_secs(20)))
            .await
            .map_err(|error| {
                crate::log_event!(
                    self.user_id as i64,
                    PrintType::Client,
                    crate::util::logger::LogLevel::Error,
                    "omega.forward_failed",
                    "operation=SetUserState message_id={} error_class={} outcome=unknown error={}",
                    message_id,
                    error.code(),
                    error
                );
                CommunicationType::ErrorInternal
            })?;
        if response.is_type(CommunicationType::Success) {
            return Ok(
                response.add_typed_default(DataType::UserState, DataValue::Str(state.to_string()))
            );
        }
        Ok(response)
    }

    pub(super) async fn handle_set_user_state(self: Arc<Self>, cv: CommunicationValue) {
        let Ok(message_id) = cv.require_id() else {
            return;
        };
        match self.request_set_user_state(cv.clone()).await {
            Ok(response) => self.send_message(&response).await,
            Err(error_type) => self.send_error_response(message_id, error_type).await,
        }
    }
}
