use crate::anonymous_clients::anonymous_manager;
use crate::app_state::AppState;
use crate::calls::call_group::call_invite_secret_from_cv;
use crate::data::user::UserStatus;
use crate::rho::connection::{GeneralConnection, MtpReceiver, MtpSender};
use crate::rho::rho_connection::RhoConnection;
use crate::util::logger::PrintType;
use crate::{log_cv_in, log_cv_out, log_err, log_in, log_out};
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use trust_dns_resolver::TokioAsyncResolver;
use uuid::Uuid;

pub struct ClientConnection {
    pub state: Arc<AppState>,
    pub user_id: u64,
    pub session_id: u64,
    pub client_version: String,

    pub sender: Arc<MtpSender>,
    pub receiver: Arc<MtpReceiver>,
    pub_key: Arc<RwLock<Option<Vec<u8>>>>,
    pub rho_connection: Arc<RwLock<Option<Arc<RhoConnection>>>>,
    is_open: Arc<RwLock<bool>>,
    message_slots: Arc<tokio::sync::Semaphore>,
}

impl ClientConnection {
    pub async fn from_general(general: Arc<GeneralConnection>, user_id: u64) -> Arc<Self> {
        Arc::new(Self {
            state: general.state.clone(),
            pub_key: Arc::new(RwLock::new(None)),
            rho_connection: general.rho_connection.clone(),
            is_open: Arc::new(RwLock::new(true)),
            sender: general.sender.clone(),
            receiver: general.receiver.clone(),
            user_id: user_id,
            session_id: general.session_id.read().await.clone(),
            client_version: general.client_version.read().await.clone(),
            message_slots: Arc::new(tokio::sync::Semaphore::new(32)),
        })
    }
    pub fn start(self: Arc<Self>) {
        let self_clone = self.clone();
        tokio::spawn(async move {
            while let Ok(cv) = self_clone.receiver.receive().await {
                self_clone.clone().handle_message(cv).await;
            }
            self_clone.handle_close().await;
        });

        let self_clone2 = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            if self_clone2.get_rho_connection().await.is_none() {
                self_clone2
                    .send_error_response(0, CommunicationType::ErrorNoIota)
                    .await;
            }
        });
    }

    /// Get the user ID
    pub async fn get_user_id(&self) -> u64 {
        self.user_id
    }

    /// Get RhoConnection if available
    pub async fn get_rho_connection(&self) -> Option<Arc<RhoConnection>> {
        self.rho_connection.read().await.clone()
    }

    pub async fn set_rho_connection(&self, rho_connection: Arc<RhoConnection>) {
        *self.rho_connection.write().await = Some(rho_connection);
    }

    /// A membership snapshot can remove an account from an Iota while keeping
    /// its authenticated Omega connection alive.
    pub async fn clear_rho_connection(&self) {
        *self.rho_connection.write().await = None;
    }

    /// Send a CommunicationValue to the client
    pub async fn send_message(self: Arc<Self>, cv: &CommunicationValue) {
        if !*self.is_open.read().await {
            log_out!(
                self.user_id as i64,
                PrintType::Client,
                "Attempted to send message to a closed connection."
            );
            return;
        }
        log_cv_out!(PrintType::Client, &cv);
        let _ = self.sender.send(&cv).await;
    }

    /// Handle incoming message from client
    pub async fn handle_message(self: Arc<Self>, cv: CommunicationValue) {
        let Ok(permit) = self.message_slots.clone().acquire_owned().await else {
            return;
        };
        tokio::spawn(async move {
            let _permit = permit;
            log_cv_in!(PrintType::Client, cv);

            let mut cv = cv;

            if cv.is_type(CommunicationType::SetUserState) {
                self.handle_set_user_state(cv).await;
                return;
            }

            // Compatibility for clients predating SetUserState.  The target
            // user fields, if present, are deliberately ignored: an
            // authenticated connection may only change its own state.
            if cv.is_type(CommunicationType::ClientChanged)
                && cv.get_data_opt(DataType::UserState).is_some()
            {
                self.handle_set_user_state(
                    CommunicationValue::new(CommunicationType::SetUserState)
                        .with_id(cv.get_id())
                        .add_typed_default(
                            DataType::UserState,
                            cv.get_data(DataType::UserState).clone(),
                        ),
                )
                .await;
                return;
            }

            // Handle call invites
            if cv.is_type(CommunicationType::CallInvite) {
                self.handle_call_invite(cv).await;
                return;
            }

            // Handle get call requests
            if cv.is_type(CommunicationType::CallToken) {
                self.handle_get_call(cv).await;
                return;
            }

            if cv.is_type(CommunicationType::CallData) {
                self.handle_get_call_data(cv).await;
                return;
            }

            if cv.is_type(CommunicationType::CallDisconnectUser) {
                self.handle_call_disconnect_user(cv).await;
                return;
            }

            if cv.is_type(CommunicationType::CallTimeoutUser) {
                self.handle_call_timeout_user(cv).await;
                return;
            }

            if cv.is_type(CommunicationType::CallSetAnonymousJoining) {
                self.handle_call_set_anonymous_joining(cv).await;
                return;
            }
            if cv.is_type(CommunicationType::LoadTxtRecord) {
                self.handle_load_txt_record(cv).await;
                return;
            }
            if cv.is_type(CommunicationType::GetUserData) {
                if let Some(anonymous) = {
                    if let Some(user_id) = cv.get_data(DataType::UserId).as_signed_number() {
                        anonymous_manager::get_anonymous_user(user_id as u64).await
                    } else if let Some(username) = cv.get_data(DataType::Username).as_str() {
                        anonymous_manager::get_anonymous_user_by_name(username.to_string()).await
                    } else {
                        None
                    }
                } {
                    let response = CommunicationValue::new(CommunicationType::GetUserData)
                        .with_id(cv.get_id())
                        .add_typed_default(
                            DataType::Username,
                            DataValue::Str(anonymous.get_user_name().await),
                        )
                        .add_typed_default(
                            DataType::UserId,
                            DataValue::SignedNumber(anonymous.get_user_id().into()),
                        )
                        .add_typed_default(
                            DataType::Display,
                            DataValue::Str(anonymous.get_display_name().await),
                        )
                        .add_typed_default(
                            DataType::Avatar,
                            DataValue::Str(anonymous.get_avatar().await),
                        )
                        .add_typed_default(
                            DataType::UserState,
                            DataValue::Str("online".to_string()),
                        );

                    self.send_message(&response).await;

                    return;
                }
            }

            if cv.is_type(CommunicationType::ChangeUserData)
                || cv.is_type(CommunicationType::ReadNotification)
                || cv.is_type(CommunicationType::GetNotifications)
                || cv.is_type(CommunicationType::GetUserData)
                || cv.is_type(CommunicationType::GetIotaData)
                || cv.is_type(CommunicationType::DeleteUser)
            {
                if cv.is_type(CommunicationType::ChangeUserData)
                    && cv.get_data_opt(DataType::OnlineStatus).is_some()
                {
                    let mut profile_request = cv.clone();
                    let preference = profile_request.remove_data(DataType::OnlineStatus);
                    let state_request = CommunicationValue::new(CommunicationType::SetUserState)
                        .with_id(cv.get_id())
                        .add_typed_default(DataType::UserState, preference.unwrap());
                    let state_response = match self.request_set_user_state(state_request).await {
                        Ok(response) => response,
                        Err(error_type) => {
                            self.send_error_response(cv.get_id(), error_type).await;
                            return;
                        }
                    };
                    if !state_response.is_type(CommunicationType::Success) {
                        self.send_message(&state_response).await;
                        return;
                    }

                    if profile_request.data_len() == 0 {
                        self.send_message(&state_response).await;
                        return;
                    }

                    match self
                        .await_omega_response(profile_request.with_sender(self.user_id))
                        .await
                    {
                        Ok(response) if response.is_type(CommunicationType::Success) => {
                            self.send_message(&response).await;
                        }
                        Ok(response) => self.send_message(&response).await,
                        Err(_) => {
                            self.send_error_response(cv.get_id(), CommunicationType::ErrorInternal)
                                .await;
                        }
                    }
                    return;
                }
                let sender = self.get_user_id().await;
                self.handle_omega_forward(cv.with_sender(sender as u64))
                    .await;
                return;
            }

            let is_per_device_settings = cv.is_type(CommunicationType::SettingsSave)
                || cv.is_type(CommunicationType::SettingsLoad)
                || cv.is_type(CommunicationType::SettingsList);
            let is_global_settings = cv.is_type(CommunicationType::GlobalSettingsSave)
                || cv.is_type(CommunicationType::GlobalSettingsLoad);

            if is_per_device_settings || is_global_settings {
                let expected_session_id: i128 = self.session_id.into();
                let session_id = cv.get_data(DataType::SessionId).as_signed_number();

                if is_per_device_settings {
                    let Some(session_id) = session_id else {
                        let response = CommunicationValue::new(CommunicationType::ErrorInvalidData)
                            .with_id(cv.get_id())
                            .with_receiver(self.user_id)
                            .add_typed_default(
                                DataType::Message,
                                DataValue::Str("Missing session_id".to_string()),
                            )
                            .add_typed_default(
                                DataType::SessionId,
                                DataValue::SignedNumber(expected_session_id),
                            );
                        self.send_message(&response).await;
                        return;
                    };

                    if session_id != expected_session_id {
                        let response = CommunicationValue::new(CommunicationType::ErrorInvalidData)
                            .with_id(cv.get_id())
                            .with_receiver(self.user_id)
                            .add_typed_default(
                                DataType::Message,
                                DataValue::Str("session_id mismatch".to_string()),
                            )
                            .add_typed_default(
                                DataType::SessionId,
                                DataValue::SignedNumber(expected_session_id),
                            );
                        self.send_message(&response).await;
                        return;
                    }
                } else if let Some(session_id) = session_id {
                    if session_id != expected_session_id {
                        let response = CommunicationValue::new(CommunicationType::ErrorInvalidData)
                            .with_id(cv.get_id())
                            .with_receiver(self.user_id)
                            .add_typed_default(
                                DataType::Message,
                                DataValue::Str("session_id mismatch".to_string()),
                            )
                            .add_typed_default(
                                DataType::SessionId,
                                DataValue::SignedNumber(expected_session_id),
                            );
                        self.send_message(&response).await;
                        return;
                    }
                } else {
                    cv = cv.add_typed_default(
                        DataType::SessionId,
                        DataValue::SignedNumber(expected_session_id),
                    );
                }
            }

            // Every Iota request is bound to the authenticated device.  A
            // caller may omit the field for compatibility, but can never
            // select a different device session.
            let expected_session_id = self.session_id as i128;
            if let Some(session_id) = cv.get_data(DataType::SessionId).as_signed_number() {
                if session_id != expected_session_id {
                    let response = CommunicationValue::new(CommunicationType::ErrorInvalidData)
                        .with_id(cv.get_id())
                        .add_typed_default(
                            DataType::SessionId,
                            DataValue::SignedNumber(expected_session_id),
                        );
                    self.send_message(&response).await;
                    return;
                }
            } else {
                cv = cv.add_typed_default(
                    DataType::SessionId,
                    DataValue::SignedNumber(expected_session_id),
                );
            }

            // Forward other messages to Iota
            self.forward_to_iota(cv).await;
        });
    }
    async fn handle_omega_forward(self: Arc<Self>, cv: CommunicationValue) {
        let request_id = cv.get_id();
        match self.await_omega_response(cv).await {
            Ok(response_cv) => self.send_message(&response_cv).await,
            Err(_) => {
                self.send_error_response(request_id, CommunicationType::ErrorInternal)
                    .await;
            }
        }
    }

    async fn await_omega_response(&self, cv: CommunicationValue) -> Result<CommunicationValue, ()> {
        self.state
            .omega
            .clone()
            .await_response(&cv.with_sender(self.user_id), Some(Duration::from_secs(20)))
            .await
            .map_err(|_| ())
    }

    async fn request_set_user_state(
        &self,
        cv: CommunicationValue,
    ) -> Result<CommunicationValue, CommunicationType> {
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
        let Some(rho) = self.get_rho_connection().await else {
            return Err(CommunicationType::ErrorNoIota);
        };
        let request = if self.state.omega.supports_set_user_state().await {
            CommunicationValue::new(CommunicationType::SetUserState)
                .with_id(cv.get_id())
                .with_sender(self.user_id)
                .add_typed_default(
                    DataType::UserId,
                    DataValue::SignedNumber(self.user_id as i128),
                )
                .add_typed_default(
                    DataType::SessionId,
                    DataValue::SignedNumber(self.session_id as i128),
                )
                .add_typed_default(
                    DataType::IotaId,
                    DataValue::SignedNumber(rho.get_iota_id().await as i128),
                )
                .add_typed_default(DataType::UserState, DataValue::Str(state.to_string()))
        } else {
            // Legacy Omega accepts the original ClientChanged request. It is
            // intentionally limited to the authenticated user's ID and a
            // writable preference, with no derived connectivity state.
            CommunicationValue::new(CommunicationType::ClientChanged)
                .with_id(cv.get_id())
                .with_sender(self.user_id)
                .add_typed_default(
                    DataType::UserId,
                    DataValue::SignedNumber(self.user_id as i128),
                )
                .add_typed_default(DataType::UserState, DataValue::Str(state.to_string()))
        };
        if !self.state.omega.supports_set_user_state().await {
            self.state
                .omega
                .send_message_result(&request)
                .await
                .map_err(|_| CommunicationType::ErrorInternal)?;
            return Ok(CommunicationValue::new(CommunicationType::Success)
                .with_id(cv.get_id())
                .add_typed_default(DataType::UserState, DataValue::Str(state.to_string())));
        }
        self.await_omega_response(request)
            .await
            .map_err(|_| CommunicationType::ErrorInternal)
    }

    async fn handle_set_user_state(self: Arc<Self>, cv: CommunicationValue) {
        match self.request_set_user_state(cv.clone()).await {
            Ok(response) => self.send_message(&response).await,
            Err(error_type) => self.send_error_response(cv.get_id(), error_type).await,
        }
    }

    /// Handle call invite
    async fn handle_call_invite(self: Arc<Self>, cv: CommunicationValue) {
        let receiver_id: i128 = cv.get_data(DataType::ReceiverId).as_number().unwrap_or(0);
        if receiver_id == 0 {
            self.send_error_response(cv.get_id(), CommunicationType::ErrorNoUserId)
                .await;
            return;
        }

        let call_id = match cv.get_data(DataType::CallId) {
            DataValue::Str(id_str) => match Uuid::parse_str(id_str.as_str()) {
                Ok(id) => id,
                Err(_) => {
                    self.send_error_response(cv.get_id(), CommunicationType::ErrorInvalidCallId)
                        .await;
                    return;
                }
            },
            _ => {
                self.send_error_response(cv.get_id(), CommunicationType::ErrorNoCallId)
                    .await;
                return;
            }
        };

        let secret = match call_invite_secret_from_cv(&cv) {
            Some(secret) => secret,
            None => {
                self.send_error_response(cv.get_id(), CommunicationType::BadRequest)
                    .await;
                return;
            }
        };
        let invited = self
            .state
            .call_manager
            .add_invite(call_id, self.user_id, receiver_id as u64, secret.clone())
            .await;
        if !invited {
            self.send_error_response(cv.get_id(), CommunicationType::ErrorInvalidCallId)
                .await;
            return;
        }

        if !self
            .state
            .call_manager
            .should_forward_invite(self.user_id, receiver_id as u64)
        {
            let response = CommunicationValue::new(CommunicationType::Success).with_id(cv.get_id());
            self.send_message(&response).await;
            return;
        }

        // Find target RhoConnection
        let target_rho = match self.state.rho.get_for_user(receiver_id as i64).await {
            Some(rho) => rho,
            _ => {
                // Get sender user ID
                let sender_id = self.get_user_id().await;

                // User is offline - send push notification for call invite
                let push_cv = CommunicationValue::new(CommunicationType::PushNotification)
                    .with_receiver(receiver_id as u64)
                    .add_typed_default(
                        DataType::SenderId,
                        DataValue::SignedNumber(sender_id.into()),
                    )
                    .add_typed_default(DataType::CallId, DataValue::Str(call_id.to_string()))
                    .add_typed_default(
                        DataType::Notifications,
                        DataValue::Str("call_invite".to_string()),
                    );

                let omega_conn = self.state.omega.clone();
                // Send fire-and-forget, don't await to avoid blocking
                tokio::spawn(async move {
                    let _ = omega_conn.send_message(&push_cv).await;
                });

                let error_cv = CommunicationValue::new(CommunicationType::ErrorNotFound)
                    .with_id(cv.get_id())
                    .add_typed_default(
                        DataType::ReceiverId,
                        DataValue::SignedNumber(receiver_id.into()),
                    );
                self.send_message(&error_cv).await;
                return;
            }
        };

        // Get sender user ID
        let sender_id = self.get_user_id().await as i64;

        // Create and send call distribution message
        let forward = CommunicationValue::new(CommunicationType::CallInvite)
            .with_receiver(receiver_id as u64)
            .with_sender(sender_id as u64)
            .add_typed_default(DataType::CallSecret, secret.to_data_value())
            .add_typed_default(DataType::CallId, DataValue::Str(call_id.to_string()))
            .add_typed_default(
                DataType::ReceiverId,
                DataValue::SignedNumber(receiver_id.into()),
            )
            .add_typed_default(
                DataType::SenderId,
                DataValue::SignedNumber(sender_id.into()),
            );

        target_rho.message_to_client(forward).await;

        let response = CommunicationValue::new(CommunicationType::Success).with_id(cv.get_id());
        self.send_message(&response).await;
    }

    /// Handle get call request
    async fn handle_get_call(self: Arc<Self>, cv: CommunicationValue) {
        let user_id = self.get_user_id().await;

        let call_id = match cv.get_data(DataType::CallId) {
            DataValue::Str(id_str) => match Uuid::parse_str(id_str.as_str()) {
                Ok(id) => id,
                Err(_) => {
                    self.send_error_response(cv.get_id(), CommunicationType::ErrorInvalidCallId)
                        .await;
                    return;
                }
            },
            _ => {
                self.send_error_response(cv.get_id(), CommunicationType::ErrorNoCallId)
                    .await;
                return;
            }
        };

        match self
            .state
            .call_manager
            .get_call_token(user_id, call_id)
            .await
        {
            Ok(token) => {
                let response = CommunicationValue::new(CommunicationType::CallToken)
                    .with_id(cv.get_id())
                    .with_receiver(user_id as u64)
                    .add_typed_default(DataType::CallToken, DataValue::Str(token));
                self.send_message(&response).await;
            }
            Err(error) => {
                log::warn!("Unable to create call token for {}: {}", call_id, error);
                let error_cv = CommunicationValue::new(CommunicationType::ErrorNoCallId)
                    .with_id(cv.get_id())
                    .add_typed_default(DataType::CallId, DataValue::Str(call_id.to_string()));
                self.send_message(&error_cv).await;
            }
        }
    }
    async fn handle_get_call_data(self: Arc<Self>, cv: CommunicationValue) {
        let user_id = self.get_user_id().await;

        let call_id = match cv.get_data(DataType::CallId) {
            DataValue::Str(id_str) => match Uuid::parse_str(id_str.as_str()) {
                Ok(id) => id,
                Err(_) => {
                    self.send_error_response(cv.get_id(), CommunicationType::ErrorInvalidCallId)
                        .await;
                    return;
                }
            },
            _ => {
                self.send_error_response(cv.get_id(), CommunicationType::ErrorNoCallId)
                    .await;
                return;
            }
        };

        if let Some(call) = self.state.call_manager.get_call(call_id).await {
            if let Some(_) = call.get_caller(user_id).await {
                let mut user_ids: Vec<DataValue> = Vec::new();
                let members = call.members.read().await.clone();
                for member in members {
                    if member.user_id == user_id {
                        user_ids.push(DataValue::SignedNumber(member.user_id.into()));
                    }
                }

                let response = CommunicationValue::new(CommunicationType::CallData)
                    .with_id(cv.get_id())
                    .with_receiver(user_id as u64)
                    .add_typed_default(DataType::UserIds, DataValue::Array(user_ids));
                self.send_message(&response).await;
            } else {
                let error_cv = CommunicationValue::new(CommunicationType::ErrorInvalidUserId)
                    .with_id(cv.get_id())
                    .add_typed_default(DataType::UserId, DataValue::SignedNumber(user_id.into()));
                self.send_message(&error_cv).await;
                return;
            }
        } else {
            let error_cv = CommunicationValue::new(CommunicationType::ErrorNotFound)
                .with_id(cv.get_id())
                .add_typed_default(DataType::CallId, DataValue::Str(call_id.to_string()));
            self.send_message(&error_cv).await;
            return;
        }
    }

    async fn handle_call_timeout_user(self: Arc<Self>, cv: CommunicationValue) {
        let Ok(call_id) = Uuid::from_str(cv.get_data(DataType::CallId).as_str().unwrap_or(""))
        else {
            self.send_error_response(cv.get_id(), CommunicationType::ErrorInvalidCallId)
                .await;
            return;
        };
        let user_id = cv
            .get_data(DataType::UserId)
            .as_signed_number()
            .unwrap_or(0);
        let untill = cv
            .get_data(DataType::Untill)
            .as_signed_number()
            .unwrap_or(0);

        let Some(call) = self.state.call_manager.get_call(call_id).await else {
            self.send_error_response(cv.get_id(), CommunicationType::ErrorNotFound)
                .await;
            return;
        };

        let Some(caller) = call.get_caller(self.get_user_id().await).await else {
            self.send_error_response(cv.get_id(), CommunicationType::ErrorInvalidUserId)
                .await;
            return;
        };
        if caller.has_admin() {
            let _ = self
                .state
                .livekit
                .remove_participant(call_id, user_id as u64)
                .await;
            if let Some(target) = call.get_caller(user_id as u64).await {
                target.set_timeout(untill as i64).await;
            }
        }
    }
    async fn handle_call_disconnect_user(self: Arc<Self>, cv: CommunicationValue) {
        let Ok(call_id) = Uuid::from_str(cv.get_data(DataType::CallId).as_str().unwrap_or(""))
        else {
            self.send_error_response(cv.get_id(), CommunicationType::ErrorInvalidCallId)
                .await;
            return;
        };
        let user_id = cv
            .get_data(DataType::UserId)
            .as_signed_number()
            .unwrap_or(0);

        let Some(call) = self.state.call_manager.get_call(call_id).await else {
            self.send_error_response(cv.get_id(), CommunicationType::ErrorNotFound)
                .await;
            return;
        };
        let Some(caller) = call.get_caller(self.get_user_id().await).await else {
            self.send_error_response(cv.get_id(), CommunicationType::ErrorInvalidUserId)
                .await;
            return;
        };
        if caller.has_admin() {
            call.remove_caller(user_id as u64).await;
        }
    }
    async fn handle_call_set_anonymous_joining(self: Arc<Self>, cv: CommunicationValue) {
        let Ok(call_id) = Uuid::from_str(cv.get_data(DataType::CallId).as_str().unwrap_or(""))
        else {
            self.send_error_response(cv.get_id(), CommunicationType::ErrorInvalidCallId)
                .await;
            return;
        };
        let enable = cv.get_data(DataType::Enabled).as_bool().unwrap_or(true);

        let call = self.state.call_manager.get_call(call_id).await;

        let mut short_link = None;
        if let Some(call) = call {
            if let Some(caller) = call.get_caller(self.get_user_id().await).await {
                if caller.has_admin() {
                    call.set_anonymous_joining(
                        enable,
                        &self.state.omega,
                        self.state.config.omikron_id,
                    )
                    .await;
                }
            }
            short_link = call.get_short_link().await;
        }
        let mut response_cv = CommunicationValue::new(CommunicationType::CallSetAnonymousJoining)
            .with_id(cv.get_id())
            .add_typed_default(DataType::CallId, DataValue::Str(call_id.to_string()))
            .add_typed_default(DataType::Enabled, DataValue::Bool(enable));
        if let Some(short_link) = short_link {
            response_cv = response_cv.add_typed_default(DataType::Link, DataValue::Str(short_link));
        }
        self.send_message(&response_cv).await;
    }

    async fn handle_load_txt_record(self: Arc<Self>, cv: CommunicationValue) {
        if let Some(path) = cv.get_data(DataType::Path).as_str() {
            let resolver = match TokioAsyncResolver::tokio_from_system_conf() {
                Ok(r) => r,
                Err(_) => {
                    let path_data = cv.get_data(DataType::Path).clone();
                    let error_cv = CommunicationValue::new(CommunicationType::ErrorNotFound)
                        .with_id(cv.get_id())
                        .add_typed_default(DataType::Path, path_data);
                    self.send_message(&error_cv).await;
                    return;
                }
            };

            match resolver.txt_lookup(path).await {
                Ok(txt_lookup) => {
                    if let Some(txt_record) = txt_lookup.iter().next() {
                        let record_bytes: Vec<u8> = txt_record
                            .txt_data()
                            .iter()
                            .flat_map(|chunk| chunk.iter().copied())
                            .collect();
                        let record_text = match String::from_utf8(record_bytes) {
                            Ok(text) => text,
                            Err(_) => {
                                self.send_error_response(
                                    cv.get_id(),
                                    CommunicationType::ErrorInvalidData,
                                )
                                .await;
                                return;
                            }
                        };

                        let response = CommunicationValue::new(CommunicationType::LoadTxtRecord)
                            .with_id(cv.get_id())
                            .add_typed_default(DataType::Content, DataValue::Str(record_text));
                        self.send_message(&response).await;
                        return;
                    }

                    let path_data = cv.get_data(DataType::Path).clone();
                    let error_cv = CommunicationValue::new(CommunicationType::ErrorNotFound)
                        .with_id(cv.get_id())
                        .add_typed_default(DataType::Path, path_data);
                    self.send_message(&error_cv).await;
                }
                Err(_) => {
                    let path_data = cv.get_data(DataType::Path).clone();
                    let error_cv = CommunicationValue::new(CommunicationType::ErrorNotFound)
                        .with_id(cv.get_id())
                        .add_typed_default(DataType::Path, path_data);
                    self.send_message(&error_cv).await;
                }
            }

            return;
        }

        let path_data = cv.get_data(DataType::Path).clone();
        let error_cv = CommunicationValue::new(CommunicationType::ErrorNotFound)
            .with_id(cv.get_id())
            .add_typed_default(DataType::Path, path_data);
        self.send_message(&error_cv).await;
    }

    /// Forward message to Iota
    async fn forward_to_iota(self: Arc<Self>, cv: CommunicationValue) {
        let sender_user_id = self.get_user_id().await;
        let msg_id = cv.get_id();
        let msg_type = cv.get_type();

        log_in!(
            sender_user_id as i64,
            PrintType::Client,
            "Forwarding client->iota: sender={} type={:?} id={} receiver={}",
            sender_user_id,
            msg_type,
            msg_id,
            cv.get_receiver()
        );

        if cv.is_type(CommunicationType::AddConversation)
            && cv
                .get_data(DataType::ChatPartnerId)
                .as_signed_number()
                .is_none()
        {
            let chat_partner_name = cv
                .get_data(DataType::ChatPartnerName)
                .as_str()
                .unwrap_or("")
                .to_string();

            if anonymous_manager::get_anonymous_user_by_name(chat_partner_name.to_string())
                .await
                .is_some()
            {
                self.send_error_response(cv.get_id(), CommunicationType::ErrorAnonymous)
                    .await;
                return;
            }

            let load_uuid_response = self
                .state
                .omega
                .clone()
                .await_response(
                    &CommunicationValue::new(CommunicationType::GetUserData)
                        .with_id(cv.clone().get_id())
                        .add_typed_default(
                            DataType::Username,
                            DataValue::Str(chat_partner_name.clone()),
                        ),
                    Some(Duration::from_secs(20)),
                )
                .await;
            let chat_partner_id = {
                if let Ok(load_uuid_response) = load_uuid_response {
                    load_uuid_response.get_data(DataType::UserId).clone()
                } else {
                    DataValue::Null
                }
            };

            if let Some(rho_conn) = self.get_rho_connection().await {
                let iota_id = rho_conn.get_iota_id().await;
                log_in!(
                    sender_user_id as i64,
                    PrintType::Client,
                    "Resolved rho for add_conversation: sender={} -> iota_id={} id={}",
                    sender_user_id,
                    iota_id,
                    msg_id
                );

                let updated_cv = cv
                    .with_sender(sender_user_id as u64)
                    .add_typed_default(DataType::ChatPartnerId, chat_partner_id);
                rho_conn.message_to_iota(updated_cv).await;
            } else {
                log_err!(
                    sender_user_id as i64,
                    PrintType::Client,
                    "No rho/iota mapping found for add_conversation sender={} type={:?} id={}",
                    sender_user_id,
                    msg_type,
                    msg_id
                );
            }
            return;
        }

        if let Some(rho_conn) = self.get_rho_connection().await {
            let iota_id = rho_conn.get_iota_id().await;
            log_in!(
                sender_user_id as i64,
                PrintType::Client,
                "Resolved rho for forward: sender={} -> iota_id={} type={:?} id={}",
                sender_user_id,
                iota_id,
                msg_type,
                msg_id
            );

            let updated_cv = cv.with_sender(sender_user_id as u64);
            rho_conn.message_to_iota(updated_cv).await;
        } else {
            log_err!(
                sender_user_id as i64,
                PrintType::Client,
                "No rho/iota mapping found for sender={} type={:?} id={}",
                sender_user_id,
                msg_type,
                msg_id
            );
            let error_cv = CommunicationValue::new(CommunicationType::ErrorNoIota)
                .with_id(msg_id)
                .add_typed_default(
                    DataType::UserId,
                    DataValue::SignedNumber(sender_user_id.into()),
                );
            self.send_message(&error_cv).await;
        }
    }

    /// Send error response
    async fn send_error_response(self: Arc<Self>, message_id: u32, error_type: CommunicationType) {
        let error = CommunicationValue::new(error_type).with_id(message_id);
        self.send_message(&error).await;
    }

    /// Close the connection
    pub async fn close(&self) {
        let mut is_open_guard = self.is_open.write().await;
        if !*is_open_guard {
            return;
        }
        *is_open_guard = false;

        let _ = self.sender.close();
    }

    /// Handle connection close
    pub async fn handle_close(self: Arc<Self>) {
        let user_id = self.get_user_id().await;
        if let Some(rho_conn) = self.state.rho.get_for_user(user_id as i64).await {
            rho_conn.close_client_connection(self.clone()).await;
        }
    }
}

// Implement Clone to make it easier to work with Arc<ClientConnection>
impl Clone for ClientConnection {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
            sender: Arc::clone(&self.sender),
            receiver: Arc::clone(&self.receiver),
            user_id: self.user_id,
            session_id: self.session_id,
            client_version: self.client_version.clone(),
            pub_key: Arc::clone(&self.pub_key),
            rho_connection: Arc::clone(&self.rho_connection),
            is_open: Arc::clone(&self.is_open),
            message_slots: Arc::clone(&self.message_slots),
        }
    }
}
