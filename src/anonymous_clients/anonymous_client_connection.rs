use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue, TypeMap};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::anonymous_clients::anonymous_manager::{self, generate_username};
use crate::app_state::AppState;
use crate::calls::call_group::call_invite_secret_from_cv;
use crate::data::user::UserStatus;
use crate::rho::connection::{GeneralConnection, MtpReceiver, MtpSender};
use crate::util::data_type_id;
use crate::util::logger::PrintType;
use crate::{log_cv_in, log_cv_out, log_out};

pub struct AnonymousClientConnection {
    pub state: Arc<AppState>,
    user_id: u64,

    pub sender: Arc<MtpSender>,
    pub receiver: Arc<MtpReceiver>,
    pub ping: Arc<RwLock<i64>>,
    pub interested_users: Arc<RwLock<Vec<i64>>>,
    is_open: Arc<RwLock<bool>>,
    pub user_name: Arc<RwLock<String>>,
    pub display_name: Arc<RwLock<String>>,
    pub avatar: Arc<RwLock<String>>,
    message_slots: Arc<tokio::sync::Semaphore>,
}

impl AnonymousClientConnection {
    pub async fn from_general(general: Arc<GeneralConnection>, user_id: u64) -> Arc<Self> {
        let username: String = generate_username();
        Arc::new(Self {
            state: general.state.clone(),
            user_id: user_id,

            ping: Arc::new(RwLock::new(0)),
            interested_users: Arc::new(RwLock::new(Vec::new())),
            is_open: Arc::new(RwLock::new(true)),
            sender: general.sender.clone(),
            receiver: general.receiver.clone(),
            user_name: Arc::new(RwLock::new(username.to_lowercase())),
            display_name: Arc::new(RwLock::new(username)),
            avatar: Arc::new(RwLock::new(String::new())),
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
    }

    /// Get the user ID
    pub fn get_user_id(&self) -> u64 {
        self.user_id
    }

    /// Get the user name
    pub async fn get_user_name(&self) -> String {
        self.user_name.read().await.clone()
    }

    /// Get the display name
    pub async fn get_display_name(&self) -> String {
        self.display_name.read().await.clone()
    }

    pub async fn set_display_name(&self, display: String) {
        *self.display_name.write().await = display;
    }

    /// Get the avatar
    pub async fn get_avatar(&self) -> String {
        self.avatar.read().await.clone()
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
        if !cv.is_type(CommunicationType::Pong) {
            log_cv_out!(PrintType::Client, &cv);
        }
        if let Err(e) = self.sender.send(&cv).await {
            log_out!(
                self.user_id as i64,
                PrintType::Client,
                "Send failed: {:?}",
                e
            );
        }
    }

    /// Handle incoming message from client
    pub async fn handle_message(self: Arc<Self>, cv: CommunicationValue) {
        let Ok(permit) = self.message_slots.clone().acquire_owned().await else {
            return;
        };
        tokio::spawn(async move {
            let _permit = permit;
            if cv.is_type(CommunicationType::Ping) {
                self.handle_ping(cv).await;
                return;
            }
            log_cv_in!(PrintType::Client, &cv);

            if cv.is_type(CommunicationType::Identification) {
                let call_id = Uuid::parse_str(cv.get_data(DataType::CallId).as_str().unwrap_or(""))
                    .unwrap_or(Uuid::new_v4());

                let call = if let Some(call) = self.state.call_manager.get_call(call_id).await {
                    if call.is_anonymous().await {
                        call
                    } else {
                        self.send_error_response(
                            &cv.get_id(),
                            CommunicationType::ErrorNotAuthenticated,
                        )
                        .await;
                        return;
                    }
                } else {
                    self.send_error_response(
                        &cv.get_id(),
                        CommunicationType::ErrorNotAuthenticated,
                    )
                    .await;
                    return;
                };

                let mut invited = Vec::new();
                for call_invitee in call.members.read().await.clone() {
                    let Ok(call_invitee_cv) = self
                        .state
                        .omega
                        .clone()
                        .await_response(
                            &CommunicationValue::new(CommunicationType::GetUserData)
                                .add_typed_default(
                                    DataType::UserId,
                                    DataValue::SignedNumber(call_invitee.user_id.into()),
                                ),
                            Some(Duration::from_secs(2)),
                        )
                        .await
                    else {
                        continue;
                    };
                    let mut json_invitee = Vec::new();
                    let _ = json_invitee.push((
                        DataType::UserId,
                        call_invitee_cv.get_data(DataType::UserId).clone(),
                    ));
                    let _ = json_invitee.push((
                        DataType::Username,
                        call_invitee_cv.get_data(DataType::Username).clone(),
                    ));
                    let _ = json_invitee.push((
                        DataType::Display,
                        call_invitee_cv.get_data(DataType::Display).clone(),
                    ));
                    let _ = json_invitee.push((
                        DataType::Avatar,
                        call_invitee_cv.get_data(DataType::Avatar).clone(),
                    ));

                    let _ = invited.push(DataValue::Container(
                        json_invitee
                            .iter()
                            .map(|(k, v)| (data_type_id(*k, &TypeMap::latest()), v.clone()))
                            .collect(),
                    ));
                }

                let token = match call.create_anonymous_token(self.get_user_id()).await {
                    Ok(Some(token)) => token,
                    Ok(None) | Err(_) => return,
                };

                let mut serialized = Vec::new();
                let _ = serialized.push((DataType::CallId, DataValue::Str(call_id.to_string())));
                let _ = serialized.push((DataType::CallInvited, DataValue::Array(invited.clone())));
                let _ = serialized.push((DataType::CallMembers, DataValue::Array(invited)));
                let _ = serialized.push((DataType::CallToken, DataValue::Str(token)));
                self.clone()
                    .send_message(
                        &&CommunicationValue::new(CommunicationType::IdentificationResponse)
                            .with_id(cv.get_id())
                            .add_typed_default(
                                DataType::UserId,
                                DataValue::SignedNumber(self.user_id.into()),
                            )
                            .add_typed_default(
                                DataType::Username,
                                DataValue::Str(self.clone().get_user_name().await),
                            )
                            .add_typed_default(
                                DataType::Display,
                                DataValue::Str(self.get_display_name().await),
                            )
                            .add_typed_default(
                                DataType::Avatar,
                                DataValue::Str(self.get_avatar().await),
                            )
                            .add_typed_default(
                                DataType::CallState,
                                DataValue::Container(
                                    serialized
                                        .iter()
                                        .map(|(k, v)| {
                                            (data_type_id(*k, &TypeMap::latest()), v.clone())
                                        })
                                        .collect(),
                                ),
                            ),
                    )
                    .await;
            }

            // Handle ping
            if cv.is_type(CommunicationType::Ping) {
                self.handle_ping(cv).await;
                return;
            }
            // Handle client status changes
            if cv.is_type(CommunicationType::ClientChanged) {
                self.handle_client_changed(cv).await;
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

            if cv.is_type(CommunicationType::CallDisconnectUser) {
                self.handle_call_disconnect_user(cv).await;
                return;
            }

            if cv.is_type(CommunicationType::CallTimeoutUser) {
                self.handle_call_timeout_user(cv).await;
                return;
            }

            if cv.is_type(CommunicationType::ChangeUserData) {
                if let Some(display_name) = cv.get_data(DataType::Display).as_str() {
                    let _ = self.set_display_name(display_name.to_string()).await;
                }

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
                            DataValue::SignedNumber(anonymous.user_id.into()),
                        )
                        .add_typed_default(
                            DataType::Display,
                            DataValue::Str(anonymous.get_display_name().await),
                        )
                        .add_typed_default(
                            DataType::UserState,
                            DataValue::Str("online".to_string()),
                        )
                        .add_typed_default(
                            DataType::Avatar,
                            DataValue::Str(anonymous.get_avatar().await),
                        );

                    self.send_message(&response).await;

                    return;
                }
            }

            if cv.is_type(CommunicationType::GetUserData)
                || cv.is_type(CommunicationType::GetIotaData)
                || cv.is_type(CommunicationType::DeleteUser)
            {
                self.handle_omega_forward(cv).await;
                return;
            }
        });
    }
    async fn handle_omega_forward(self: Arc<Self>, cv: CommunicationValue) {
        let client_for_closure = self.clone();
        tokio::spawn(async move {
            let response_cv = self
                .state
                .omega
                .clone()
                .await_response(&cv.with_sender(self.user_id), Some(Duration::from_secs(20)))
                .await;
            if let Ok(response_cv) = response_cv {
                client_for_closure.send_message(&response_cv).await;
            }
        });
    }

    /// Handle ping message
    async fn handle_ping(self: Arc<Self>, cv: CommunicationValue) {
        // Update our ping if provided
        if let DataValue::SignedNumber(last_ping) = cv.get_data(DataType::LastPing) {
            if let Ok(ping_val) = last_ping.to_string().parse::<i64>() {
                let mut ping_guard = self.ping.write().await;
                *ping_guard = ping_val;
            }
        }

        // Send pong response
        let response = CommunicationValue::new(CommunicationType::Pong).with_id(cv.get_id());

        self.send_message(&response).await;
    }

    /// Handle client status change
    async fn handle_client_changed(self: Arc<Self>, cv: CommunicationValue) {
        if let DataValue::Str(status_str) = cv.get_data(DataType::UserState) {
            let user_status = UserStatus::from_str(&status_str).unwrap_or(UserStatus::user_online);
            self.state
                .omega
                .client_changed(self.user_id as i64, self.user_id as i64, user_status)
                .await;
        }
    }

    /// Handle call invite
    async fn handle_call_invite(self: Arc<Self>, cv: CommunicationValue) {
        let receiver_id: i64 = cv.get_data(DataType::ReceiverId).as_number().unwrap_or(0) as i64;
        if receiver_id == 0 {
            self.send_error_response(&cv.get_id(), CommunicationType::ErrorNoUserId)
                .await;
            return;
        }

        let call_id = match cv.get_data(DataType::CallId) {
            DataValue::Str(id_str) => match Uuid::parse_str(&id_str.to_string()) {
                Ok(id) => id,
                Err(_) => {
                    self.send_error_response(&cv.get_id(), CommunicationType::ErrorInvalidCallId)
                        .await;
                    return;
                }
            },
            _ => {
                self.send_error_response(&cv.get_id(), CommunicationType::ErrorNoCallId)
                    .await;
                return;
            }
        };

        let secret = match call_invite_secret_from_cv(&cv) {
            Some(secret) => secret,
            None => {
                self.send_error_response(&cv.get_id(), CommunicationType::BadRequest)
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
            self.send_error_response(&cv.get_id(), CommunicationType::ErrorInvalidCallId)
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
        let target_rho = match self.state.rho.get_for_user(receiver_id).await {
            Some(rho) => rho,
            _ => {
                // Get sender user ID
                let sender_id = self.get_user_id();

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
        let sender_id = self.get_user_id();

        // Create and send call distribution message
        let forward = CommunicationValue::new(CommunicationType::CallInvite)
            .with_receiver(receiver_id as u64)
            .with_sender(sender_id)
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
        let user_id = self.get_user_id();

        let call_id = match cv.get_data(DataType::CallId) {
            DataValue::Str(id_str) => match Uuid::parse_str(&id_str.to_string()) {
                Ok(id) => id,
                Err(_) => {
                    self.send_error_response(&cv.get_id(), CommunicationType::ErrorInvalidCallId)
                        .await;
                    return;
                }
            },
            _ => {
                self.send_error_response(&cv.get_id(), CommunicationType::ErrorNoCallId)
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
                    .with_receiver(user_id)
                    .add_typed_default(DataType::CallToken, DataValue::Str(token));
                self.send_message(&response).await;
            }
            Err(error) => {
                log::warn!(
                    "Unable to create anonymous call token for {}: {}",
                    call_id,
                    error
                );
                let error_cv = CommunicationValue::new(CommunicationType::ErrorNoCallId)
                    .with_id(cv.get_id())
                    .add_typed_default(DataType::CallId, DataValue::Str(call_id.to_string()));
                self.send_message(&error_cv).await;
            }
        }
    }
    async fn handle_call_timeout_user(self: Arc<Self>, cv: CommunicationValue) {
        let Ok(call_id) = Uuid::from_str(cv.get_data(DataType::CallId).as_str().unwrap_or(""))
        else {
            self.send_error_response(&cv.get_id(), CommunicationType::ErrorInvalidCallId)
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
            self.send_error_response(&cv.get_id(), CommunicationType::ErrorNotFound)
                .await;
            return;
        };
        let Some(caller) = call.get_caller(self.get_user_id()).await else {
            self.send_error_response(&cv.get_id(), CommunicationType::ErrorInvalidUserId)
                .await;
            return;
        };
        if caller.has_admin() {
            if let Some(target) = call.get_caller(user_id as u64).await {
                target.set_timeout(untill as i64).await;
            }
        }
    }
    async fn handle_call_disconnect_user(self: Arc<Self>, cv: CommunicationValue) {
        let Ok(call_id) = Uuid::from_str(cv.get_data(DataType::CallId).as_str().unwrap_or(""))
        else {
            self.send_error_response(&cv.get_id(), CommunicationType::ErrorInvalidCallId)
                .await;
            return;
        };
        let user_id = cv
            .get_data(DataType::UserId)
            .as_signed_number()
            .unwrap_or(0);

        let Some(call) = self.state.call_manager.get_call(call_id).await else {
            self.send_error_response(&cv.get_id(), CommunicationType::ErrorNotFound)
                .await;
            return;
        };
        let Some(caller) = call.get_caller(self.get_user_id()).await else {
            self.send_error_response(&cv.get_id(), CommunicationType::ErrorInvalidUserId)
                .await;
            return;
        };
        if caller.has_admin() {
            call.remove_caller(user_id as u64).await;
        }
    }

    /// Send error response
    async fn send_error_response(self: Arc<Self>, message_id: &u32, error_type: CommunicationType) {
        let error = CommunicationValue::new(error_type).with_id(*message_id);
        self.send_message(&error).await;
    }
    /// Close the connection
    #[allow(unused)]
    pub async fn close(&self) {
        let mut is_open_guard = self.is_open.write().await;
        if !*is_open_guard {
            return;
        }
        *is_open_guard = false;

        let _ = self.sender.close();
    }

    #[allow(dead_code)]
    /// Set interested users list
    pub async fn set_interested_users(self: Arc<Self>, interested_ids: Vec<i64>) {
        let mut interested_guard = self.interested_users.write().await;
        *interested_guard = interested_ids;
    }
    #[allow(dead_code)]
    pub async fn get_interested_users(self: Arc<Self>) -> Vec<i64> {
        let interested_guard = self.interested_users.read().await;
        interested_guard.clone()
    }

    #[allow(dead_code)]
    /// Check if interested in a user and send notification
    pub async fn are_you_interested(self: Arc<Self>, user_id: i64, user_status: &str) {
        let interested_guard = self.clone().get_interested_users().await;
        if interested_guard.contains(&user_id) {
            let status = if user_status == "user_invisible" {
                "user_offline"
            } else {
                user_status
            };
            let notification = CommunicationValue::new(CommunicationType::ClientChanged)
                .add_typed_default(DataType::UserId, DataValue::Str(user_id.to_string()))
                .add_typed_default(DataType::UserState, DataValue::Str(status.to_string()));

            self.send_message(&notification).await;
        }
    }

    /// Handle connection close
    pub async fn handle_close(&self) {

        // TODO delete temp user
    }
}

// Implement Clone to make it easier to work with Arc<AnonymousClientConnection>
impl Clone for AnonymousClientConnection {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
            sender: Arc::clone(&self.sender),
            receiver: Arc::clone(&self.receiver),
            user_id: self.user_id,
            ping: Arc::clone(&self.ping),
            interested_users: Arc::clone(&self.interested_users),
            is_open: Arc::clone(&self.is_open),
            user_name: Arc::clone(&self.user_name),
            display_name: Arc::clone(&self.display_name),
            avatar: Arc::clone(&self.avatar),
            message_slots: Arc::clone(&self.message_slots),
        }
    }
}
