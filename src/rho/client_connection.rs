use crate::anonymous_clients::anonymous_manager;
use crate::calls::{call_manager, call_util};
use crate::omega::omega_connection::get_omega_connection;
use crate::rho::connection::GeneralConnection;
use crate::rho::{rho_connection::RhoConnection, rho_manager};
use crate::util::logger::PrintType;
use crate::{data::user::UserStatus, omega::omega_connection::OmegaConnection};
use crate::{log_cv_in, log_cv_out, log_err, log_in, log_out};
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use mtp::host::{Receiver, Sender};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use uuid::Uuid;

pub struct ClientConnection {
    pub user_id: u64,
    pub session_id: u64,
    pub client_version: String,

    pub sender: Arc<Sender>,
    pub receiver: Arc<Receiver>,
    pub ping: Arc<RwLock<i64>>,
    pub_key: Arc<RwLock<Option<Vec<u8>>>>,
    pub rho_connection: Arc<RwLock<Option<Arc<RhoConnection>>>>,
    pub interested_users: Arc<RwLock<Vec<i64>>>,
    is_open: Arc<RwLock<bool>>,
}

impl ClientConnection {
    pub async fn from_general(general: Arc<GeneralConnection>, user_id: u64) -> Arc<Self> {
        Arc::new(Self {
            ping: Arc::new(RwLock::new(0)),
            pub_key: Arc::new(RwLock::new(None)),
            rho_connection: general.rho_connection.clone(),
            interested_users: Arc::new(RwLock::new(Vec::new())),
            is_open: Arc::new(RwLock::new(true)),
            sender: general.sender.clone(),
            receiver: general.receiver.clone(),
            user_id: user_id,
            session_id: general.session_id.read().await.clone(),
            client_version: general.client_version.read().await.clone(),
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

    /// Get current ping
    pub async fn get_ping(&self) -> i64 {
        *self.ping.read().await
    }

    /// Get RhoConnection if available
    pub async fn get_rho_connection(&self) -> Option<Arc<RhoConnection>> {
        self.rho_connection.read().await.clone()
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
        if !cv.is_type(CommunicationType::Pong) && !cv.is_type(CommunicationType::Ping) {
            log_cv_out!(PrintType::Client, &cv);
        }
        let _ = self.sender.send(&cv).await;
    }

    /// Handle incoming message from client
    pub async fn handle_message(self: Arc<Self>, cv: CommunicationValue) {
        tokio::spawn(async move {
            if cv.is_type(CommunicationType::Ping) {
                self.handle_ping(cv).await;
                return;
            }
            log_cv_in!(PrintType::Client, cv);

            let mut cv = cv;

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

            // Forward other messages to Iota
            self.forward_to_iota(cv).await;
        });
    }
    async fn handle_omega_forward(self: Arc<Self>, cv: CommunicationValue) {
        let client_for_closure = self.clone();
        tokio::spawn(async move {
            let response_cv = get_omega_connection()
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
            let current = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis();
            let mut ping_guard = self.ping.write().await;
            *ping_guard = (current as i128 - *last_ping) as i64;
        }

        // Get Iota ping from RhoConnection
        let iota_ping = if let Some(rho_conn) = self.get_rho_connection().await {
            rho_conn.get_iota_connection().get_ping().await
        } else {
            -1
        };

        // Send pong response
        let response = CommunicationValue::new(CommunicationType::Pong)
            .with_id(cv.get_id())
            .add_typed_default(
                DataType::PingIota,
                DataValue::SignedNumber(iota_ping.into()),
            );

        self.send_message(&response).await;
    }

    /// Handle client status change
    async fn handle_client_changed(self: Arc<Self>, cv: CommunicationValue) {
        let user_id = self.get_user_id().await;
        if let DataValue::Str(status_str) = cv.get_data(DataType::UserState) {
            let user_status = UserStatus::from_str(&status_str).unwrap_or(UserStatus::user_online);
            if let Some(rho_conn) = self.get_rho_connection().await {
                OmegaConnection::client_changed(
                    rho_conn.get_iota_id().await as i64,
                    user_id as i64,
                    user_status,
                )
                .await;
            }
        }
    }

    /// Handle call invite
    async fn handle_call_invite(self: Arc<Self>, cv: CommunicationValue) {
        let receiver_id: i128 = cv
            .get_data(DataType::ReceiverId)
            .as_signed_number()
            .unwrap_or(0);
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

        let secret = cv
            .get_data(DataType::CallSecret)
            .as_str()
            .map(|s| s.to_string());
        let invited =
            call_manager::add_invite(call_id, self.user_id, receiver_id as u64, secret).await;
        if !invited {
            self.send_error_response(cv.get_id(), CommunicationType::ErrorInvalidCallId)
                .await;
            return;
        }

        // Find target RhoConnection
        let target_rho = match rho_manager::get_rho_con_for_user(receiver_id as i64).await {
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

                let omega_conn = get_omega_connection();
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
            .add_typed_default(
                DataType::CallSecret,
                cv.get_data(DataType::CallSecret).clone(),
            )
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

        if let Some(token) = call_manager::get_call_token(user_id, call_id).await {
            let response = CommunicationValue::new(CommunicationType::CallToken)
                .with_id(cv.get_id())
                .with_receiver(user_id as u64)
                .add_typed_default(DataType::CallToken, DataValue::Str(token));
            self.send_message(&response).await;
        } else {
            let error_cv = CommunicationValue::new(CommunicationType::ErrorNoCallId)
                .with_id(cv.get_id())
                .add_typed_default(DataType::CallId, DataValue::Str(call_id.to_string()));
            self.send_message(&error_cv).await;
            return;
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

        if let Some(call) = call_manager::get_call(call_id).await {
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

        let Some(call) = call_manager::get_call(call_id).await else {
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
            let _ = call_util::remove_participant(call_id, user_id as u64).await;
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

        let Some(call) = call_manager::get_call(call_id).await else {
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

        let call = call_manager::get_call(call_id).await;

        let mut short_link = None;
        if let Some(call) = call {
            if let Some(caller) = call.get_caller(self.get_user_id().await).await {
                if caller.has_admin() {
                    call.set_anonymous_joining(enable).await;
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
            if let Ok(builder) = hickory_resolver::Resolver::builder_tokio() {
                let resolver = builder.build();
                if let Ok(lookup) = resolver.txt_lookup(path).await {
                    for record in lookup.iter() {
                        for txt_data in record.txt_data() {
                            if let Ok(s) = std::str::from_utf8(txt_data) {
                                let response =
                                    CommunicationValue::new(CommunicationType::LoadTxtRecord)
                                        .with_id(cv.get_id())
                                        .add_typed_default(
                                            DataType::Content,
                                            DataValue::Str(s.to_string()),
                                        );
                                self.send_message(&response).await;
                                return;
                            }
                        }
                    }
                }
            }
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

            let load_uuid_response = get_omega_connection()
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

    /// Check if interested in a user and send notification
    #[allow(dead_code)]
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
        let user_id = self.get_user_id().await;
        if let Some(rho_conn) = rho_manager::get_rho_con_for_user(user_id as i64).await {
            rho_conn
                .close_client_connection(Arc::new(self.clone()))
                .await;
        }
    }
}

// Implement Clone to make it easier to work with Arc<ClientConnection>
impl Clone for ClientConnection {
    fn clone(&self) -> Self {
        Self {
            sender: Arc::clone(&self.sender),
            receiver: Arc::clone(&self.receiver),
            user_id: self.user_id,
            session_id: self.session_id,
            client_version: self.client_version.clone(),
            ping: Arc::clone(&self.ping),
            pub_key: Arc::clone(&self.pub_key),
            rho_connection: Arc::clone(&self.rho_connection),
            interested_users: Arc::clone(&self.interested_users),
            is_open: Arc::clone(&self.is_open),
        }
    }
}
