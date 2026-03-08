use crate::anonymous_clients::anonymous_manager;
use crate::calls::{call_manager, call_util};
use crate::omega::omega_connection::get_omega_connection;
use crate::rho::connection::GeneralConnection;
use crate::rho::{rho_connection::RhoConnection, rho_manager};
use crate::util::logger::PrintType;
use crate::{data::user::UserStatus, omega::omega_connection::OmegaConnection};
use crate::{log_cv_in, log_cv_out, log_out};
use epsilon_core::{CommunicationType, CommunicationValue, DataTypes, DataValue};
use epsilon_native::{Receiver, Sender};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use uuid::Uuid;

pub struct ClientConnection {
    pub user_id: u64,

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
            rho_connection: Arc::new(RwLock::new(None)),
            interested_users: Arc::new(RwLock::new(Vec::new())),
            is_open: Arc::new(RwLock::new(true)),
            sender: general.sender.clone(),
            receiver: general.receiver.clone(),
            user_id: user_id,
        })
    }
    pub fn start(self: Arc<Self>) {
        let self_clone = self.clone();
        tokio::spawn(async move {
            while let Ok(cv) = self_clone.receiver.receive().await {
                self_clone.clone().handle_message(cv).await;
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
        if !cv.is_type(CommunicationType::pong) && !cv.is_type(CommunicationType::ping) {
            log_cv_out!(PrintType::Client, &cv);
        }
        self.sender.send(&cv).await;
    }

    /// Handle incoming message from client
    pub async fn handle_message(self: Arc<Self>, cv: CommunicationValue) {
        tokio::spawn(async move {
            if cv.is_type(CommunicationType::ping) {
                self.handle_ping(cv).await;
                return;
            }
            log_cv_in!(PrintType::Client, cv);

            // Handle client status changes
            if cv.is_type(CommunicationType::client_changed) {
                self.handle_client_changed(cv).await;
                return;
            }

            // Handle call invites
            if cv.is_type(CommunicationType::call_invite) {
                self.handle_call_invite(cv).await;
                return;
            }

            // Handle get call requests
            if cv.is_type(CommunicationType::call_token) {
                self.handle_get_call(cv).await;
                return;
            }

            if cv.is_type(CommunicationType::call_disconnect_user) {
                self.handle_call_disconnect_user(cv).await;
                return;
            }

            if cv.is_type(CommunicationType::call_timeout_user) {
                self.handle_call_timeout_user(cv).await;
                return;
            }

            if cv.is_type(CommunicationType::call_set_anonymous_joining) {
                self.handle_call_set_anonymous_joining(cv).await;
                return;
            }
            if cv.is_type(CommunicationType::get_user_data) {
                if let Some(anonymous) = {
                    if let Some(user_id) = cv.get_data(DataTypes::user_id).as_number() {
                        anonymous_manager::get_anonymous_user(user_id as u64).await
                    } else if let Some(username) = cv.get_data(DataTypes::username).as_str() {
                        anonymous_manager::get_anonymous_user_by_name(username.to_string()).await
                    } else {
                        None
                    }
                } {
                    let response = CommunicationValue::new(CommunicationType::get_user_data)
                        .with_id(cv.get_id())
                        .add_data(
                            DataTypes::username,
                            DataValue::Str(anonymous.get_user_name().await),
                        )
                        .add_data(
                            DataTypes::user_id,
                            DataValue::Number(anonymous.get_user_id() as i64),
                        )
                        .add_data(
                            DataTypes::display,
                            DataValue::Str(anonymous.get_display_name().await),
                        )
                        .add_data(
                            DataTypes::avatar,
                            DataValue::Str(anonymous.get_avatar().await),
                        )
                        .add_data(DataTypes::user_state, DataValue::Str("online".to_string()));

                    self.send_message(&response).await;

                    return;
                }
            }

            if cv.is_type(CommunicationType::change_user_data)
                || cv.is_type(CommunicationType::read_notification)
                || cv.is_type(CommunicationType::get_notifications)
                || cv.is_type(CommunicationType::get_user_data)
                || cv.is_type(CommunicationType::get_iota_data)
                || cv.is_type(CommunicationType::delete_user)
            {
                let sender = self.get_user_id().await;
                self.handle_omega_forward(cv.with_sender(sender as u64))
                    .await;
                return;
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
        if let DataValue::Number(last_ping) = cv.get_data(DataTypes::last_ping) {
            let current = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis();
            let mut ping_guard = self.ping.write().await;
            *ping_guard = current as i64 - last_ping;
        }

        // Get Iota ping from RhoConnection
        let iota_ping = if let Some(rho_conn) = self.get_rho_connection().await {
            rho_conn.get_iota_connection().get_ping().await
        } else {
            -1
        };

        // Send pong response
        let response = CommunicationValue::new(CommunicationType::pong)
            .with_id(cv.get_id())
            .add_data(DataTypes::ping_iota, DataValue::Number(iota_ping));

        self.send_message(&response).await;
    }

    /// Handle client status change
    async fn handle_client_changed(self: Arc<Self>, cv: CommunicationValue) {
        let user_id = self.get_user_id().await;
        if let DataValue::Str(_status_str) = cv.get_data(DataTypes::user_state) {
            let user_status = UserStatus::user_online;
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
        let receiver_id: i64 = cv.get_data(DataTypes::receiver_id).as_number().unwrap_or(0);
        if receiver_id == 0 {
            self.send_error_response(cv.get_id(), CommunicationType::error_no_user_id)
                .await;
            return;
        }

        let call_id = match cv.get_data(DataTypes::call_id) {
            DataValue::Str(id_str) => match Uuid::parse_str(id_str.as_str()) {
                Ok(id) => id,
                Err(_) => {
                    self.send_error_response(cv.get_id(), CommunicationType::error_invalid_call_id)
                        .await;
                    return;
                }
            },
            _ => {
                self.send_error_response(cv.get_id(), CommunicationType::error_no_call_id)
                    .await;
                return;
            }
        };

        let invited = call_manager::add_invite(call_id, self.user_id, receiver_id as u64).await;
        if !invited {
            self.send_error_response(cv.get_id(), CommunicationType::error_invalid_call_id)
                .await;
            return;
        }

        // Find target RhoConnection
        let target_rho = match rho_manager::get_rho_con_for_user(receiver_id).await {
            Some(rho) => rho,
            _ => {
                self.send_error_response(cv.get_id(), CommunicationType::error)
                    .await;
                return;
            }
        };

        // Get sender user ID
        let sender_id = self.get_user_id().await;

        // Create and send call distribution message
        let forward = CommunicationValue::new(CommunicationType::call_invite)
            .with_receiver(receiver_id as u64)
            .with_sender(sender_id as u64)
            .add_data(DataTypes::call_id, DataValue::Str(call_id.to_string()))
            .add_data(
                DataTypes::receiver_id,
                DataValue::Str(receiver_id.to_string()),
            )
            .add_data(DataTypes::sender_id, DataValue::Str(sender_id.to_string()));

        target_rho.message_to_client(forward).await;

        let response = CommunicationValue::new(CommunicationType::success).with_id(cv.get_id());
        self.send_message(&response).await;
    }

    /// Handle get call request
    async fn handle_get_call(self: Arc<Self>, cv: CommunicationValue) {
        let user_id = self.get_user_id().await;

        let call_id = match cv.get_data(DataTypes::call_id) {
            DataValue::Str(id_str) => match Uuid::parse_str(id_str.as_str()) {
                Ok(id) => id,
                Err(_) => {
                    self.send_error_response(cv.get_id(), CommunicationType::error)
                        .await;
                    return;
                }
            },
            _ => {
                self.send_error_response(cv.get_id(), CommunicationType::error)
                    .await;
                return;
            }
        };

        if let Some(token) = call_manager::get_call_token(user_id, call_id).await {
            let response = CommunicationValue::new(CommunicationType::call_token)
                .with_id(cv.get_id())
                .with_receiver(user_id as u64)
                .add_data(DataTypes::call_token, DataValue::Str(token));
            self.send_message(&response).await;
        } else {
            self.send_error_response(cv.get_id(), CommunicationType::error)
                .await;
            return;
        }
    }
    async fn handle_call_timeout_user(self: Arc<Self>, cv: CommunicationValue) {
        let call_id =
            Uuid::from_str(cv.get_data(DataTypes::call_id).as_str().unwrap_or("")).unwrap();
        let user_id = cv.get_data(DataTypes::user_id).as_number().unwrap_or(0);
        let untill = cv.get_data(DataTypes::untill).as_number().unwrap_or(0);

        let call = call_manager::get_call(call_id).await;
        if let Some(call) = call {
            if call
                .get_caller(self.get_user_id().await)
                .await
                .unwrap()
                .has_admin()
            {
                let _ = call_util::remove_participant(call_id, user_id as u64).await;
                call.get_caller(user_id as u64)
                    .await
                    .unwrap()
                    .set_timeout(untill)
                    .await;
            }
        }
    }
    async fn handle_call_disconnect_user(self: Arc<Self>, cv: CommunicationValue) {
        let call_id =
            Uuid::from_str(cv.get_data(DataTypes::call_id).as_str().unwrap_or("")).unwrap();
        let user_id = cv.get_data(DataTypes::user_id).as_number().unwrap_or(0);

        let call = call_manager::get_call(call_id).await;
        if let Some(call) = call {
            if call
                .get_caller(self.get_user_id().await)
                .await
                .unwrap()
                .has_admin()
            {
                call.remove_caller(user_id as u64).await;
            }
        }
    }
    async fn handle_call_set_anonymous_joining(self: Arc<Self>, cv: CommunicationValue) {
        let call_id =
            Uuid::from_str(cv.get_data(DataTypes::call_id).as_str().unwrap_or("")).unwrap();
        let enable = cv.get_data(DataTypes::enabled).as_bool().unwrap_or(true);

        let call = call_manager::get_call(call_id).await;

        let mut short_link = None;
        if let Some(call) = call {
            if call
                .get_caller(self.get_user_id().await)
                .await
                .unwrap()
                .has_admin()
            {
                call.set_anonymous_joining(enable).await;
            }
            short_link = call.get_short_link().await;
        }
        let mut response_cv =
            CommunicationValue::new(CommunicationType::call_set_anonymous_joining)
                .with_id(cv.get_id())
                .add_data(DataTypes::call_id, DataValue::Str(call_id.to_string()))
                .add_data(DataTypes::enabled, DataValue::Bool(enable));
        if let Some(short_link) = short_link {
            response_cv = response_cv.add_data(DataTypes::link, DataValue::Str(short_link));
        }
        self.send_message(&response_cv).await;
    }

    /// Forward message to Iota
    async fn forward_to_iota(self: Arc<Self>, cv: CommunicationValue) {
        if cv.is_type(CommunicationType::add_conversation)
            && cv
                .get_data(DataTypes::chat_partner_id)
                .as_number()
                .is_some()
        {
            let chat_partner_name = cv
                .get_data(DataTypes::chat_partner_name)
                .as_str()
                .unwrap_or("")
                .to_string();

            if anonymous_manager::get_anonymous_user_by_name(chat_partner_name.to_string())
                .await
                .is_some()
            {
                self.send_error_response(cv.get_id(), CommunicationType::error_anonymous)
                    .await;
                return;
            }

            let load_uuid_response = get_omega_connection()
                .await_response(
                    &CommunicationValue::new(CommunicationType::get_user_data)
                        .with_id(cv.clone().get_id())
                        .add_data(
                            DataTypes::username,
                            DataValue::Str(chat_partner_name.clone()),
                        ),
                    Some(Duration::from_secs(20)),
                )
                .await;
            let chat_partner_id = {
                if let Ok(load_uuid_response) = load_uuid_response {
                    load_uuid_response.get_data(DataTypes::user_id).clone()
                } else {
                    DataValue::Null
                }
            };

            if let Some(rho_conn) = self.get_rho_connection().await {
                let updated_cv = cv
                    .with_sender(self.get_user_id().await as u64)
                    .add_data(DataTypes::chat_partner_id, chat_partner_id);
                rho_conn.message_to_iota(updated_cv).await;
            }
            return;
        }

        if let Some(rho_conn) = self.get_rho_connection().await {
            let updated_cv = cv.with_sender(self.get_user_id().await as u64);
            rho_conn.message_to_iota(updated_cv).await;
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
        if *is_open_guard {
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
    pub async fn get_interested_users(self: Arc<Self>) -> Vec<i64> {
        let interested_guard = self.interested_users.read().await;
        interested_guard.clone()
    }

    /// Check if interested in a user and send notification
    pub async fn are_you_interested(self: Arc<Self>, user_id: i64) {
        let interested_guard = self.clone().get_interested_users().await;
        if interested_guard.contains(&user_id) {
            let notification = CommunicationValue::new(CommunicationType::client_changed)
                .add_data(DataTypes::user_id, DataValue::Str(user_id.to_string()))
                .add_data(DataTypes::user_state, DataValue::Str("online".to_string()));

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
            ping: Arc::clone(&self.ping),
            pub_key: Arc::clone(&self.pub_key),
            rho_connection: Arc::clone(&self.rho_connection),
            interested_users: Arc::clone(&self.interested_users),
            is_open: Arc::clone(&self.is_open),
        }
    }
}
