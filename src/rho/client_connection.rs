use async_tungstenite::tungstenite::Message;
use async_tungstenite::{WebSocketReceiver, WebSocketSender};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use json::JsonValue;
use json::number::Number;
use rand::Rng;
use rand::distributions::Alphanumeric;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio_util::compat::Compat;
use tungstenite::Utf8Bytes;
use uuid::Uuid;

use super::{rho_connection::RhoConnection, rho_manager};
use crate::anonymous_clients::anonymous_manager;
use crate::calls::{call_manager, call_util};
use crate::omega::omega_connection::get_omega_connection;
use crate::util::crypto_helper::{load_public_key, public_key_to_base64};
use crate::util::crypto_util::{DataFormat, SecurePayload};
use crate::util::logger::PrintType;
use crate::{
    data::{
        communication::{CommunicationType, CommunicationValue, DataTypes},
        user::UserStatus,
    },
    omega::omega_connection::OmegaConnection,
};
use crate::{get_private_key, get_public_key, log_in, log_out};

pub struct ClientConnection {
    pub sender: Arc<RwLock<WebSocketSender<Compat<tokio::net::TcpStream>>>>,
    pub receiver: Arc<RwLock<WebSocketReceiver<Compat<tokio::net::TcpStream>>>>,
    pub user_id: Arc<RwLock<i64>>,
    identified: Arc<RwLock<bool>>,
    challenged: Arc<RwLock<bool>>,
    challenge: Arc<RwLock<String>>,
    pub ping: Arc<RwLock<i64>>,
    pub_key: Arc<RwLock<Option<Vec<u8>>>>,
    pub rho_connection: Arc<RwLock<Option<Arc<RhoConnection>>>>,
    pub interested_users: Arc<RwLock<Vec<i64>>>,
    is_open: Arc<RwLock<bool>>,
}

impl ClientConnection {
    /// Create a new ClientConnection
    pub fn new(
        sender: WebSocketSender<Compat<tokio::net::TcpStream>>,
        receiver: WebSocketReceiver<Compat<tokio::net::TcpStream>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            sender: Arc::new(RwLock::new(sender)),
            receiver: Arc::new(RwLock::new(receiver)),
            user_id: Arc::new(RwLock::new(0)),
            identified: Arc::new(RwLock::new(false)),
            challenged: Arc::new(RwLock::new(false)),
            challenge: Arc::new(RwLock::new(String::new())),
            ping: Arc::new(RwLock::new(-1)),
            pub_key: Arc::new(RwLock::new(None)),
            rho_connection: Arc::new(RwLock::new(None)),
            interested_users: Arc::new(RwLock::new(Vec::new())),
            is_open: Arc::new(RwLock::new(true)),
        })
    }

    /// Get the user ID
    pub async fn get_user_id(&self) -> i64 {
        *self.user_id.read().await
    }

    /// Check if connection is identified
    pub async fn is_identified(&self) -> bool {
        *self.identified.read().await
    }

    /// Get current ping
    pub async fn get_ping(&self) -> i64 {
        *self.ping.read().await
    }

    /// Get RhoConnection if available
    pub async fn get_rho_connection(&self) -> Option<Arc<RhoConnection>> {
        self.rho_connection.read().await.clone()
    }

    /// Send a string message to the client
    pub async fn send_message_str(self: Arc<Self>, message: &str) {
        let mut session = self.sender.write().await;
        if let Err(e) = session
            .send(Message::Text(Utf8Bytes::from(message.to_string())))
            .await
        {
            log_out!(
                self.get_user_id().await,
                PrintType::Client,
                "Failed to send message to client: {}",
                e,
            );
        }
    }

    /// Send a CommunicationValue to the client
    pub async fn send_message(self: Arc<Self>, cv: &CommunicationValue) {
        if !*self.is_open.read().await {
            log_out!(
                self.get_user_id().await,
                PrintType::Client,
                "Attempted to send message to a closed connection."
            );
            return;
        }
        if !cv.is_type(CommunicationType::pong) && !cv.is_type(CommunicationType::ping) {
            log_out!(
                self.get_user_id().await,
                PrintType::Client,
                "{}",
                &cv.to_json().to_string()
            );
        }
        self.send_message_str(&cv.to_json().to_string()).await;
    }

    /// Handle incoming message from client
    pub async fn handle_message(self: Arc<Self>, message: Utf8Bytes) {
        tokio::spawn(async move {
            let cv = CommunicationValue::from_json(&message);
            if cv.is_type(CommunicationType::ping) {
                self.handle_ping(cv).await;
                return;
            }
            log_in!(
                self.get_user_id().await,
                PrintType::Client,
                "{}",
                &cv.to_json().to_string()
            );
            let identified = *self.identified.read().await;
            let challenged = *self.challenged.read().await;

            // Handle identification
            if !identified && cv.is_type(CommunicationType::identification) {
                let user_id = cv
                    .get_data(DataTypes::user_id)
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0);
                if user_id == 0 {
                    log_out!(
                        self.get_user_id().await,
                        PrintType::Client,
                        "Invalid USER ID"
                    );
                    self.clone()
                        .send_error_response(&cv.get_id(), CommunicationType::error_invalid_data)
                        .await;
                    self.close().await;
                    return;
                }

                *self.user_id.write().await = user_id;

                let get_pub_key_msg = CommunicationValue::new(CommunicationType::get_user_data)
                    .with_id(cv.get_id())
                    .add_data(DataTypes::user_id, JsonValue::from(user_id));

                let response_cv = get_omega_connection()
                    .await_response(&get_pub_key_msg, Some(Duration::from_secs(20)))
                    .await;

                if let Ok(response_cv) = response_cv {
                    if !response_cv.is_type(CommunicationType::get_user_data) {
                        self.clone()
                            .send_error_response(&cv.get_id(), CommunicationType::error_internal)
                            .await;
                        self.close().await;
                        return;
                    }

                    let base64_pub = response_cv
                        .get_data(DataTypes::public_key)
                        .and_then(|v| v.as_str())
                        .unwrap_or("");

                    let pub_key = match load_public_key(base64_pub) {
                        Some(pk) => pk,
                        _ => {
                            self.clone()
                                .send_error_response(
                                    &cv.get_id(),
                                    CommunicationType::error_invalid_public_key,
                                )
                                .await;
                            self.close().await;
                            return;
                        }
                    };

                    *self.pub_key.write().await = Some(pub_key.as_bytes().to_vec());

                    let challenge: String = rand::thread_rng()
                        .sample_iter(&Alphanumeric)
                        .take(32)
                        .map(char::from)
                        .collect();

                    *self.challenge.write().await = challenge.clone();

                    let encrypted_challenge =
                        SecurePayload::new(&challenge, DataFormat::Raw, get_private_key())
                            .unwrap()
                            .encrypt_x448(pub_key)
                            .unwrap()
                            .export(DataFormat::Base64);

                    *self.identified.write().await = true;

                    let challenge_msg = CommunicationValue::new(CommunicationType::challenge)
                        .with_id(cv.get_id())
                        .add_data_str(
                            DataTypes::public_key,
                            public_key_to_base64(&get_public_key()),
                        )
                        .add_data_str(DataTypes::challenge, encrypted_challenge);

                    self.send_message(&challenge_msg).await;
                } else {
                    self.clone()
                        .send_error_response(&cv.get_id(), CommunicationType::error_internal)
                        .await;
                    self.close().await;
                    return;
                }

                return;
            }

            if identified && !challenged && cv.is_type(CommunicationType::challenge_response) {
                let client_response = cv
                    .get_data(DataTypes::challenge)
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                let debase64d = STANDARD.decode(&client_response).unwrap();
                if String::from_utf8(debase64d.clone()).unwrap() == *self.challenge.read().await {
                    *self.challenged.write().await = true;

                    let user_id = self.get_user_id().await;

                    let rho_connection = match rho_manager::get_rho_con_for_user(user_id).await {
                        Some(rho) => rho,
                        _ => {
                            self.send_error_response(
                                &cv.get_id(),
                                CommunicationType::error_no_iota,
                            )
                            .await;
                            return;
                        }
                    };
                    rho_connection.add_client_connection(self.clone()).await;

                    // Set identification data
                    {
                        let mut user_id_guard = self.user_id.write().await;
                        *user_id_guard = user_id;
                    }
                    {
                        let mut identified_guard = self.identified.write().await;
                        *identified_guard = true;
                    }
                    *self.rho_connection.write().await = Some(Arc::clone(&rho_connection));

                    let response =
                        CommunicationValue::new(CommunicationType::identification_response)
                            .with_id(cv.get_id());
                    self.send_message(&response).await;
                } else {
                    self.clone()
                        .send_error_response(
                            &cv.get_id(),
                            CommunicationType::error_not_authenticated,
                        )
                        .await;
                    self.close().await;
                    return;
                }
                return;
            }

            if !self.is_identified().await {
                self.clone()
                    .send_error_response(&cv.get_id(), CommunicationType::error_not_authenticated)
                    .await;
                self.close().await;
                return;
            }

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
                    if let Some(user_id) = cv
                        .get_data(DataTypes::user_id)
                        .unwrap_or(&JsonValue::Null)
                        .as_i64()
                    {
                        anonymous_manager::get_anonymous_user(user_id).await
                    } else if let Some(username) = cv
                        .get_data(DataTypes::username)
                        .unwrap_or(&JsonValue::Null)
                        .as_str()
                    {
                        anonymous_manager::get_anonymous_user_by_name(username.to_string()).await
                    } else {
                        None
                    }
                } {
                    let response = CommunicationValue::new(CommunicationType::get_user_data)
                        .with_id(cv.get_id())
                        .add_data_str(DataTypes::username, anonymous.get_user_name().await)
                        .add_data(
                            DataTypes::user_id,
                            JsonValue::Number(Number::from(anonymous.get_user_id().await)),
                        )
                        .add_data_str(DataTypes::display, anonymous.get_display_name().await)
                        .add_data_str(DataTypes::user_state, "online".to_string())
                        .add_data_str(DataTypes::avatar, anonymous.get_avatar().await);

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
                self.handle_omega_forward(cv).await;
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
                .await_response(
                    &cv.with_sender(*self.user_id.read().await),
                    Some(Duration::from_secs(20)),
                )
                .await;
            if let Ok(response_cv) = response_cv {
                client_for_closure.send_message(&response_cv).await;
            }
        });
    }

    /// Handle ping message
    async fn handle_ping(self: Arc<Self>, cv: CommunicationValue) {
        // Update our ping if provided
        if let Some(last_ping) = cv.get_data(DataTypes::last_ping) {
            if let Ok(ping_val) = last_ping.to_string().parse::<i64>() {
                let mut ping_guard = self.ping.write().await;
                *ping_guard = ping_val;
            }
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
            .add_data(DataTypes::ping_iota, JsonValue::from(iota_ping));

        self.send_message(&response).await;
    }

    /// Handle client status change
    async fn handle_client_changed(self: Arc<Self>, cv: CommunicationValue) {
        let user_id = self.get_user_id().await;
        if let Some(_status_str) = cv.get_data(DataTypes::user_state) {
            let user_status = UserStatus::online;
            if let Some(rho_conn) = self.get_rho_connection().await {
                OmegaConnection::client_changed(rho_conn.get_iota_id().await, user_id, user_status)
                    .await;
            }
        }
    }

    /// Handle call invite
    async fn handle_call_invite(self: Arc<Self>, cv: CommunicationValue) {
        let receiver_id: i64 = cv
            .get_data(DataTypes::receiver_id)
            .unwrap_or(&json::JsonValue::Number(Number::from(0)))
            .as_i64()
            .unwrap_or(0);
        if receiver_id == 0 {
            self.send_error_response(&cv.get_id(), CommunicationType::error_no_user_id)
                .await;
            return;
        }

        let call_id = match cv.get_data(DataTypes::call_id) {
            Some(id_str) => match Uuid::parse_str(&id_str.to_string()) {
                Ok(id) => id,
                Err(_) => {
                    self.send_error_response(
                        &cv.get_id(),
                        CommunicationType::error_invalid_call_id,
                    )
                    .await;
                    return;
                }
            },
            _ => {
                self.send_error_response(&cv.get_id(), CommunicationType::error_no_call_id)
                    .await;
                return;
            }
        };

        let invited =
            call_manager::add_invite(call_id, *self.user_id.read().await, receiver_id).await;
        if !invited {
            self.send_error_response(&cv.get_id(), CommunicationType::error_invalid_call_id)
                .await;
            return;
        }

        // Find target RhoConnection
        let target_rho = match rho_manager::get_rho_con_for_user(receiver_id).await {
            Some(rho) => rho,
            _ => {
                self.send_error_response(&cv.get_id(), CommunicationType::error)
                    .await;
                return;
            }
        };

        // Get sender user ID
        let sender_id = self.get_user_id().await;

        // Create and send call distribution message
        let forward = CommunicationValue::new(CommunicationType::call_invite)
            .with_receiver(receiver_id)
            .with_sender(sender_id)
            .add_data_str(DataTypes::call_id, call_id.to_string())
            .add_data_str(DataTypes::receiver_id, receiver_id.to_string())
            .add_data_str(DataTypes::sender_id, sender_id.to_string());

        target_rho.message_to_client(forward).await;

        let response = CommunicationValue::new(CommunicationType::success).with_id(cv.get_id());
        self.send_message(&response).await;
    }

    /// Handle get call request
    async fn handle_get_call(self: Arc<Self>, cv: CommunicationValue) {
        let user_id = self.get_user_id().await;

        let call_id = match cv.get_data(DataTypes::call_id) {
            Some(id_str) => match Uuid::parse_str(&id_str.to_string()) {
                Ok(id) => id,
                Err(_) => {
                    self.send_error_response(&cv.get_id(), CommunicationType::error)
                        .await;
                    return;
                }
            },
            _ => {
                self.send_error_response(&cv.get_id(), CommunicationType::error)
                    .await;
                return;
            }
        };

        if let Some(token) = call_manager::get_call_token(user_id, call_id).await {
            let response = CommunicationValue::new(CommunicationType::call_token)
                .with_id(cv.get_id())
                .with_receiver(user_id)
                .add_data_str(DataTypes::call_token, token);
            self.send_message(&response).await;
        } else {
            self.send_error_response(&cv.get_id(), CommunicationType::error)
                .await;
            return;
        }
    }
    async fn handle_call_timeout_user(self: Arc<Self>, cv: CommunicationValue) {
        let call_id = Uuid::from_str(
            cv.get_data(DataTypes::call_id)
                .unwrap_or(&JsonValue::Null)
                .as_str()
                .unwrap_or(""),
        )
        .unwrap();
        let user_id = cv
            .get_data(DataTypes::user_id)
            .unwrap_or(&JsonValue::Null)
            .as_i64()
            .unwrap_or(0);
        let untill = cv
            .get_data(DataTypes::untill)
            .unwrap_or(&JsonValue::Null)
            .as_i64()
            .unwrap_or(0);

        let call = call_manager::get_call(call_id).await;
        if let Some(call) = call {
            if call
                .get_caller(self.get_user_id().await)
                .await
                .unwrap()
                .has_admin()
            {
                let _ = call_util::remove_participant(call_id, user_id).await;
                call.get_caller(user_id)
                    .await
                    .unwrap()
                    .set_timeout(untill)
                    .await;
            }
        }
    }
    async fn handle_call_disconnect_user(self: Arc<Self>, cv: CommunicationValue) {
        let call_id = Uuid::from_str(
            cv.get_data(DataTypes::call_id)
                .unwrap_or(&JsonValue::Null)
                .as_str()
                .unwrap_or(""),
        )
        .unwrap();
        let user_id = cv
            .get_data(DataTypes::user_id)
            .unwrap_or(&JsonValue::Null)
            .as_i64()
            .unwrap_or(0);

        let call = call_manager::get_call(call_id).await;
        if let Some(call) = call {
            if call
                .get_caller(self.get_user_id().await)
                .await
                .unwrap()
                .has_admin()
            {
                call.remove_caller(user_id).await;
            }
        }
    }
    async fn handle_call_set_anonymous_joining(self: Arc<Self>, cv: CommunicationValue) {
        let call_id = Uuid::from_str(
            cv.get_data(DataTypes::call_id)
                .unwrap_or(&JsonValue::Null)
                .as_str()
                .unwrap_or(""),
        )
        .unwrap();
        let enable = cv
            .get_data(DataTypes::enabled)
            .unwrap_or(&JsonValue::Null)
            .as_bool()
            .unwrap_or(true);

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
                .add_data(DataTypes::call_id, JsonValue::String(call_id.to_string()))
                .add_data(DataTypes::enabled, JsonValue::Boolean(enable));
        if let Some(short_link) = short_link {
            response_cv = response_cv.add_data(DataTypes::link, JsonValue::String(short_link));
        }
        self.send_message(&response_cv).await;
    }

    /// Forward message to Iota
    async fn forward_to_iota(self: Arc<Self>, cv: CommunicationValue) {
        if cv.is_type(CommunicationType::add_conversation)
            && cv.get_data(DataTypes::chat_partner_id).is_none()
        {
            let chat_partner_name = cv
                .get_data(DataTypes::chat_partner_name)
                .unwrap_or(&JsonValue::Null)
                .as_str()
                .unwrap_or("")
                .to_string();

            if anonymous_manager::get_anonymous_user_by_name(chat_partner_name.to_string())
                .await
                .is_some()
            {
                self.send_error_response(&cv.get_id(), CommunicationType::error_anonymous)
                    .await;
                return;
            }

            let load_uuid_response = get_omega_connection()
                .await_response(
                    &CommunicationValue::new(CommunicationType::get_user_data)
                        .with_id(cv.clone().get_id())
                        .add_data(
                            DataTypes::username,
                            JsonValue::from(chat_partner_name.clone()),
                        ),
                    Some(Duration::from_secs(20)),
                )
                .await;
            let chat_partner_id = {
                if let Ok(load_uuid_response) = load_uuid_response {
                    load_uuid_response
                        .get_data(DataTypes::user_id)
                        .unwrap_or(&JsonValue::Null)
                        .clone()
                } else {
                    JsonValue::Null
                }
            };

            if let Some(rho_conn) = self.get_rho_connection().await {
                let updated_cv = cv
                    .with_sender(self.get_user_id().await)
                    .add_data(DataTypes::chat_partner_id, chat_partner_id);
                rho_conn.message_to_iota(updated_cv).await;
            }
            return;
        }

        if let Some(rho_conn) = self.get_rho_connection().await {
            let updated_cv = cv.with_sender(self.get_user_id().await);
            rho_conn.message_to_iota(updated_cv).await;
        }
    }

    /// Send error response
    async fn send_error_response(
        self: Arc<Self>,
        message_id: &Uuid,
        error_type: CommunicationType,
    ) {
        let error = CommunicationValue::new(error_type).with_id(*message_id);
        self.send_message(&error).await;
    }

    /// Close the connection
    pub async fn close(&self) {
        let mut is_open_guard = self.is_open.write().await;
        if *is_open_guard {
            return;
        }
        *is_open_guard = false;

        let mut session = self.sender.write().await;
        let _ = session.close(None).await;
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
                .add_data_str(DataTypes::user_id, user_id.to_string())
                .add_data_str(DataTypes::user_state, format!("online"));

            self.send_message(&notification).await;
        }
    }

    /// Handle connection close
    pub async fn handle_close(&self) {
        if self.is_identified().await {
            let user_id = self.get_user_id().await;
            if let Some(rho_conn) = rho_manager::get_rho_con_for_user(user_id).await {
                rho_conn
                    .close_client_connection(Arc::new(self.clone()))
                    .await;
            }
        }
    }
}

// Implement Clone to make it easier to work with Arc<ClientConnection>
impl Clone for ClientConnection {
    fn clone(&self) -> Self {
        Self {
            sender: Arc::clone(&self.sender),
            receiver: Arc::clone(&self.receiver),
            user_id: Arc::clone(&self.user_id),
            identified: Arc::clone(&self.identified),
            challenged: Arc::clone(&self.challenged),
            challenge: Arc::clone(&self.challenge),
            ping: Arc::clone(&self.ping),
            pub_key: Arc::clone(&self.pub_key),
            rho_connection: Arc::clone(&self.rho_connection),
            interested_users: Arc::clone(&self.interested_users),
            is_open: Arc::clone(&self.is_open),
        }
    }
}
