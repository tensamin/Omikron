use async_tungstenite::tungstenite::Message;
use async_tungstenite::{WebSocketReceiver, WebSocketSender};
use json::JsonValue;
use json::number::Number;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tokio_util::compat::Compat;
use tungstenite::Utf8Bytes;
use uuid::Uuid;

use crate::anonymous_clients::anonymous_manager::{self, generate_username};
use crate::calls::call_manager;
use crate::data::communication::{CommunicationType, CommunicationValue, DataTypes};
use crate::omega::omega_connection::get_omega_connection;
use crate::rho::rho_manager;
use crate::util::logger::PrintType;
use crate::{log_in, log_out};

pub struct AnonymousClientConnection {
    pub sender: Arc<RwLock<WebSocketSender<Compat<tokio::net::TcpStream>>>>,
    pub receiver: Arc<RwLock<WebSocketReceiver<Compat<tokio::net::TcpStream>>>>,
    pub user_id: Arc<RwLock<i64>>,
    pub ping: Arc<RwLock<i64>>,
    pub interested_users: Arc<RwLock<Vec<i64>>>,
    is_open: Arc<RwLock<bool>>,
    pub user_name: Arc<RwLock<String>>,
    pub display_name: Arc<RwLock<String>>,
    pub avatar: Arc<RwLock<String>>,
}

impl AnonymousClientConnection {
    /// Create a new AnonymousClientConnection
    pub fn new(
        sender: WebSocketSender<Compat<tokio::net::TcpStream>>,
        receiver: WebSocketReceiver<Compat<tokio::net::TcpStream>>,
    ) -> Arc<Self> {
        let username: String = generate_username();
        Arc::new(Self {
            sender: Arc::new(RwLock::new(sender)),
            receiver: Arc::new(RwLock::new(receiver)),
            user_id: Arc::new(RwLock::new(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as i64,
            )),
            ping: Arc::new(RwLock::new(-1)),
            interested_users: Arc::new(RwLock::new(Vec::new())),
            is_open: Arc::new(RwLock::new(true)),
            user_name: Arc::new(RwLock::new(username.to_lowercase())),
            display_name: Arc::new(RwLock::new(username)),
            avatar: Arc::new(RwLock::new(String::new())),
        })
    }

    /// Get the user ID
    pub async fn get_user_id(&self) -> i64 {
        *self.user_id.read().await
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
                "Failed to send message to anonymous client: {}",
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
        if !cv.is_type(CommunicationType::pong) {
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
                "Anonymous: {}",
                &cv.to_json().to_string()
            );

            if cv.is_type(CommunicationType::identification) {
                let call_id = Uuid::parse_str(
                    cv.get_data(DataTypes::call_id)
                        .unwrap_or(&JsonValue::Null)
                        .as_str()
                        .unwrap_or(""),
                )
                .unwrap_or(Uuid::new_v4());

                let call = if let Some(call) = call_manager::get_call(call_id).await {
                    if call.is_anonymous().await {
                        call
                    } else {
                        self.send_error_response(
                            &cv.get_id(),
                            CommunicationType::error_not_authenticated,
                        )
                        .await;
                        return;
                    }
                } else {
                    self.send_error_response(
                        &cv.get_id(),
                        CommunicationType::error_not_authenticated,
                    )
                    .await;
                    return;
                };

                let mut invited = JsonValue::new_array();
                for call_invitee in call.members.read().await.clone() {
                    let call_invitee_cv = get_omega_connection()
                        .await_response(
                            &CommunicationValue::new(CommunicationType::get_user_data).add_data(
                                DataTypes::user_id,
                                JsonValue::from(call_invitee.user_id),
                            ),
                            Some(Duration::from_secs(2)),
                        )
                        .await
                        .unwrap();
                    let mut json_invitee = JsonValue::new_object();
                    let _ = json_invitee.insert(
                        "user_id",
                        call_invitee_cv
                            .get_data(DataTypes::user_id)
                            .unwrap_or(&JsonValue::Null)
                            .clone(),
                    );
                    let _ = json_invitee.insert(
                        "username",
                        call_invitee_cv
                            .get_data(DataTypes::username)
                            .unwrap_or(&JsonValue::Null)
                            .clone(),
                    );
                    let _ = json_invitee.insert(
                        "display",
                        call_invitee_cv
                            .get_data(DataTypes::display)
                            .unwrap_or(&JsonValue::Null)
                            .clone(),
                    );
                    let _ = json_invitee.insert(
                        "avatar",
                        call_invitee_cv
                            .get_data(DataTypes::avatar)
                            .unwrap_or(&JsonValue::Null)
                            .clone(),
                    );

                    let _ = invited.push(json_invitee);
                }

                let token = call.create_anonymous_token(self.get_user_id().await).await;

                let mut serialized = JsonValue::new_object();
                let _ = serialized.insert("call_id", JsonValue::String(call_id.to_string()));
                let _ = serialized.insert("call_invited", invited.clone());
                let _ = serialized.insert("call_members", invited);
                let _ = serialized.insert("call_token", JsonValue::String(token.unwrap()));
                self.clone()
                    .send_message(
                        &&CommunicationValue::new(CommunicationType::identification_response)
                            .with_id(cv.get_id())
                            .add_data(
                                DataTypes::user_id,
                                JsonValue::from(self.get_user_id().await),
                            )
                            .add_data(
                                DataTypes::username,
                                JsonValue::String(self.clone().get_user_name().await),
                            )
                            .add_data(
                                DataTypes::display,
                                JsonValue::String(self.get_display_name().await),
                            )
                            .add_data(
                                DataTypes::avatar,
                                JsonValue::String(self.get_avatar().await),
                            )
                            .add_data(DataTypes::call_state, serialized),
                    )
                    .await;
            }

            // Handle ping
            if cv.is_type(CommunicationType::ping) {
                self.handle_ping(cv).await;
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

            if cv.is_type(CommunicationType::change_user_data) {
                if let Some(display_name) = cv
                    .get_data(DataTypes::display)
                    .unwrap_or(&JsonValue::Null)
                    .as_str()
                {
                    let _ = self.set_display_name(display_name.to_string()).await;
                }

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

            if cv.is_type(CommunicationType::get_user_data)
                || cv.is_type(CommunicationType::get_iota_data)
                || cv.is_type(CommunicationType::delete_user)
            {
                self.handle_omega_forward(cv).await;
                return;
            }
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

        // Send pong response
        let response = CommunicationValue::new(CommunicationType::pong).with_id(cv.get_id());

        self.send_message(&response).await;
    }

    /// Handle client status change
    async fn handle_client_changed(self: Arc<Self>, _cv: CommunicationValue) {
        /*let user_id = self.get_user_id().await;
        if let Some(_status_str) = cv.get_data(DataTypes::user_state) {
            let user_status = UserStatus::online;
        }*/
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

        // TODO delete temp user
    }
}

// Implement Clone to make it easier to work with Arc<AnonymousClientConnection>
impl Clone for AnonymousClientConnection {
    fn clone(&self) -> Self {
        Self {
            sender: Arc::clone(&self.sender),
            receiver: Arc::clone(&self.receiver),
            user_id: Arc::clone(&self.user_id),
            ping: Arc::clone(&self.ping),
            interested_users: Arc::clone(&self.interested_users),
            is_open: Arc::clone(&self.is_open),
            user_name: Arc::clone(&self.user_name),
            display_name: Arc::clone(&self.display_name),
            avatar: Arc::clone(&self.avatar),
        }
    }
}
