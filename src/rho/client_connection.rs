use futures::SinkExt;
use std::sync::{Arc, Weak};
use tokio::sync::Mutex;
use tokio::sync::RwLock;
use tokio_tungstenite::{WebSocketStream, tungstenite::Message};
use tungstenite::Utf8Bytes;
use uuid::Uuid;

use super::{rho_connection::RhoConnection, rho_manager};
use crate::{
    auth::auth_connector,
    // calls::call_manager::CallManager,
    data::{
        communication::{CommunicationType, CommunicationValue, DataTypes},
        user::{User, UserStatus},
    },
    omega::omega_connection::OmegaConnection,
};

/// ClientConnection represents a WebSocket connection from a client device
pub struct ClientConnection {
    /// WebSocket session
    pub session: Arc<Mutex<WebSocketStream<tokio::net::TcpStream>>>,
    /// User ID associated with this client
    pub user_id: Arc<RwLock<Option<Uuid>>>,
    /// Whether this connection has been identified/authenticated
    pub identified: Arc<RwLock<bool>>,
    /// Ping latency tracking
    pub ping: Arc<RwLock<i64>>,
    /// Weak reference to RhoConnection to avoid circular references
    pub rho_connection: Arc<RwLock<Option<Weak<RhoConnection>>>>,
    /// List of user IDs this client is interested in receiving updates about
    pub interested_users: Arc<RwLock<Vec<Uuid>>>,
}

impl ClientConnection {
    /// Create a new ClientConnection
    pub fn new(session: WebSocketStream<tokio::net::TcpStream>) -> Arc<Self> {
        Arc::new(Self {
            session: Arc::new(Mutex::new(session)),
            user_id: Arc::new(RwLock::new(None)),
            identified: Arc::new(RwLock::new(false)),
            ping: Arc::new(RwLock::new(-1)),
            rho_connection: Arc::new(RwLock::new(None)),
            interested_users: Arc::new(RwLock::new(Vec::new())),
        })
    }

    /// Get the user ID
    pub async fn get_user_id(&self) -> Option<Uuid> {
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

    /// Set the RhoConnection reference
    pub async fn set_rho_connection(&self, rho_connection: Weak<RhoConnection>) {
        let mut rho_ref = self.rho_connection.write().await;
        *rho_ref = Some(rho_connection);
    }

    /// Get RhoConnection if available
    pub async fn get_rho_connection(&self) -> Option<Arc<RhoConnection>> {
        let rho_ref = self.rho_connection.read().await;
        if let Some(weak_ref) = rho_ref.as_ref() {
            weak_ref.upgrade()
        } else {
            None
        }
    }

    /// Send a string message to the client
    pub async fn send_message_str(&self, message: &str) {
        let mut session = self.session.lock().await;
        if let Err(e) = session
            .send(Message::Text(Utf8Bytes::from(message.to_string())))
            .await
        {
            eprintln!("Failed to send message to client: {}", e);
        }
    }

    /// Send a CommunicationValue to the client
    pub async fn send_message(&self, cv: &CommunicationValue) {
        self.send_message_str(&cv.to_json().to_string()).await;
    }

    /// Handle incoming message from client
    pub async fn handle_message(self: Arc<Self>, message: Utf8Bytes) {
        let cv = CommunicationValue::from_json(&message);

        // Handle identification
        if cv.is_type(CommunicationType::identification) && !self.is_identified().await {
            self.handle_identification(Arc::clone(&self), cv).await;
            return;
        }

        if !self.is_identified().await {
            return;
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
        if cv.is_type(CommunicationType::get_call) {
            self.handle_get_call(cv).await;
            return;
        }

        // Forward other messages to Iota
        self.forward_to_iota(cv).await;
    }

    /// Handle identification message
    async fn handle_identification(&self, sarc: Arc<ClientConnection>, mut cv: CommunicationValue) {
        // Extract user ID
        let user_id = match cv.get_data(DataTypes::user_id) {
            Some(id_str) => match Uuid::parse_str(&id_str.to_string()) {
                Ok(id) => id,
                Err(_) => {
                    self.send_error_response(
                        &cv.get_id(),
                        CommunicationType::error_invalid_user_id,
                    )
                    .await;
                    return;
                }
            },
            None => {
                self.send_error_response(&cv.get_id(), CommunicationType::error_invalid_user_id)
                    .await;
                return;
            }
        };

        // Validate private key
        if let Some(private_key_hash) = cv.get_data(DataTypes::private_key_hash) {
            println!("private_key_hash: {}", private_key_hash);
            let is_valid =
                auth_connector::is_private_key_valid(user_id, &private_key_hash.to_string()).await;

            if !is_valid {
                println!("Invalid private key");
                self.send_error_response(
                    &cv.get_id(),
                    CommunicationType::error_invalid_private_key,
                )
                .await;
                return;
            }
        } else {
            println!("Missing private key");
            self.send_error_response(&cv.get_id(), CommunicationType::error_invalid_private_key)
                .await;
            return;
        }

        // Find RhoConnection for this user
        let rho_connection = match rho_manager::get_rho_con_for_user(user_id).await {
            Some(rho) => rho,
            None => {
                self.send_error_response(&cv.get_id(), CommunicationType::error_no_iota)
                    .await;
                return;
            }
        };

        // Set identification data
        {
            let mut user_id_guard = self.user_id.write().await;
            *user_id_guard = Some(user_id);
        }
        {
            let mut identified_guard = self.identified.write().await;
            *identified_guard = true;
        }

        self.set_rho_connection(Arc::downgrade(&rho_connection))
            .await;

        rho_connection.add_client_connection(Arc::from(sarc)).await;

        let response = CommunicationValue::new(CommunicationType::identification_response)
            .with_id(cv.get_id());
        self.send_message(&response).await;
    }

    /// Handle ping message
    async fn handle_ping(&self, mut cv: CommunicationValue) {
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
            .add_data_str(DataTypes::ping_iota, iota_ping.to_string());

        self.send_message(&response).await;
    }

    /// Handle client status change
    async fn handle_client_changed(&self, mut cv: CommunicationValue) {
        if let Some(user_id) = self.get_user_id().await {
            if let Some(status_str) = cv.get_data(DataTypes::user_state) {
                // Parse user status - this would need to be implemented properly
                let user_status = UserStatus::online; // placeholder
                if let Some(rho_conn) = self.get_rho_connection().await {
                    OmegaConnection::client_changed(
                        rho_conn.get_iota_id().await,
                        user_id,
                        user_status,
                    )
                    .await;
                }
            }
        }
    }

    /// Handle call invite
    async fn handle_call_invite(&self, cv: CommunicationValue) {
        let receiver_id = match cv.get_data(DataTypes::receiver_id) {
            Some(id_str) => match Uuid::parse_str(&id_str.to_string()) {
                Ok(id) => id,
                Err(_) => {
                    self.send_error_response(&cv.get_id(), CommunicationType::error)
                        .await;
                    return;
                }
            },
            None => {
                self.send_error_response(&cv.get_id(), CommunicationType::error)
                    .await;
                return;
            }
        };

        let call_id = match cv.get_data(DataTypes::call_id) {
            Some(id_str) => match Uuid::parse_str(&id_str.to_string()) {
                Ok(id) => id,
                Err(_) => {
                    self.send_error_response(&cv.get_id(), CommunicationType::error)
                        .await;
                    return;
                }
            },
            None => {
                self.send_error_response(&cv.get_id(), CommunicationType::error)
                    .await;
                return;
            }
        };

        let call_secret_sha = cv
            .get_data(DataTypes::call_secret_sha)
            .map(|s| s.to_string());
        let call_secret = cv.get_data(DataTypes::call_secret).map(|s| s.to_string());

        if call_secret_sha.is_none() || call_secret.is_none() {
            self.send_error_response(&cv.get_id(), CommunicationType::error)
                .await;
            return;
        }

        // Get call group - placeholder implementation
        // let call_group = CallManager::get_call_group(call_id, &call_secret_sha.unwrap(), true).await;
        // if call_group.is_none() {
        //     self.send_error_response(&cv.get_id(), CommunicationType::error)
        //         .await;
        //     return;
        // }

        // Find target RhoConnection
        let target_rho = match rho_manager::get_rho_con_for_user(receiver_id).await {
            Some(rho) => rho,
            None => {
                self.send_error_response(&cv.get_id(), CommunicationType::error)
                    .await;
                return;
            }
        };

        // Get sender user ID
        let sender_id = match self.get_user_id().await {
            Some(id) => id,
            None => return,
        };

        // Create and send call distribution message
        let distribute = CommunicationValue::new(CommunicationType::new_call)
            .with_receiver(receiver_id)
            .with_sender(sender_id)
            .add_data_str(DataTypes::call_id, call_id.to_string())
            .add_data_str(DataTypes::receiver_id, receiver_id.to_string())
            .add_data_str(DataTypes::sender_id, sender_id.to_string())
            .add_data_str(DataTypes::call_secret, call_secret.unwrap());

        target_rho.message_iota_to_client(distribute).await;

        // Handle call group invitation logic here
        // This would require implementing CallGroup::Caller and related functionality

        // Send success response
        let response = CommunicationValue::new(CommunicationType::call_invite).with_id(cv.get_id());
        self.send_message(&response).await;
    }

    /// Handle get call request
    async fn handle_get_call(&self, mut cv: CommunicationValue) {
        let user_id = match self.get_user_id().await {
            Some(id) => id,
            None => return,
        };

        let call_id = match cv.get_data(DataTypes::call_id) {
            Some(id_str) => match Uuid::parse_str(&id_str.to_string()) {
                Ok(id) => id,
                Err(_) => {
                    self.send_error_response(&cv.get_id(), CommunicationType::error)
                        .await;
                    return;
                }
            },
            None => {
                self.send_error_response(&cv.get_id(), CommunicationType::error)
                    .await;
                return;
            }
        };

        let call_secret_sha = cv
            .get_data(DataTypes::call_secret_sha)
            .map(|s| s.to_string());

        if call_secret_sha.is_none() {
            self.send_error_response(&cv.get_id(), CommunicationType::error)
                .await;
            return;
        }

        // Get call group
        let mut response = CommunicationValue::new(CommunicationType::get_call)
            .with_id(cv.get_id())
            .with_receiver(user_id);

        // Placeholder call group logic
        // if let Some(call_group) = CallManager::get_call_group(call_id, &call_secret_sha.unwrap(), true).await {
        //     response = response
        //         .add_data_str(DataTypes::call_state, call_group.call_state.to_string())
        //         .add_data_str(DataTypes::start_date, call_group.started_at.to_string());
        //
        //     if call_group.ended_at != 0 {
        //         response = response.add_data_str(DataTypes::end_date, call_group.ended_at.to_string());
        //     }
        // } else {
        response = response.add_data_str(DataTypes::call_state, "DESTROYED".to_string());
        // }

        self.send_message(&response).await;
    }

    /// Forward message to Iota
    async fn forward_to_iota(&self, mut cv: CommunicationValue) {
        if let Some(user_id) = self.get_user_id().await {
            if let Some(rho_conn) = self.get_rho_connection().await {
                let updated_cv = cv.with_sender(user_id);
                rho_conn.message_to_iota(updated_cv).await;
            }
        }
    }

    /// Send error response
    async fn send_error_response(&self, message_id: &Uuid, error_type: CommunicationType) {
        let error = CommunicationValue::new(error_type).with_id(*message_id);
        self.send_message(&error).await;
    }

    /// Close the connection
    pub async fn close(&self) {
        let mut session = self.session.lock().await;
        let _ = session.close(None).await;
    }

    /// Set interested users list
    pub async fn set_interested_users(&self, interested_ids: Vec<Uuid>) {
        let mut interested_guard = self.interested_users.write().await;
        *interested_guard = interested_ids;
    }

    /// Check if interested in a user and send notification
    pub async fn are_you_interested(&self, user: &User) {
        let interested_guard = self.interested_users.read().await;
        if interested_guard.contains(&user.user_id) {
            let notification = CommunicationValue::new(CommunicationType::client_changed)
                .add_data_str(DataTypes::user_id, user.user_id.to_string())
                .add_data_str(
                    DataTypes::user_state,
                    format!("{:?}", user.status.to_string()),
                );

            self.send_message(&notification).await;
        }
    }

    /// Handle connection close
    pub async fn handle_close(&self) {
        if self.is_identified().await {
            if let Some(user_id) = self.get_user_id().await {
                if let Some(rho_conn) = rho_manager::get_rho_con_for_user(user_id).await {
                    rho_conn
                        .close_client_connection(Arc::new(self.clone()))
                        .await;
                }
            }
        }
    }
}

// Implement Clone to make it easier to work with Arc<ClientConnection>
impl Clone for ClientConnection {
    fn clone(&self) -> Self {
        Self {
            session: Arc::clone(&self.session),
            user_id: Arc::clone(&self.user_id),
            identified: Arc::clone(&self.identified),
            ping: Arc::clone(&self.ping),
            rho_connection: Arc::clone(&self.rho_connection),
            interested_users: Arc::clone(&self.interested_users),
        }
    }
}

impl std::fmt::Debug for ClientConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientConnection")
            .field("user_id", &"[async]")
            .field("identified", &"[async]")
            .field("ping", &"[async]")
            .finish()
    }
}
