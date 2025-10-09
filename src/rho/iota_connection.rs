use futures::SinkExt;
use json::{JsonValue, number::Number};
use std::{
    collections::HashMap,
    sync::{Arc, Weak},
};
use tokio::sync::{Mutex, RwLock};
use tokio_tungstenite::{WebSocketStream, tungstenite::Message};
use tungstenite::Utf8Bytes;
use uuid::Uuid;

use super::{rho_connection::RhoConnection, rho_manager};
use crate::{
    auth::auth_connector,
    // calls::call_manager::CallManager,
    data::{
        communication::{CommunicationType, CommunicationValue, DataTypes},
        user::User,
    },
    omega::omega_connection::OmegaConnection,
};

/// IotaConnection represents a WebSocket connection from an Iota device
pub struct IotaConnection {
    session: Arc<Mutex<WebSocketStream<tokio::net::TcpStream>>>,
    iota_id: Arc<RwLock<Uuid>>,
    user_ids: Arc<RwLock<Vec<Uuid>>>,
    identified: Arc<RwLock<bool>>,
    ping: Arc<RwLock<i64>>,
    rho_connection: Arc<RwLock<Option<Weak<RhoConnection>>>>,
}

impl IotaConnection {
    /// Create a new IotaConnection
    pub fn new(session: WebSocketStream<tokio::net::TcpStream>) -> Arc<Self> {
        Arc::new(Self {
            session: Arc::new(Mutex::new(session)),
            iota_id: Arc::new(RwLock::new(Uuid::nil())),
            user_ids: Arc::new(RwLock::new(Vec::new())),
            identified: Arc::new(RwLock::new(false)),
            ping: Arc::new(RwLock::new(0)),
            rho_connection: Arc::new(RwLock::new(None)),
        })
    }

    /// Create with known IDs (for testing)
    pub fn new_with_ids(
        iota_id: Uuid,
        user_ids: Vec<Uuid>,
        session: Arc<Mutex<WebSocketStream<tokio::net::TcpStream>>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            session,
            iota_id: Arc::new(RwLock::new(iota_id)),
            user_ids: Arc::new(RwLock::new(user_ids)),
            identified: Arc::new(RwLock::new(true)),
            ping: Arc::new(RwLock::new(0)),
            rho_connection: Arc::new(RwLock::new(None)),
        })
    }

    /// Get the Iota ID
    pub async fn get_iota_id(&self) -> Uuid {
        *self.iota_id.read().await
    }

    /// Get the user IDs
    pub async fn get_user_ids(&self) -> Vec<Uuid> {
        self.user_ids.read().await.clone()
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

    /// Send a message to the Iota
    pub async fn send_message_str(&self, message: &str) {
        let mut session = self.session.lock().await;
        let _ = session
            .send(Message::Text(Utf8Bytes::from(message.to_string())))
            .await;
    }

    /// Send a CommunicationValue to the Iota
    pub async fn send_message(&self, cv: CommunicationValue) {
        self.send_message_str(&cv.to_json().to_string()).await;
    }

    /// Handle incoming message from Iota
    pub async fn handle_message(self: Arc<Self>, message: String) {
        let cv = CommunicationValue::from_json(&message);

        // Handle identification
        if cv.is_type(CommunicationType::identification) && !self.is_identified().await {
            self.handle_identification(cv).await;
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

        // Handle forwarding to other Iotas or clients
        let receiver_id = cv.get_receiver();
        if !self.get_user_ids().await.contains(&receiver_id)
            || cv.is_type(CommunicationType::message_other_iota)
            || cv.is_type(CommunicationType::send_chat)
        {
            self.handle_forward_message(cv).await;
            return;
        }

        // Handle GET_CHATS
        if cv.is_type(CommunicationType::get_chats) {
            self.handle_get_chats(cv).await;
            return;
        }

        // Forward to client
        self.forward_to_client(cv).await;
    }

    /// Handle identification message
    async fn handle_identification(self: Arc<Self>, mut cv: CommunicationValue) {
        // Parse Iota ID
        let iota_id = match cv.get_data(DataTypes::iota_id) {
            Some(id_str) => match Uuid::parse_str(&id_str.to_string()) {
                Ok(id) => id,
                Err(_) => {
                    self.send_error_response(&cv.get_id()).await;
                    return;
                }
            },
            None => {
                self.send_error_response(&cv.get_id()).await;
                return;
            }
        };

        // Parse user IDs
        let mut validated_user_ids = Vec::new();
        if let Some(user_ids_str) = cv.get_data(DataTypes::user_ids) {
            for id_str in user_ids_str.to_string().split(',') {
                if id_str.is_empty() {
                    continue;
                }
                if let Ok(user_id) = Uuid::parse_str(id_str.trim()) {
                    let auth_iota_id = auth_connector::get_iota_id(user_id).await.unwrap();
                    if auth_iota_id == iota_id {
                        validated_user_ids.push(user_id);
                    }
                }
            }
        }

        // Set identification data
        {
            let mut iota_id_guard = self.iota_id.write().await;
            *iota_id_guard = iota_id;
        }
        {
            let mut user_ids_guard = self.user_ids.write().await;
            *user_ids_guard = validated_user_ids.clone();
        }
        {
            let mut identified_guard = self.identified.write().await;
            *identified_guard = true;
        }

        // Check for existing connection and close it
        if rho_manager::contains_iota(iota_id).await {
            if let Some(existing_rho) = rho_manager::get_rho_by_iota(iota_id).await {
                existing_rho.close_iota_connection().await;
            }
        }

        // Create RhoConnection
        let rho_connection =
            Arc::new(RhoConnection::new(self.clone(), validated_user_ids.clone()).await);

        // Set up bidirectional reference
        self.set_rho_connection(Arc::downgrade(&rho_connection))
            .await;

        // Add to manager
        rho_manager::add_rho(rho_connection).await;

        // Send response
        let response = CommunicationValue::new(CommunicationType::identification_response)
            .with_id(cv.get_id())
            .add_data_str(DataTypes::accepted, validated_user_ids.len().to_string());

        self.send_message(response).await;
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

        // Collect client pings
        let client_pings = if let Some(rho_conn) = self.get_rho_connection().await {
            rho_conn.get_client_pings().await
        } else {
            HashMap::new()
        };

        // Send pong response
        let pings = client_pings
            .into_iter()
            .map(|(k, v)| (k, JsonValue::String(v.to_string())))
            .collect();
        let response = CommunicationValue::new(CommunicationType::pong)
            .with_id(cv.get_id())
            .add_data(DataTypes::ping_clients, JsonValue::Object(pings));
        self.send_message(response).await;
    }

    /// Handle message forwarding to other Iotas
    async fn handle_forward_message(&self, cv: CommunicationValue) {
        let receiver_id = cv.get_receiver();
        // Validate sender if present
        let sender_id = cv.get_sender();
        if !self.get_user_ids().await.contains(&sender_id) {
            self.send_error_response(&cv.get_id()).await;
            return;
        }

        // Find target RhoConnection
        if let Some(target_rho) = rho_manager::get_rho_con_for_user(receiver_id).await {
            target_rho.message_to_iota(cv).await;
        } else {
            // Send error if target not found
            let error = CommunicationValue::new(CommunicationType::error)
                .with_id(cv.get_id())
                .with_sender(cv.get_sender());
            self.send_message(error).await;
        }
    }

    /// Handle GET_CHATS message
    async fn handle_get_chats(&self, mut cv: CommunicationValue) {
        let receiver_id = cv.get_receiver();
        let mut interested_ids: Vec<Uuid> = Vec::new();

        // Process contacts and add call information
        if let Some(contacts_data) = cv.get_data(DataTypes::user_ids) {
            // Parse contacts JSON array and enrich with call data
            // This would need proper JSON parsing implementation
            // For now, placeholder logic:

            // Extract user IDs from contacts
            // let contacts: Vec<ContactInfo> = parse_contacts(contacts_data);
            // for contact in &contacts {
            //     interested_ids.push(contact.user_id);
            // }

            // Get call invites for receiver
            // let invites = CallManager::get_call_invites(receiver_id).await;

            // Enrich contacts with call information
            // let enriched_contacts = enrich_with_calls(contacts, invites);

            // cv = cv.add_data(DataTypes::user_ids, enriched_contacts.into());
        }

        // Notify OmegaConnection about user states
        OmegaConnection::user_states(receiver_id, interested_ids.clone());

        // Set interested users in RhoConnection
        if let Some(rho_conn) = self.get_rho_connection().await {
            rho_conn.set_interested(receiver_id, interested_ids).await;
        }

        // Forward to client
        self.forward_to_client(cv).await;
    }

    /// Forward message to client
    async fn forward_to_client(&self, cv: CommunicationValue) {
        if let Some(rho_conn) = self.get_rho_connection().await {
            let updated_cv = cv.with_sender(self.get_iota_id().await);
            let receiver_id = updated_cv.get_receiver();
            rho_conn.message_iota_to_client(updated_cv).await;
        }
    }

    /// Send error response
    async fn send_error_response(&self, message_id: &Uuid) {
        let error = CommunicationValue::new(CommunicationType::error).with_id(*message_id);
        self.send_message(error).await;
    }

    /// Handle connection close
    pub async fn handle_close(&self) {
        if self.is_identified().await {
            if let Some(rho_conn) = self.get_rho_connection().await {
                rho_conn.close_iota_connection().await;
            }
        }
    }
}

impl std::fmt::Debug for IotaConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IotaConnection")
            .field("iota_id", &"[async]")
            .field("identified", &"[async]")
            .field("ping", &"[async]")
            .finish()
    }
}
