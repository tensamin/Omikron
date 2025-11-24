use crate::calls::call_group::CallGroup;
use crate::calls::call_manager;
use crate::util::print::PrintType;
use crate::util::print::line;
use crate::util::print::line_err;
use async_tungstenite::WebSocketReceiver;
use async_tungstenite::WebSocketSender;
use async_tungstenite::tungstenite::Message;
use json::JsonValue;
use json::parse;
use std::{
    collections::HashMap,
    sync::{Arc, Weak},
};
use tokio::sync::RwLock;
use tokio_util::compat::Compat;
use tower::retry::backoff::InvalidBackoff;
use tungstenite::Utf8Bytes;
use uuid::Uuid;

use super::{rho_connection::RhoConnection, rho_manager};
use crate::{
    auth::auth_connector,
    // calls::call_manager::CallManager,
    data::communication::{CommunicationType, CommunicationValue, DataTypes},
    omega::omega_connection::OmegaConnection,
};

pub struct IotaConnection {
    pub sender: Arc<RwLock<WebSocketSender<Compat<tokio::net::TcpStream>>>>,
    pub receiver: Arc<RwLock<WebSocketReceiver<Compat<tokio::net::TcpStream>>>>,
    pub iota_id: Arc<RwLock<Uuid>>,
    pub user_ids: Arc<RwLock<Vec<Uuid>>>,
    pub identified: Arc<RwLock<bool>>,
    pub ping: Arc<RwLock<i64>>,
    pub rho_connection: Arc<RwLock<Option<Weak<RhoConnection>>>>,
}

impl IotaConnection {
    /// Create a new IotaConnection
    pub fn new(
        sender: WebSocketSender<Compat<tokio::net::TcpStream>>,
        receiver: WebSocketReceiver<Compat<tokio::net::TcpStream>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            sender: Arc::new(RwLock::new(sender)),
            receiver: Arc::new(RwLock::new(receiver)),
            iota_id: Arc::new(RwLock::new(Uuid::nil())),
            user_ids: Arc::new(RwLock::new(Vec::new())),
            identified: Arc::new(RwLock::new(false)),
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
        let mut session = self.sender.write().await;
        if let Err(e) = session
            .send(Message::Text(Utf8Bytes::from(message.to_string())))
            .await
        {
            line_err(
                PrintType::IotaOut,
                &format!("Failed to send WebSocket message: {:?}", e),
            );
        }
    }

    /// Send a CommunicationValue to the Iota
    pub async fn send_message(&self, cv: CommunicationValue) {
        if !cv.is_type(CommunicationType::pong) {
            line(PrintType::IotaOut, &cv.to_json().to_string());
        }
        self.send_message_str(&cv.to_json().to_string()).await;
    }

    /// Handle incoming message from Iota
    pub async fn handle_message(self: Arc<Self>, message: Utf8Bytes) {
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
        line(PrintType::IotaIn, &cv.to_json().to_string());
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
    async fn handle_identification(self: Arc<Self>, cv: CommunicationValue) {
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
        let mut validated_user_ids: Vec<Uuid> = Vec::new();
        if let Some(user_ids_str) = cv.get_data(DataTypes::user_ids) {
            for id_str in user_ids_str.to_string().split(',') {
                if id_str.is_empty() {
                    continue;
                }
                if let Ok(user_id) = Uuid::parse_str(id_str.trim()) {
                    if let Some(auth_iota_id) = auth_connector::get_iota_id(user_id).await {
                        if auth_iota_id == iota_id {
                            validated_user_ids.push(user_id);
                        }
                    } else {
                        line(PrintType::IotaIn, "User ID not found");
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
        let mut str = String::new();
        for id in &validated_user_ids {
            str.push_str(&format!(",{}", id));
        }
        let response = CommunicationValue::new(CommunicationType::identification_response)
            .with_id(cv.get_id())
            .add_data_str(DataTypes::accepted_ids, str)
            .add_data_str(DataTypes::accepted, validated_user_ids.len().to_string());

        self.send_message(response).await;
    }

    /// Handle ping message
    async fn handle_ping(&self, cv: CommunicationValue) {
        if let Some(last_ping) = cv.get_data(DataTypes::last_ping) {
            if let Ok(ping_val) = last_ping.to_string().parse::<i64>() {
                let mut ping_guard = self.ping.write().await;
                *ping_guard = ping_val;
            }
        }

        let client_pings = if let Some(rho_conn) = self.get_rho_connection().await {
            rho_conn.get_client_pings().await
        } else {
            HashMap::new()
        };

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
        let sender_id = cv.get_sender();
        if !self.get_user_ids().await.contains(&sender_id) {
            self.send_message(CommunicationValue::new(
                CommunicationType::error_invalid_user_id,
            ))
            .await;
            return;
        }

        if let Some(target_rho) = rho_manager::get_rho_con_for_user(receiver_id).await {
            target_rho.message_to_iota(cv).await;
        } else {
            let error = CommunicationValue::new(CommunicationType::error_no_iota)
                .with_id(cv.get_id())
                .with_sender(cv.get_sender());
            self.send_message(error).await;
        }
    }

    /// Handle GET_CHATS message
    async fn handle_get_chats(&self, cv: CommunicationValue) {
        let receiver_id = cv.get_receiver();
        let mut interested_ids: Vec<Uuid> = Vec::new();

        let calls: Vec<Arc<CallGroup>> = call_manager::get_call_groups(receiver_id).await;
        let mut invites: HashMap<Uuid, Vec<Uuid>> = HashMap::new();

        for call in calls {
            for inviter in call.members.read().await.iter() {
                let inviter_id = inviter.user_id;
                if let Some(call_ids) = invites.get_mut(&inviter_id) {
                    call_ids.push(call.call_id);
                } else {
                    invites.insert(inviter_id, vec![call.call_id]);
                }
            }
        }

        // Process contacts and add call information
        // Enriched Contacts data:
        // [{"user_id": "uuid", "calls": ["call_id"]}, {"user_id": "uuid"}]
        let mut enriched_contacts = JsonValue::new_array();
        // Contacts data:
        // [{"user_id": "uuid"}, {"user_id": "uuid"}]
        if let Some(contacts_data) = cv.get_data(DataTypes::user_ids) {
            if let JsonValue::Array(user_ids) = contacts_data {
                for user_id in user_ids {
                    if let JsonValue::String(user_id_str) = user_id {
                        if let Ok(user_id) = Uuid::parse_str(user_id_str) {
                            interested_ids.push(user_id);
                            let mut enriched_contact = JsonValue::new_object();
                            let _ = enriched_contact.insert("user_id", user_id.to_string());
                            let _ = enriched_contact.insert("calls", JsonValue::new_array());
                            let _ = enriched_contacts.push(enriched_contact);
                        }
                    }
                }
            } else {
                enriched_contacts = contacts_data.clone();
            }
        }

        // Notify OmegaConnection about user states
        OmegaConnection::user_states(receiver_id, interested_ids.clone()).await;

        // Set interested users in RhoConnection
        if let Some(rho_conn) = self.get_rho_connection().await {
            rho_conn.set_interested(receiver_id, interested_ids).await;
        }

        // Forward to client
        self.forward_to_client(cv.add_data(DataTypes::user_ids, enriched_contacts))
            .await;
    }

    /// Forward message to client
    async fn forward_to_client(&self, cv: CommunicationValue) {
        if let Some(rho_conn) = self.get_rho_connection().await {
            let updated_cv = cv.with_sender(self.get_iota_id().await);
            let _receiver_id = updated_cv.get_receiver();
            rho_conn.message_to_client(updated_cv).await;
        }
    }

    async fn send_error_response(&self, message_id: &Uuid) {
        let error = CommunicationValue::new(CommunicationType::error).with_id(*message_id);
        self.send_message(error).await;
    }

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
