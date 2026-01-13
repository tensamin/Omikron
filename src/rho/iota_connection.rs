use crate::calls::call_group::CallGroup;
use crate::calls::call_manager;
use crate::get_private_key;
use crate::get_public_key;
use crate::log_err;
use crate::log_in;
use crate::log_out;
use crate::omega::omega_connection::WAITING_TASKS;
use crate::omega::omega_connection::get_omega_connection;
use crate::util::crypto_helper::encrypt;
use crate::util::crypto_helper::load_public_key;
use crate::util::crypto_helper::public_key_to_base64;
use crate::util::logger::PrintType;
use async_tungstenite::WebSocketReceiver;
use async_tungstenite::WebSocketSender;
use async_tungstenite::tungstenite::Message;
use dashmap::DashMap;
use json::JsonValue;
use rand::Rng;
use rand::distributions::Alphanumeric;
use std::{
    collections::HashMap,
    sync::{Arc, Weak},
};
use tokio::sync::RwLock;
use tokio_util::compat::Compat;
use tungstenite::Utf8Bytes;
use uuid::Uuid;
use x448::PublicKey;

use super::{rho_connection::RhoConnection, rho_manager};
use crate::{
    // calls::call_manager::CallManager,
    data::communication::{CommunicationType, CommunicationValue, DataTypes},
    omega::omega_connection::OmegaConnection,
};

pub struct IotaConnection {
    pub sender: Arc<RwLock<WebSocketSender<Compat<tokio::net::TcpStream>>>>,
    pub receiver: Arc<RwLock<WebSocketReceiver<Compat<tokio::net::TcpStream>>>>,
    pub iota_id: Arc<RwLock<i64>>,
    pub user_ids: Arc<RwLock<Vec<i64>>>,
    identified: Arc<RwLock<bool>>,
    challenged: Arc<RwLock<bool>>,
    challenge: Arc<RwLock<String>>,
    pub ping: Arc<RwLock<i64>>,
    pub_key: Arc<RwLock<Option<Vec<u8>>>>,
    pub waiting_tasks:
        DashMap<Uuid, Box<dyn Fn(Arc<OmegaConnection>, CommunicationValue) -> bool + Send + Sync>>,
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
            iota_id: Arc::new(RwLock::new(0)),
            user_ids: Arc::new(RwLock::new(Vec::new())),
            identified: Arc::new(RwLock::new(false)),
            challenged: Arc::new(RwLock::new(false)),
            challenge: Arc::new(RwLock::new(String::new())),
            ping: Arc::new(RwLock::new(0)),
            pub_key: Arc::new(RwLock::new(None)),
            waiting_tasks: DashMap::new(),
            rho_connection: Arc::new(RwLock::new(None)),
        })
    }

    /// Get the Iota ID
    pub async fn get_iota_id(&self) -> i64 {
        *self.iota_id.read().await
    }

    pub async fn get_public_key(&self) -> Option<PublicKey> {
        if let Some(public_key) = self.pub_key.read().await.clone() {
            PublicKey::from_bytes(&public_key)
        } else {
            None
        }
    }

    /// Get the user IDs
    pub async fn get_user_ids(&self) -> Vec<i64> {
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
            log_err!(PrintType::Iota, "Failed to send WebSocket message: {:?}", e,);
        }
    }

    /// Send a CommunicationValue to the Iota
    pub async fn send_message(&self, cv: &CommunicationValue) {
        if !cv.is_type(CommunicationType::pong) {
            log_out!(PrintType::Iota, "{}", cv.to_json().to_string());
        }
        self.send_message_str(&cv.to_json().to_string()).await;
    }

    /// Handle incoming message from Iota
    pub async fn handle_message(self: Arc<Self>, message: Utf8Bytes) {
        let cv = CommunicationValue::from_json(&message);
        let identified = *self.identified.read().await;
        let challenged = *self.challenged.read().await;

        if !identified && cv.is_type(CommunicationType::identification) {
            let iota_id = cv
                .get_data(DataTypes::iota_id)
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            if iota_id == 0 {
                self.send_error_response(&cv.get_id(), CommunicationType::error_invalid_data)
                    .await;
                self.close().await;
                return;
            }

            let user_ids_json = cv
                .get_data(DataTypes::user_ids)
                .unwrap_or(&JsonValue::Null)
                .clone();
            let mut user_ids = Vec::new();
            if let JsonValue::Array(ids) = user_ids_json {
                for id_val in ids {
                    if let Some(id) = id_val.as_i64() {
                        user_ids.push(id);
                    }
                }
            }

            *self.iota_id.write().await = iota_id;
            *self.user_ids.write().await = user_ids;

            let get_pub_key_msg = CommunicationValue::new(CommunicationType::get_iota_data)
                .add_data(DataTypes::iota_id, JsonValue::from(iota_id));

            let msg_id = get_pub_key_msg.get_id();
            let iota_conn_clone = self.clone();
            let original_cv_id = cv.get_id();

            WAITING_TASKS.insert(
                msg_id,
                Box::new(move |_, response_cv: CommunicationValue| {
                    let iota_conn_for_task = iota_conn_clone.clone();
                    tokio::spawn(async move {
                        if !response_cv.is_type(CommunicationType::get_iota_data) {
                            iota_conn_for_task
                                .send_error_response(
                                    &original_cv_id,
                                    CommunicationType::error_internal,
                                )
                                .await;
                            iota_conn_for_task.close().await;
                            return;
                        }

                        let base64_pub = response_cv
                            .get_data(DataTypes::public_key)
                            .and_then(|v| v.as_str())
                            .unwrap_or("");

                        let pub_key = match load_public_key(base64_pub) {
                            Some(pk) => pk,
                            None => {
                                iota_conn_for_task
                                    .send_error_response(
                                        &original_cv_id,
                                        CommunicationType::error_invalid_public_key,
                                    )
                                    .await;
                                iota_conn_for_task.close().await;
                                return;
                            }
                        };

                        *iota_conn_for_task.pub_key.write().await =
                            Some(pub_key.as_bytes().to_vec());

                        let challenge: String = rand::thread_rng()
                            .sample_iter(&Alphanumeric)
                            .take(32)
                            .map(char::from)
                            .collect();

                        *iota_conn_for_task.challenge.write().await = challenge.clone();

                        let encrypted_challenge =
                            encrypt(get_private_key(), pub_key, &challenge).unwrap_or_default();

                        *iota_conn_for_task.identified.write().await = true;

                        let challenge_msg = CommunicationValue::new(CommunicationType::challenge)
                            .with_id(original_cv_id)
                            .add_data_str(
                                DataTypes::public_key,
                                public_key_to_base64(&get_public_key()),
                            )
                            .add_data_str(DataTypes::challenge, encrypted_challenge);

                        iota_conn_for_task.send_message(&challenge_msg).await;
                    });
                    true
                }),
            );

            get_omega_connection().send_message(&get_pub_key_msg).await;
            return;
        } else if !identified && cv.is_type(CommunicationType::complete_register_iota) {
            let base64_pub = cv
                .get_data(DataTypes::public_key)
                .and_then(|v| v.as_str())
                .unwrap_or("");

            if base64_pub.is_empty() {
                self.send_error_response(&cv.get_id(), CommunicationType::error_invalid_public_key)
                    .await;
                self.close().await;
                return;
            }

            let register_msg = CommunicationValue::new(CommunicationType::complete_register_iota)
                .add_data(
                    DataTypes::public_key,
                    JsonValue::String(base64_pub.to_string()),
                );

            let msg_id = register_msg.get_id();
            let iota_conn_clone = self.clone();
            let original_cv_id = cv.get_id();

            WAITING_TASKS.insert(
                msg_id,
                Box::new(move |_, response_cv: CommunicationValue| {
                    let iota_conn_for_task = iota_conn_clone.clone();
                    tokio::spawn(async move {
                        if !response_cv.is_type(CommunicationType::complete_register_iota) {
                            iota_conn_for_task
                                .send_error_response(
                                    &original_cv_id,
                                    CommunicationType::error_internal,
                                )
                                .await;
                            iota_conn_for_task.close().await;
                            return;
                        }

                        let new_iota_id = response_cv
                            .get_data(DataTypes::iota_id)
                            .and_then(|v| v.as_i64())
                            .unwrap_or(0);

                        if new_iota_id == 0 {
                            iota_conn_for_task
                                .send_error_response(
                                    &original_cv_id,
                                    CommunicationType::error_internal,
                                )
                                .await;
                            iota_conn_for_task.close().await;
                            return;
                        }

                        *iota_conn_for_task.iota_id.write().await = new_iota_id;
                        *iota_conn_for_task.identified.write().await = true;

                        let success_msg = CommunicationValue::new(CommunicationType::success)
                            .with_id(original_cv_id)
                            .add_data(DataTypes::iota_id, JsonValue::from(new_iota_id));

                        iota_conn_for_task.send_message(&success_msg).await;
                    });
                    true
                }),
            );
            get_omega_connection().send_message(&register_msg).await;
            return;
        }

        if identified && !challenged && cv.is_type(CommunicationType::challenge_response) {
            let client_response = cv
                .get_data(DataTypes::challenge)
                .and_then(|v| v.as_str())
                .unwrap_or("");

            if client_response == *self.challenge.read().await {
                *self.challenged.write().await = true;

                let iota_id = self.get_iota_id().await;
                let user_ids = self.get_user_ids().await;

                let mut validated_user_ids: Vec<i64> = Vec::new();
                for user_id in user_ids {
                    validated_user_ids.push(user_id);
                }

                if rho_manager::contains_iota(iota_id).await {
                    if let Some(existing_rho) = rho_manager::get_rho_by_iota(iota_id).await {
                        existing_rho.close_iota_connection().await;
                    }
                }

                let rho_connection =
                    Arc::new(RhoConnection::new(self.clone(), validated_user_ids.clone()).await);

                self.set_rho_connection(Arc::downgrade(&rho_connection))
                    .await;

                rho_manager::add_rho(rho_connection).await;

                let mut str = String::new();
                for id in &validated_user_ids {
                    str.push_str(&format!(",{}", id));
                }
                if !str.is_empty() {
                    str.remove(0);
                }

                self.send_message(
                    &CommunicationValue::new(CommunicationType::identification_response)
                        .with_id(cv.get_id())
                        .add_data_str(DataTypes::accepted_ids, str)
                        .add_data_str(DataTypes::accepted, validated_user_ids.len().to_string()),
                )
                .await;
            } else {
                self.send_error_response(&cv.get_id(), CommunicationType::error_invalid_challenge)
                    .await;
                self.close().await;
            }
            return;
        }

        if !self.is_identified().await {
            self.send_error_response(&cv.get_id(), CommunicationType::error_not_authenticated)
                .await;
            self.close().await;
            return;
        }

        // Handle ping
        if cv.is_type(CommunicationType::ping) {
            self.handle_ping(cv).await;
            return;
        }
        log_in!(PrintType::Iota, "{}", &cv.to_json().to_string());
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

        if cv.is_type(CommunicationType::change_iota_data)
            || cv.is_type(CommunicationType::get_user_data)
            || cv.is_type(CommunicationType::get_iota_data)
            || cv.is_type(CommunicationType::get_register)
            || cv.is_type(CommunicationType::complete_register_user)
            || cv.is_type(CommunicationType::delete_iota)
        {
            self.handle_omega_forward(cv).await;
            return;
        }
        // Forward to client
        self.forward_to_client(cv).await;
    }

    async fn send_error_response(&self, message_id: &Uuid, error_type: CommunicationType) {
        let error = CommunicationValue::new(error_type).with_id(*message_id);
        self.send_message(&error).await;
    }

    async fn close(&self) {
        let mut sender = self.sender.write().await;
        let _ = sender.close(None).await;
    }

    async fn handle_omega_forward(self: Arc<Self>, cv: CommunicationValue) {
        let iota_for_closure = self.clone();
        WAITING_TASKS.insert(
            cv.get_id(),
            Box::new(move |_, response_cv| {
                let iota = iota_for_closure.clone();
                tokio::spawn(async move {
                    iota.send_message(&response_cv).await;
                });
                true
            }),
        );
        get_omega_connection()
            .send_message(&cv.with_sender(*self.iota_id.read().await))
            .await;
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
        self.send_message(&response).await;
    }

    /// Handle message forwarding to other Iotas
    async fn handle_forward_message(&self, cv: CommunicationValue) {
        let receiver_id = cv.get_receiver();
        let sender_id = cv.get_sender();

        if self.get_user_ids().await.contains(&sender_id) {
            if let Some(target_rho) = rho_manager::get_rho_con_for_user(receiver_id).await {
                target_rho.message_to_iota(cv).await;
            } else {
                let error = CommunicationValue::new(CommunicationType::error_no_iota)
                    .with_id(cv.get_id())
                    .with_sender(cv.get_sender());
                self.send_message(&error).await;
            }
        } else {
            self.send_message(
                &CommunicationValue::new(CommunicationType::error_invalid_user_id).add_data(
                    DataTypes::error_type,
                    JsonValue::String(
                        "You are sending to another User without authority.".to_string(),
                    ),
                ),
            )
            .await;
        }
    }

    /// Handle GET_CHATS message
    async fn handle_get_chats(&self, cv: CommunicationValue) {
        let receiver_id = cv.get_receiver();
        let mut interested_ids: Vec<i64> = Vec::new();

        let calls: Vec<Arc<CallGroup>> = call_manager::get_call_groups(receiver_id).await;
        let mut invites: HashMap<i64, Vec<JsonValue>> = HashMap::new();
        let empty = &calls.is_empty();
        for call in calls {
            for inviter in call.members.read().await.iter() {
                let inviter_id = inviter.user_id;
                if let Some(call_ids) = invites.get_mut(&inviter_id) {
                    call_ids.push(JsonValue::String(call.call_id.to_string()));
                } else {
                    invites.insert(
                        inviter_id,
                        vec![JsonValue::String(call.call_id.to_string())],
                    );
                }
            }
        }

        // Process contacts and add call information
        let enriched_contacts = if *empty {
            if let Some(contacts_data) = cv.get_data(DataTypes::user_ids) {
                log_in!(PrintType::Call, "Call empty");
                contacts_data.clone()
            } else {
                log_in!(PrintType::Call, "Call empty No Data");
                JsonValue::new_array()
            }
        } else {
            let mut enrc_contacts = JsonValue::new_array();
            if let Some(contacts_data) = cv.get_data(DataTypes::user_ids) {
                if let JsonValue::Array(user_ids) = contacts_data {
                    for user_json in user_ids {
                        let user_id = user_json["user_id"].as_i64().unwrap_or(0);
                        interested_ids.push(user_id);
                        let mut enriched_contact = JsonValue::new_object();
                        let _ = enriched_contact.insert("user_id", user_id);
                        if let Some(calls) = invites.get(&user_id) {
                            let _ =
                                enriched_contact.insert("calls", JsonValue::Array(calls.clone()));
                        }
                        let _ = enrc_contacts.push(enriched_contact);
                    }
                } else {
                    enrc_contacts = contacts_data.clone();
                }
            }
            enrc_contacts
        };

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
