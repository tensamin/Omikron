use crate::calls::call_group::CallGroup;
use crate::calls::call_manager;
use crate::log_cv_in;
use crate::log_cv_out;
use crate::log_err;
use crate::omega::omega_connection::get_omega_connection;
use crate::rho::connection::GeneralConnection;
use crate::util::logger::PrintType;
use dashmap::DashMap;
use epsilon_core::CommunicationType;
use epsilon_core::CommunicationValue;
use epsilon_core::DataTypes;
use epsilon_core::DataValue;
use epsilon_native::Receiver;
use epsilon_native::Sender;
use std::{
    collections::HashMap,
    sync::{Arc, Weak},
    time::Duration,
};
use tokio::sync::RwLock;
use tokio::sync::mpsc;
use x448::PublicKey;

use super::{rho_connection::RhoConnection, rho_manager};
use crate::omega::omega_connection::OmegaConnection;

pub struct IotaConnection {
    pub iota_id: u64,
    pub sender: Arc<Sender>,
    pub receiver: Arc<Receiver>,
    pub user_ids: Arc<RwLock<Vec<u64>>>,
    pub ping: Arc<RwLock<i64>>,
    pub_key: Arc<RwLock<Option<Vec<u8>>>>,
    pub waiting_tasks:
        DashMap<u32, Box<dyn Fn(Arc<IotaConnection>, CommunicationValue) -> bool + Send + Sync>>,
    pub rho_connection: Arc<RwLock<Option<Weak<RhoConnection>>>>,
}

impl IotaConnection {
    pub async fn from_general(general: Arc<GeneralConnection>, iota_id: u64) -> Arc<Self> {
        Arc::new(Self {
            ping: Arc::new(RwLock::new(0)),
            pub_key: Arc::new(RwLock::new(None)),
            rho_connection: Arc::new(RwLock::new(None)),
            user_ids: Arc::new(RwLock::new(Vec::new())),
            sender: general.sender.clone(),
            receiver: general.receiver.clone(),
            iota_id: iota_id,
            waiting_tasks: DashMap::new(),
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

    /// Get the Iota ID
    pub async fn get_iota_id(&self) -> u64 {
        self.iota_id
    }

    pub async fn get_public_key(&self) -> Option<PublicKey> {
        if let Some(public_key) = self.pub_key.read().await.clone() {
            PublicKey::from_bytes(&public_key)
        } else {
            None
        }
    }

    /// Get the user IDs
    pub async fn get_user_ids(&self) -> Vec<u64> {
        self.user_ids.read().await.clone()
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

    /// Send a CommunicationValue to the Iota
    pub async fn send_message(&self, cv: &CommunicationValue) {
        if !cv.is_type(CommunicationType::pong) {
            log_cv_out!(PrintType::Iota, cv);
        }
        self.sender.send(&cv).await;
    }

    /// Handle incoming message from Iota
    pub async fn handle_message(self: Arc<Self>, cv: CommunicationValue) {
        // Handle ping
        if cv.is_type(CommunicationType::ping) || cv.is_type(CommunicationType::pong) {
            self.handle_ping(cv).await;
            return;
        }

        log_cv_in!(PrintType::Iota, cv);

        // Handle GET_CHATS
        if cv.is_type(CommunicationType::get_chats) {
            self.handle_get_chats(cv).await;
            return;
        }

        // Handle forwarding to other Iotas or clients
        let receiver_id = cv.get_receiver();
        if (receiver_id != 0 && !self.get_user_ids().await.contains(&(receiver_id as u64)))
            || cv.is_type(CommunicationType::message_other_iota)
            || cv.is_type(CommunicationType::send_chat)
        {
            self.handle_forward_message(cv).await;
            return;
        }

        if cv.is_type(CommunicationType::change_iota_data)
            || cv.is_type(CommunicationType::push_notification)
            || cv.is_type(CommunicationType::get_user_data)
            || cv.is_type(CommunicationType::get_iota_data)
            || cv.is_type(CommunicationType::get_register)
            || cv.is_type(CommunicationType::complete_register_user)
            || cv.is_type(CommunicationType::delete_iota)
        {
            let sender = self.get_iota_id().await;
            self.handle_omega_forward(cv.with_sender(sender as u64))
                .await;
            return;
        }
        // Forward to client
        self.forward_to_client(cv).await;
    }

    async fn send_error_response(&self, message_id: u32, error_type: CommunicationType) {
        let error = CommunicationValue::new(error_type).with_id(message_id);
        self.send_message(&error).await;
    }

    async fn close(&self) {
        let _ = self.sender.close();
    }

    async fn handle_omega_forward(self: Arc<Self>, cv: CommunicationValue) {
        let iota_for_closure = self.clone();
        tokio::spawn(async move {
            let response_cv = get_omega_connection()
                .await_response(&cv.with_sender(self.iota_id), Some(Duration::from_secs(20)))
                .await;
            if let Ok(response_cv) = response_cv {
                iota_for_closure.send_message(&response_cv).await;
            }
        });
    }
    /// Handle ping message
    async fn handle_ping(&self, cv: CommunicationValue) {
        if let DataValue::Number(last_ping) = cv.get_data(DataTypes::last_ping) {
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

        let pings: Vec<(DataTypes, DataValue)> = client_pings
            .into_iter()
            .map(|(k, v)| (DataTypes::parse(k), DataValue::Number(v)))
            .collect();
        let response = CommunicationValue::new(CommunicationType::pong)
            .with_id(cv.get_id())
            .add_data(DataTypes::ping_clients, DataValue::Container(pings));
        self.send_message(&response).await;
    }

    /// Handle message forwarding to other Iotas
    async fn handle_forward_message(&self, cv: CommunicationValue) {
        let receiver_id = cv.get_receiver();
        let sender_id = cv.get_sender();

        if self.get_user_ids().await.contains(&(sender_id as u64)) {
            if let Some(target_rho) = rho_manager::get_rho_con_for_user(receiver_id as i64).await {
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
                    DataValue::Str(
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

        // ============================
        // Load Calls
        // ============================
        let calls: Vec<Arc<CallGroup>> = call_manager::get_call_groups(receiver_id).await;

        let mut invites: HashMap<i64, Vec<DataValue>> = HashMap::new();
        let empty = calls.is_empty();

        for call in calls {
            for inviter in call.members.read().await.iter() {
                let call_self = call.get_caller(receiver_id).await.unwrap();

                let inviter_id = inviter.user_id;
                let timeout = *call_self.timeout.read().await;
                let admin = call_self.has_admin();

                // Build call container
                let mut call_map: HashMap<DataTypes, DataValue> = HashMap::new();

                call_map.insert(DataTypes::call_id, DataValue::Str(call.call_id.to_string()));

                if timeout > 0 {
                    call_map.insert(DataTypes::timeout, DataValue::Number(timeout as i64));
                }

                if admin {
                    call_map.insert(DataTypes::has_admin, DataValue::Bool(true));
                }

                let call_container = DataValue::container_from_map(&call_map);

                invites
                    .entry(inviter_id as i64)
                    .or_insert_with(Vec::new)
                    .push(call_container);
            }
        }

        // ============================
        // Enrich Contacts
        // ============================
        let enriched_contacts = if empty {
            match cv.get_data(DataTypes::user_ids) {
                DataValue::Array(arr) => DataValue::Array(arr.clone()),
                _ => DataValue::Array(vec![]),
            }
        } else {
            let mut enriched: Vec<DataValue> = Vec::new();

            if let DataValue::Array(users) = cv.get_data(DataTypes::user_ids) {
                for user_val in users {
                    if let DataValue::Container(entries) = user_val {
                        let mut user_map: HashMap<DataTypes, DataValue> =
                            entries.iter().cloned().collect();

                        // extract user_id
                        if let Some(DataValue::Number(user_id)) = user_map.get(&DataTypes::user_id)
                        {
                            interested_ids.push(*user_id);

                            // attach calls if exists
                            if let Some(call_list) = invites.get(user_id) {
                                user_map
                                    .insert(DataTypes::calls, DataValue::Array(call_list.clone()));
                            }
                        }

                        enriched.push(DataValue::container_from_map(&user_map));
                    }
                }
            }

            DataValue::Array(enriched)
        };

        // ============================
        // Notify Omega
        // ============================
        OmegaConnection::user_states(receiver_id as i64, interested_ids.clone()).await;

        // ============================
        // Notify Rho
        // ============================
        if let Some(rho_conn) = self.get_rho_connection().await {
            rho_conn
                .set_interested(receiver_id as i64, interested_ids)
                .await;
        }

        // ============================
        // Forward to client
        // ============================
        self.forward_to_client(cv.add_data(DataTypes::user_ids, enriched_contacts))
            .await;
    }

    /// Forward message to client
    async fn forward_to_client(&self, cv: CommunicationValue) {
        if let Some(rho_conn) = self.get_rho_connection().await {
            let updated_cv = cv.with_sender(self.get_iota_id().await);
            rho_conn.message_to_client(updated_cv).await;
        } else {
            log_err!(
                self.get_iota_id().await as i64,
                PrintType::General,
                "Failed to forward message to client"
            );
        }
    }

    pub async fn handle_close(&self) {
        if let Some(rho_conn) = self.get_rho_connection().await {
            rho_conn.close_iota_connection().await;
        }
    }

    pub async fn await_response(
        self: Arc<IotaConnection>,
        cv: &CommunicationValue,
        timeout_duration: Option<Duration>,
    ) -> Result<CommunicationValue, String> {
        let (tx, mut rx) = mpsc::channel(1);
        let msg_id = cv.get_id();

        let task_tx = tx.clone();
        self.waiting_tasks.insert(
            msg_id,
            Box::new(move |io, response_cv| {
                let inner_tx = task_tx.clone();
                tokio::spawn(async move {
                    if let Err(e) = inner_tx.send(response_cv).await {
                        log_err!(
                            io.get_iota_id().await as i64,
                            PrintType::Iota,
                            "Failed to send response back to awaiter: {}",
                            e
                        );
                    }
                });
                true
            }),
        );

        self.send_message(cv).await;

        let timeout = timeout_duration.unwrap_or(Duration::from_secs(10));

        match tokio::time::timeout(timeout, rx.recv()).await {
            Ok(Some(response_cv)) => Ok(response_cv),
            Ok(_) => Err("Failed to receive response, channel was closed.".to_string()),
            Err(_) => {
                self.waiting_tasks.remove(&msg_id);
                Err(format!(
                    "Request timed out after {} seconds.",
                    timeout.as_secs()
                ))
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
