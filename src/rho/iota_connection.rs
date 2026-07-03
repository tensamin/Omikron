use crate::calls::call_group::CallGroup;
use crate::calls::call_manager;
use crate::log_cv_in;
use crate::log_cv_out;
use crate::log_err;
use crate::log_in;
use crate::omega::omega_connection::get_omega_connection;
use crate::rho::connection::GeneralConnection;
use crate::util::logger::PrintType;
use dashmap::DashMap;
use mtp::codec::CommunicationType;
use mtp::codec::CommunicationValue;
use mtp::codec::DataType;
use mtp::codec::DataTypeId;
use mtp::codec::DataValue;
use mtp::codec::TypeMap;
use mtp::transport::Receiver;
use mtp::transport::Sender;
use std::collections::BTreeMap;
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::RwLock;
use tokio::sync::mpsc;
use mtp::crypto::KemPublicKey;

use super::{rho_connection::RhoConnection, rho_manager};
use crate::omega::omega_connection::OmegaConnection;

#[allow(dead_code)]
pub struct IotaConnection {
    pub iota_id: u64,
    pub client_version: String,
    pub sender: Arc<Sender>,
    pub receiver: Arc<Receiver>,
    pub user_ids: Arc<RwLock<Vec<u64>>>,
    pub ping: Arc<RwLock<i64>>,
    pub_key: Arc<RwLock<Option<Vec<u8>>>>,
    pub waiting_tasks:
        DashMap<u32, Box<dyn Fn(Arc<IotaConnection>, CommunicationValue) -> bool + Send + Sync>>,
    pub rho_connection: Arc<RwLock<Option<Arc<RhoConnection>>>>,
}

impl IotaConnection {
    pub async fn from_general(general: Arc<GeneralConnection>, iota_id: u64) -> Arc<Self> {
        Arc::new(Self {
            ping: Arc::new(RwLock::new(0)),
            pub_key: Arc::new(RwLock::new(None)),
            rho_connection: general.rho_connection.clone(),
            user_ids: Arc::new(RwLock::new(Vec::new())),
            sender: general.sender.clone(),
            receiver: general.receiver.clone(),
            iota_id: iota_id,
            client_version: general.client_version.read().await.clone(),
            waiting_tasks: DashMap::new(),
        })
    }
    pub fn start(self: Arc<Self>) {
        let self_clone = self.clone();
        tokio::spawn(async move {
            loop {
                match self_clone.receiver.receive().await {
                    Ok(cv) => {
                        let iota_for_closure = self_clone.clone();
                        tokio::spawn(async move {
                            iota_for_closure.handle_message(cv).await;
                        });
                    }
                    Err(_) => {
                        break;
                    }
                }
            }
            self_clone.handle_close().await;
        });
    }

    /// Get the Iota ID
    pub async fn get_iota_id(&self) -> u64 {
        self.iota_id
    }

    #[allow(dead_code)]
    pub async fn get_public_key(&self) -> Option<KemPublicKey> {
        let guard = self.pub_key.read().await;
        guard.as_ref().map(|bytes| KemPublicKey::new(bytes.clone()))
    }

    /// Get the user IDs
    pub async fn get_user_ids(&self) -> Vec<u64> {
        self.user_ids.read().await.clone()
    }

    /// Replace all users linked to this iota and synchronize the attached rho mapping.
    pub async fn set_user_ids(&self, user_ids: Vec<u64>) {
        {
            let mut guard = self.user_ids.write().await;
            *guard = user_ids.clone();
        }

        if let Some(rho_conn) = self.get_rho_connection().await {
            let user_ids_i64: Vec<i64> = user_ids.into_iter().map(|u| u as i64).collect();
            rho_conn.set_user_ids(user_ids_i64).await;
        }
    }

    pub async fn add_user_id(&self, user_id: u64) {
        let mut should_sync = false;
        {
            let mut guard = self.user_ids.write().await;
            if !guard.contains(&user_id) {
                guard.push(user_id);
                should_sync = true;
            }
        }

        if should_sync {
            if let Some(rho_conn) = self.get_rho_connection().await {
                rho_conn.add_user_id(user_id as i64).await;
            }
        }
    }

    /// Get current ping
    pub async fn get_ping(&self) -> i64 {
        *self.ping.read().await
    }

    /// Set the RhoConnection reference
    pub async fn set_rho_connection(&self, rho_connection: Arc<RhoConnection>) {
        let mut rho_ref = self.rho_connection.write().await;
        *rho_ref = Some(rho_connection);
    }

    /// Get RhoConnection if available
    pub async fn get_rho_connection(&self) -> Option<Arc<RhoConnection>> {
        let rho_ref = self.rho_connection.read().await;
        if let Some(weak_ref) = rho_ref.as_ref() {
            Some(weak_ref.clone())
        } else {
            None
        }
    }

    /// Send a CommunicationValue to the Iota
    pub async fn send_message(&self, cv: &CommunicationValue) {
        if !cv.is_type(CommunicationType::Pong) {
            log_cv_out!(PrintType::Iota, cv);
        }
        if let Err(e) = self.sender.send(&cv).await {
            log_err!(
                self.iota_id as i64,
                PrintType::Iota,
                "Failed to send message: {:?}",
                e
            );
        }
    }

    /// Handle incoming message from Iota
    pub async fn handle_message(self: Arc<Self>, cv: CommunicationValue) {
        let msg_id = cv.get_id();
        if let Some((_, task)) = self.waiting_tasks.remove(&msg_id) {
            if (task)(self.clone(), cv.clone()) {
                return;
            }
        }

        // Handle ping
        if cv.is_type(CommunicationType::Ping) || cv.is_type(CommunicationType::Pong) {
            self.handle_ping(cv).await;
            return;
        }

        log_cv_in!(PrintType::Iota, cv);

        // Handle GET_CHATS
        if cv.is_type(CommunicationType::GetChats) {
            self.handle_get_chats(cv).await;
            return;
        }

        // Handle forwarding to other Iotas or clients
        let receiver_id = cv.get_receiver();
        if (receiver_id != 0 && !self.get_user_ids().await.contains(&(receiver_id as u64)))
            || cv.is_type(CommunicationType::MessageOtherIota)
            || cv.is_type(CommunicationType::SendChat)
        {
            self.handle_forward_message(cv).await;
            return;
        }

        if cv.is_type(CommunicationType::CompleteRegisterUser) {
            let response_cv = get_omega_connection()
                .await_response(
                    &cv.clone().with_sender(self.iota_id),
                    Some(Duration::from_secs(20)),
                )
                .await;
            if let Ok(response_cv) = response_cv {
                if response_cv.is_type(CommunicationType::Success) {
                    if let Some(user_id) = cv.get_data(DataType::UserId).as_number() {
                        self.add_user_id(user_id as u64).await;
                    }
                }
                self.send_message(&response_cv).await;
            }
            return;
        }

        if cv.is_type(CommunicationType::ChangeIotaData)
            || cv.is_type(CommunicationType::PushNotification)
            || cv.is_type(CommunicationType::GetUserData)
            || cv.is_type(CommunicationType::GetIotaData)
            || cv.is_type(CommunicationType::GetRegister)
            || cv.is_type(CommunicationType::DeleteIota)
        {
            let sender = self.get_iota_id().await;

            self.handle_omega_forward(cv.with_sender(sender as u64))
                .await;
            return;
        }
        self.forward_to_client(cv).await;
    }

    #[allow(dead_code)]
    async fn send_error_response(&self, message_id: u32, error_type: CommunicationType) {
        let error = CommunicationValue::new(error_type).with_id(message_id);
        self.send_message(&error).await;
    }

    #[allow(dead_code)]
    async fn close(&self) {
        let _ = self.sender.close();
    }

    async fn handle_omega_forward(self: Arc<Self>, cv: CommunicationValue) {
        let iota_for_closure = self.clone();
        let response_cv = get_omega_connection()
            .await_response(&cv.with_sender(self.iota_id), Some(Duration::from_secs(20)))
            .await;
        if let Ok(response_cv) = response_cv {
            iota_for_closure.send_message(&response_cv).await;
        }
    }
    /// Handle ping message
    async fn handle_ping(&self, cv: CommunicationValue) {
        if let DataValue::SignedNumber(last_ping) = cv.get_data(DataType::LastPing) {
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

        let tm = TypeMap::latest();
        let pings: Vec<DataValue> = client_pings
            .into_iter()
            .map(|(k, v)| {
                let mut map = BTreeMap::new();
                if let Ok(uid) = k.parse::<i128>() {
                    map.insert(DataType::UserId.to_id(&tm), DataValue::SignedNumber(uid));
                }
                map.insert(DataType::LastPing.to_id(&tm), DataValue::SignedNumber(v.into()));
                DataValue::container_from_map(&map)
            })
            .collect();
        let response = CommunicationValue::new(CommunicationType::Pong)
            .with_id(cv.get_id())
            .add_typed_default(DataType::PingClients, DataValue::Array(pings));

        self.send_message(&response).await;
    }

    /// Handle message forwarding to other Iotas
    async fn handle_forward_message(&self, cv: CommunicationValue) {
        let receiver_id = cv.get_receiver();
        let sender_id = cv.get_sender();
        let my_user_ids = self.get_user_ids().await;

        log_in!(
            self.iota_id as i64,
            PrintType::Iota,
            "Authority check: sender_id={} receiver_id={} iota_user_ids={:?} msg_type={:?} msg_id={}",
            sender_id,
            receiver_id,
            my_user_ids,
            cv.get_type(),
            cv.get_id()
        );

        if my_user_ids.contains(&(sender_id as u64)) {
            if let Some(target_rho) = rho_manager::get_rho_con_for_user(receiver_id as i64).await {
                target_rho.message_to_iota(cv).await;
            } else {
                let error = CommunicationValue::new(CommunicationType::ErrorNoIota)
                    .with_id(cv.get_id())
                    .with_sender(cv.get_sender());
                self.send_message(&error).await;
            }
        } else {
            log_err!(
                self.iota_id as i64,
                PrintType::Iota,
                "Rejected client->iota forward: sender_id={} is not authorized for this iota. Known users={:?}",
                sender_id,
                my_user_ids
            );

            self.send_message(
                &CommunicationValue::new(CommunicationType::ErrorInvalidUserId).add_typed_default(
                    DataType::ErrorType,
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
        let user_id = cv.get_sender();

        // Authority check: user must be linked to this Iota
        if !self.get_user_ids().await.contains(&user_id) {
            log_err!(
                self.iota_id as i64,
                PrintType::Iota,
                "Rejected get_chats: sender_id={} is not authorized for this iota.",
                user_id
            );
            return;
        }

        let mut interested_ids: Vec<i64> = Vec::new();
        let tm = TypeMap::latest();

        // ============================
        // Load Calls
        // ============================
        let calls: Vec<Arc<CallGroup>> = call_manager::get_call_groups(user_id).await;

        let mut invites: HashMap<i64, Vec<DataValue>> = HashMap::new();
        let mut global_calls: Vec<DataValue> = Vec::new();
        let empty = calls.is_empty();

        for call in calls {
            let members = call.members.read().await;

            // Find ourselves in the call to get our specific status
            let call_self = members.iter().find(|m| m.user_id == user_id).cloned();

            if let Some(call_self) = call_self {
                let timeout = *call_self.timeout.read().await;
                let admin = call_self.has_admin();

                // List of all members in the call
                let member_ids: Vec<DataValue> = members
                    .iter()
                    .map(|m| DataValue::SignedNumber(m.user_id.into()))
                    .collect();

                // Build base call container
                let mut base_call_map: BTreeMap<DataTypeId, DataValue> = BTreeMap::new();
                base_call_map.insert(DataType::CallId.to_id(&tm), DataValue::Str(call.call_id.to_string()));
                base_call_map.insert(DataType::CallMembers.to_id(&tm), DataValue::Array(member_ids));

                if timeout > 0 {
                    base_call_map
                        .insert(DataType::Timeout.to_id(&tm), DataValue::SignedNumber(timeout.into()));
                }

                if admin {
                    base_call_map.insert(DataType::HasAdmin.to_id(&tm), DataValue::Bool(true));
                }

                // Add to global calls (without contact-specific secret)
                global_calls.push(DataValue::container_from_map(&base_call_map));

                // Attach this call to EVERY member of the call (other than ourselves)
                for member in members.iter() {
                    let member_id = member.user_id;
                    if member_id == user_id {
                        continue;
                    }

                    let mut contact_call_map = base_call_map.clone();

                    // Add secret if it exists for this pairing
                    if let Some(secret) = call.secrets.read().await.get(&(member_id, user_id)) {
                        contact_call_map
                            .insert(DataType::CallSecret.to_id(&tm), DataValue::Str(secret.clone()));
                    }

                    invites
                        .entry(member_id as i64)
                        .or_insert_with(Vec::new)
                        .push(DataValue::container_from_map(&contact_call_map));
                }
            }
        }

        // ============================
        // Enrich Contacts
        // ============================
        let enriched_contacts = if empty {
            match cv.get_data(DataType::UserIds) {
                DataValue::Array(arr) => DataValue::Array(arr.clone()),
                _ => DataValue::Array(vec![]),
            }
        } else {
            let mut enriched: Vec<DataValue> = Vec::new();

            if let DataValue::Array(users) = cv.get_data(DataType::UserIds) {
                for user_val in users {
                    if let DataValue::Container(entries) = user_val {
                        let mut user_map: BTreeMap<DataTypeId, DataValue> =
                            entries.iter().cloned().collect();

                        if let Some(DataValue::SignedNumber(id)) = user_map.get(&DataType::UserId.to_id(&tm)) {
                            interested_ids.push(*id as i64);

                            if let Some(call_list) = invites.get(&(*id as i64))
                                && !call_list.is_empty()
                            {
                                user_map
                                    .insert(DataType::Calls.to_id(&tm), DataValue::Array(call_list.clone()));
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
        OmegaConnection::user_states(user_id as i64, interested_ids.clone()).await;

        // ============================
        // Notify Rho
        // ============================
        if let Some(rho_conn) = self.get_rho_connection().await {
            rho_conn
                .set_interested(user_id as i64, interested_ids)
                .await;
        }

        // ============================
        // Forward to client
        // ============================
        self.forward_to_client(
            cv.add_typed_default(DataType::UserIds, enriched_contacts)
                .add_typed_default(DataType::Calls, DataValue::Array(global_calls)),
        )
        .await;
    }

    /// Forward message to client
    async fn forward_to_client(&self, cv: CommunicationValue) {
        if let Some(rho_conn) = self.get_rho_connection().await {
            let updated_cv = cv.with_sender(self.get_iota_id().await);
            rho_conn.message_to_client(updated_cv).await;
        } else {
        }
    }

    pub async fn handle_close(&self) {
        if let Some(rho_conn) = self.get_rho_connection().await {
            rho_conn.close_iota_connection().await;
        }
    }

    #[allow(dead_code)]
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
            Box::new(move |_, response_cv| {
                let inner_tx = task_tx.clone();
                tokio::spawn(async move {
                    let _ = inner_tx.send(response_cv).await;
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
