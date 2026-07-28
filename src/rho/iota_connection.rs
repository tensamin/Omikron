use crate::app_state::AppState;
use crate::calls::call_group::CallGroup;
use crate::log_cv_in;
use crate::log_cv_out;
use crate::log_err;
use crate::log_in;
use crate::log_out;
use crate::rho::connection::{GeneralConnection, MtpReceiver, MtpSender};
use crate::util::data_type_id;
use crate::util::logger::PrintType;
use dashmap::DashMap;
use mtp::codec::CommunicationType;
use mtp::codec::CommunicationValue;
use mtp::codec::DataType;
use mtp::codec::DataTypeId;
use mtp::codec::DataValue;
use mtp::codec::TypeMap;
use mtp::crypto::KemPublicKey;
use std::collections::BTreeMap;
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::RwLock;
use tokio::sync::mpsc;

use super::rho_connection::RhoConnection;

#[allow(dead_code)]
pub struct IotaConnection {
    pub state: Arc<AppState>,
    pub iota_id: u64,
    pub client_version: String,
    pub sender: Arc<MtpSender>,
    pub receiver: Arc<MtpReceiver>,
    pub user_ids: Arc<RwLock<Vec<u64>>>,
    pub_key: Arc<RwLock<Option<Vec<u8>>>>,
    pub waiting_tasks:
        DashMap<u32, Box<dyn Fn(Arc<IotaConnection>, CommunicationValue) -> bool + Send + Sync>>,
    pub rho_connection: Arc<RwLock<Option<Arc<RhoConnection>>>>,
    pending_chat_secrets: DashMap<u64, Vec<CommunicationValue>>,
    message_slots: Arc<tokio::sync::Semaphore>,
}

impl IotaConnection {
    pub async fn from_general(general: Arc<GeneralConnection>, iota_id: u64) -> Arc<Self> {
        Arc::new(Self {
            state: general.state.clone(),
            pub_key: Arc::new(RwLock::new(None)),
            rho_connection: general.rho_connection.clone(),
            user_ids: Arc::new(RwLock::new(Vec::new())),
            sender: general.sender.clone(),
            receiver: general.receiver.clone(),
            iota_id: iota_id,
            client_version: general.client_version.read().await.clone(),
            waiting_tasks: DashMap::new(),
            pending_chat_secrets: DashMap::new(),
            message_slots: Arc::new(tokio::sync::Semaphore::new(32)),
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

        for user_id in self.get_user_ids().await {
            self.flush_pending_chat_secrets(user_id).await;
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

            self.flush_pending_chat_secrets(user_id).await;
        }
    }

    async fn flush_pending_chat_secrets(&self, user_id: u64) {
        let Some((_, messages)) = self.pending_chat_secrets.remove(&user_id) else {
            return;
        };

        for message in messages {
            self.send_message(&message).await;
        }
    }

    fn store_pending_chat_secret(&self, cv: CommunicationValue) {
        let receiver_id = cv.get_receiver();
        if receiver_id == 0 || !cv.is_type(CommunicationType::SetChatSecret) {
            return;
        }

        self.pending_chat_secrets
            .entry(receiver_id)
            .or_default()
            .push(cv);
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
        log_cv_out!(PrintType::Iota, cv);
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
        let Ok(permit) = self.message_slots.clone().acquire_owned().await else {
            return;
        };
        let _permit = permit;
        let msg_id = cv.get_id();
        if let Some((_, task)) = self.waiting_tasks.remove(&msg_id) {
            if (task)(self.clone(), cv.clone()) {
                return;
            }
        }

        log_cv_in!(PrintType::Iota, cv);

        let cv = if cv.is_type(CommunicationType::ClientStateSync) {
            self.add_call_state(cv).await
        } else {
            cv
        };

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
            // Registration carries the authenticated Iota ID separately so
            // Omega can bind the allocation lease to this connection rather
            // than trusting a client-supplied value.
            let request = cv.clone().add_typed_default(
                DataType::IotaId,
                DataValue::SignedNumber(self.iota_id.into()),
            );
            log_in!(
                self.iota_id as i64,
                PrintType::Omega,
                "Forwarding CompleteRegisterUser to Omega (request_id={})",
                request.get_id()
            );
            let mut response_cv = self
                .state
                .omega
                .clone()
                .await_response(&request, Some(Duration::from_secs(8)))
                .await;
            if let Err(error) = &response_cv {
                log_err!(
                    self.iota_id as i64,
                    PrintType::Omega,
                    "CompleteRegisterUser request_id={} failed: {}; retrying once",
                    request.get_id(),
                    error
                );
                response_cv = self
                    .state
                    .omega
                    .clone()
                    .await_response(&request, Some(Duration::from_secs(8)))
                    .await;
            }
            match response_cv {
                Ok(response_cv) => {
                    log_in!(
                        self.iota_id as i64,
                        PrintType::Omega,
                        "Omega completed registration (request_id={}, response_id={}, type={})",
                        request.get_id(),
                        response_cv.get_id(),
                        response_cv
                            .get_comm_type_enum()
                            .map(|kind| kind.to_string())
                            .unwrap_or_else(|| response_cv.get_type().to_string())
                    );
                    if response_cv.is_type(CommunicationType::Success) {
                        if let Some(user_id) = cv.get_data(DataType::UserId).as_number() {
                            self.add_user_id(user_id as u64).await;
                        }
                    }
                    self.send_message(&response_cv).await;
                }
                Err(error) => {
                    // Omega may have committed the insert even when its
                    // Success response was lost in transit. Verify the exact
                    // generated user ID before reporting failure; GetUserData
                    // uses the proven request/response path and keeps this
                    // recovery idempotent.
                    let user_id = cv.get_data(DataType::UserId).as_number();
                    if let Some(user_id) = user_id {
                        let verification = CommunicationValue::new(CommunicationType::GetUserData)
                            .add_typed_default(DataType::UserId, DataValue::SignedNumber(user_id));
                        match self
                            .state
                            .omega
                            .clone()
                            .await_response(&verification, Some(Duration::from_secs(3)))
                            .await
                        {
                            Ok(verified)
                                if verified.get_data(DataType::UserId).as_number()
                                    == Some(user_id) =>
                            {
                                log_in!(
                                    self.iota_id as i64,
                                    PrintType::Omega,
                                    "Registration response was lost; verified user {} remotely",
                                    user_id
                                );
                                self.add_user_id(user_id as u64).await;
                                self.send_message(
                                    &CommunicationValue::new(CommunicationType::Success)
                                        .with_id(cv.get_id()),
                                )
                                .await;
                                return;
                            }
                            Ok(verified) => log_err!(
                                self.iota_id as i64,
                                PrintType::Omega,
                                "Registration verification returned an unexpected user (request_id={}, response_id={})",
                                verification.get_id(),
                                verified.get_id()
                            ),
                            Err(verify_error) => log_err!(
                                self.iota_id as i64,
                                PrintType::Omega,
                                "Registration verification failed after request_id={}: {}",
                                verification.get_id(),
                                verify_error
                            ),
                        }
                    }
                    log_err!(
                        self.iota_id as i64,
                        PrintType::Omega,
                        "CompleteRegisterUser forwarding failed: {}",
                        error
                    );
                    self.send_error_response(
                        cv.get_id(),
                        CommunicationType::ErrorInternal,
                        Some(&format!("Omega forwarding failed: {error}")),
                    )
                    .await;
                }
            }
            return;
        }

        if cv.is_type(CommunicationType::ChangeIotaData)
            || cv.is_type(CommunicationType::PushNotification)
            || cv.is_type(CommunicationType::GetUserData)
            || cv.is_type(CommunicationType::GetIotaData)
            || cv.is_type(CommunicationType::DeleteIota)
        {
            let sender = self.get_iota_id().await;

            self.handle_omega_forward(cv.with_sender(sender as u64))
                .await;
            return;
        }

        // Register allocation is scoped to this authenticated Iota.  Keep the
        // source ID in typed data so Omega can create a durable lease.
        if cv.is_type(CommunicationType::GetRegister) {
            self.handle_omega_forward_without_sender(cv).await;
            return;
        }
        self.forward_to_client(cv).await;
    }

    #[allow(dead_code)]
    async fn send_error_response(
        &self,
        message_id: u32,
        error_type: CommunicationType,
        detail: Option<&str>,
    ) {
        let mut error = CommunicationValue::new(error_type).with_id(message_id);
        if let Some(detail) = detail {
            error = error.add_typed_default(DataType::ErrorType, DataValue::Str(detail.into()));
        }
        self.send_message(&error).await;
    }

    #[allow(dead_code)]
    async fn close(&self) {
        let _ = self.sender.close();
    }

    async fn handle_omega_forward(self: Arc<Self>, cv: CommunicationValue) {
        let iota_for_closure = self.clone();
        let response_cv = self
            .state
            .omega
            .clone()
            .await_response(&cv.with_sender(self.iota_id), Some(Duration::from_secs(20)))
            .await;
        if let Ok(response_cv) = response_cv {
            iota_for_closure.send_message(&response_cv).await;
        }
    }

    async fn handle_omega_forward_without_sender(self: Arc<Self>, cv: CommunicationValue) {
        let iota_for_closure = self.clone();
        let request = cv.clone().add_typed_default(
            DataType::IotaId,
            DataValue::SignedNumber(self.iota_id.into()),
        );
        let mut response_cv = self
            .state
            .omega
            .clone()
            .await_response(&request, Some(Duration::from_secs(8)))
            .await;
        if let Err(error) = &response_cv {
            log_err!(
                self.iota_id as i64,
                PrintType::Omega,
                "GetRegister request_id={} failed: {}; retrying once",
                request.get_id(),
                error
            );
            response_cv = self
                .state
                .omega
                .clone()
                .await_response(&request, Some(Duration::from_secs(8)))
                .await;
        }
        match response_cv {
            Ok(response_cv) => iota_for_closure.send_message(&response_cv).await,
            Err(error) => {
                log_err!(
                    self.iota_id as i64,
                    PrintType::Omega,
                    "GetRegister forwarding failed: {}",
                    error
                );
                self.send_error_response(
                    cv.get_id(),
                    CommunicationType::ErrorInternal,
                    Some(&format!("Omega forwarding failed: {error}")),
                )
                .await;
            }
        }
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
            if let Some(target_rho) = self.state.rho.get_for_user(receiver_id as i64).await {
                target_rho.message_to_iota(cv).await;
            } else {
                if cv.is_type(CommunicationType::SetChatSecret) {
                    self.store_pending_chat_secret(cv.clone());
                    let success = CommunicationValue::new(CommunicationType::Success)
                        .with_id(cv.get_id())
                        .with_sender(cv.get_sender())
                        .with_receiver(cv.get_sender());
                    self.send_message(&success).await;
                    return;
                }

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
        let session_id = cv.get_data(DataType::SessionId).as_signed_number();
        let tm = TypeMap::latest();

        // Presence interest is the complete contact set, independent of
        // whether this account currently participates in a call.
        if let DataValue::Array(users) = cv.get_data(DataType::UserIds) {
            for user in users {
                match user {
                    DataValue::SignedNumber(id) => interested_ids.push(*id as i64),
                    DataValue::Container(entries) => {
                        if let Some(DataValue::SignedNumber(id)) =
                            entries.iter().find_map(|(key, value)| {
                                (*key == data_type_id(DataType::UserId, &tm)).then_some(value)
                            })
                        {
                            interested_ids.push(*id as i64);
                        }
                    }
                    _ => {}
                }
            }
            interested_ids.sort_unstable();
            interested_ids.dedup();
        }

        // ============================
        // Load Calls
        // ============================
        let calls: Vec<Arc<CallGroup>> = self.state.call_manager.get_call_groups(user_id).await;

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
                base_call_map.insert(
                    data_type_id(DataType::CallId, &tm),
                    DataValue::Str(call.call_id.to_string()),
                );
                base_call_map.insert(
                    data_type_id(DataType::CallMembers, &tm),
                    DataValue::Array(member_ids),
                );

                if timeout > 0 {
                    base_call_map.insert(
                        data_type_id(DataType::Timeout, &tm),
                        DataValue::SignedNumber(timeout.into()),
                    );
                }

                if admin {
                    base_call_map
                        .insert(data_type_id(DataType::HasAdmin, &tm), DataValue::Bool(true));
                }

                if let Some(secret) = call.get_secret_for_user(user_id).await {
                    base_call_map.insert(
                        data_type_id(DataType::CallSecret, &tm),
                        secret.to_data_value(),
                    );
                }

                // Add to global calls with only this user's recipient-specific secret.
                global_calls.push(DataValue::container_from_map(&base_call_map));

                // Attach this call to EVERY member of the call (other than ourselves)
                for member in members.iter() {
                    let member_id = member.user_id;
                    if member_id == user_id {
                        continue;
                    }

                    let contact_call_map = base_call_map.clone();

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

                        if let Some(DataValue::SignedNumber(id)) =
                            user_map.get(&data_type_id(DataType::UserId, &tm))
                        {
                            if let Some(call_list) = invites.get(&(*id as i64))
                                && !call_list.is_empty()
                            {
                                user_map.insert(
                                    data_type_id(DataType::Calls, &tm),
                                    DataValue::Array(call_list.clone()),
                                );
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
        self.state
            .omega
            .user_states(user_id as i64, interested_ids.clone())
            .await;

        // ============================
        // Notify Rho
        // ============================
        if let Some(rho_conn) = self.get_rho_connection().await {
            if let Some(session_id) = session_id.and_then(|id| i64::try_from(id).ok()) {
                rho_conn
                    .set_interested(user_id as i64, session_id, interested_ids)
                    .await;
            }
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

    async fn add_call_state(&self, response: CommunicationValue) -> CommunicationValue {
        let mut output = response.clone();
        let user_id = response.get_receiver();

        for (key, value) in response.iter_typed_data() {
            if key == Some(DataType::Contacts) {
                if let Some(contacts) = value.as_array() {
                    let (contacts, global_calls) = self
                        .state
                        .call_state_aggregator
                        .augment_contacts(user_id, contacts.clone())
                        .await;
                    output =
                        output.add_typed_default(DataType::Contacts, DataValue::Array(contacts));
                    output =
                        output.add_typed_default(DataType::Calls, DataValue::Array(global_calls));
                    continue;
                }
            }
            if let Some(data_type) = key {
                output = output.add_typed_default(data_type, value.clone());
            }
        }
        output
    }

    pub async fn handle_close(&self) {
        log_out!(
            self.iota_id as i64,
            PrintType::Iota,
            "Iota {} disconnected",
            self.iota_id
        );
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
