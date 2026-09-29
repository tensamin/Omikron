use crate::app_state::AppState;
use crate::calls::call_group::CallGroup;
use crate::log_cv_in;
use crate::log_cv_out;
use crate::log_err;
use crate::log_in;
use crate::log_out;
use crate::rho::connection::{
    GeneralConnection, MtpReceiver, MtpSender, OptionalDataValueCompat, RequiredMtpFields,
};
use crate::rho::relay_router::{self, RelaySource};
use crate::util::data_type_id;
use crate::util::logger::PrintType;
use dashmap::{DashMap, mapref::entry::Entry};
use mtp::codec::CommunicationType;
use mtp::codec::CommunicationValue;
use mtp::codec::DataType;
use mtp::codec::DataTypeId;
use mtp::codec::DataValue;
use mtp::codec::TypeMap;
use mtp::crypto::KemPublicKey;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::RwLock;
use tokio::sync::mpsc;

use super::rho_connection::RhoConnection;

pub(crate) fn contact_snapshot(value: &CommunicationValue) -> Option<(i64, i64, Vec<i64>)> {
    if !value.is_type(CommunicationType::AccountStateSnapshot)
        && !value.is_type(CommunicationType::AddConversation)
    {
        return None;
    }

    let user_id = value
        .receiver()
        .and_then(|id| i64::try_from(id).ok())
        .filter(|id| *id > 0)?;
    let Some(DataValue::Array(values)) = value.get_data(DataType::UserIds) else {
        return None;
    };

    let user_id_type = data_type_id(DataType::UserId, &TypeMap::latest());
    let mut contact_ids = Vec::with_capacity(values.len());
    for value in values {
        let contact_id = match value {
            DataValue::SignedNumber(id) => i64::try_from(*id).ok(),
            DataValue::Container(entries) => entries.iter().find_map(|(key, value)| {
                (*key == user_id_type)
                    .then(|| value.as_signed_number())
                    .flatten()
                    .and_then(|id| i64::try_from(id).ok())
            }),
            _ => None,
        }
        .filter(|id| *id > 0)?;
        contact_ids.push(contact_id);
    }
    contact_ids.sort_unstable();
    contact_ids.dedup();

    Some((user_id, 0, contact_ids))
}

type ResponseTask = Box<dyn FnOnce(u32, CommunicationValue) -> bool + Send + Sync>;

#[cfg(test)]
fn reserve_response_id_with<F>(
    waiting_tasks: &DashMap<u32, ResponseTask>,
    mut candidate: F,
    task: ResponseTask,
) -> u32
where
    F: FnMut() -> u32,
{
    let mut task = Some(task);
    loop {
        let id = candidate();
        if id == 0 {
            continue;
        }
        match waiting_tasks.entry(id) {
            Entry::Occupied(_) => {}
            Entry::Vacant(entry) => {
                entry.insert(task.take().expect("task inserted once"));
                return id;
            }
        }
    }
}

fn registration_request(value: &CommunicationValue, iota_id: u64) -> CommunicationValue {
    value
        .clone()
        .add_typed_default(DataType::IotaId, DataValue::SignedNumber(iota_id.into()))
        .add_typed_default(
            DataType::RegisterId,
            DataValue::Str(uuid::Uuid::new_v4().to_string()),
        )
}

fn is_iota_omega_management_operation(value: &CommunicationValue) -> bool {
    matches!(
        value.get_comm_type_enum(),
        Some(
            CommunicationType::GetUserData
                | CommunicationType::GetIotaData
                | CommunicationType::DeleteIota
                | CommunicationType::AttachUserBegin
                | CommunicationType::AttachUserComplete
                | CommunicationType::ReleaseUserFromIota
                | CommunicationType::DeleteUserCredentialBegin
                | CommunicationType::DeleteUserCredentialComplete
                | CommunicationType::EraseHostedUserDataAck
                | CommunicationType::AcknowledgeIotaUserProvision
                | CommunicationType::CreateUserInvitation
                | CommunicationType::ListUserInvitations
                | CommunicationType::RevokeUserInvitation
        )
    )
}

#[allow(dead_code)]
pub struct IotaConnection {
    pub state: Arc<AppState>,
    _mtp_connection: Option<Arc<mtp::webserver::WebMTPConnection>>,
    pub iota_id: u64,
    pub client_version: String,
    pub sender: Arc<MtpSender>,
    pub receiver: Arc<MtpReceiver>,
    pub user_ids: Arc<RwLock<Vec<u64>>>,
    pub_key: Arc<RwLock<Option<Vec<u8>>>>,
    pub waiting_tasks: DashMap<u32, ResponseTask>,
    next_response_id: AtomicU32,
    pub rho_connection: Arc<RwLock<Option<Arc<RhoConnection>>>>,
    message_slots: Arc<tokio::sync::Semaphore>,
}

impl IotaConnection {
    pub async fn from_general(general: Arc<GeneralConnection>, iota_id: u64) -> Arc<Self> {
        Arc::new(Self {
            state: general.state.clone(),
            _mtp_connection: Some(general.mtp_connection.clone()),
            pub_key: Arc::new(RwLock::new(None)),
            rho_connection: general.rho_connection.clone(),
            user_ids: Arc::new(RwLock::new(Vec::new())),
            sender: general.sender.clone(),
            receiver: general.receiver.clone(),
            iota_id: iota_id,
            client_version: general.client_version.read().await.clone(),
            waiting_tasks: DashMap::new(),
            next_response_id: AtomicU32::new(rand::random::<u32>().max(1)),
            message_slots: Arc::new(tokio::sync::Semaphore::new(32)),
        })
    }
    pub fn start(self: Arc<Self>) {
        let self_clone = self.clone();
        tokio::spawn(async move {
            loop {
                match self_clone.receiver.receive().await {
                    Ok(cv) => {
                        let Ok(permit) = self_clone.message_slots.clone().acquire_owned().await
                        else {
                            break;
                        };
                        let connection = self_clone.clone();
                        tokio::spawn(async move {
                            let _permit = permit;
                            connection.handle_message_inner(cv).await;
                        });
                    }
                    Err(error) => {
                        log_err!(
                            self_clone.iota_id as i64,
                            PrintType::Iota,
                            "Iota receive loop ended: {}; transport close reason: {:?}",
                            error,
                            self_clone.receiver.close_reason()
                        );
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
        let Ok(user_id) = i64::try_from(user_id) else {
            return;
        };
        let manager_rho = self
            .state
            .rho
            .bind_user_to_iota(user_id, self.iota_id as i64)
            .await;
        {
            let mut guard = self.user_ids.write().await;
            if !guard.contains(&(user_id as u64)) {
                guard.push(user_id as u64);
            }
        }

        if manager_rho.is_none() {
            if let Some(rho_conn) = self.get_rho_connection().await {
                rho_conn.add_user_id(user_id).await;
            }
        }
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

    async fn replace_state_subscription(
        &self,
        user_id: i64,
        session_id: i64,
        contact_ids: Vec<i64>,
    ) -> Result<(), String> {
        let Some(rho_connection) = self.get_rho_connection().await else {
            return Err("Rho connection is unavailable".to_string());
        };
        if rho_connection
            .get_client_connection(user_id, session_id)
            .await
            .is_none()
        {
            return Err("target client session is no longer connected".to_string());
        }

        self.state
            .omega
            .replace_state_subscription(user_id, session_id, contact_ids)
            .await
    }

    fn update_presence_subscription(
        self: &Arc<Self>,
        user_id: i64,
        session_id: i64,
        contact_ids: Vec<i64>,
    ) {
        let connection = self.clone();
        tokio::spawn(async move {
            log_in!(
                connection.iota_id as i64,
                PrintType::Omega,
                "PresenceSync user={} session={} stage=subscribe",
                user_id,
                session_id
            );
            if let Err(error) = connection
                .replace_state_subscription(user_id, session_id, contact_ids)
                .await
            {
                log_err!(
                    connection.iota_id as i64,
                    PrintType::Omega,
                    "Failed to replace presence subscription for user {} session {}: {}",
                    user_id,
                    session_id,
                    error
                );
            }
        });
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

    #[allow(dead_code)]
    pub async fn send_relay(&self, cv: &CommunicationValue) -> Result<(), String> {
        self.sender
            .send(cv)
            .await
            .map_err(|error| error.to_string())
    }

    async fn handle_message_inner(self: Arc<Self>, cv: CommunicationValue) {
        let message_id = match cv.require_id() {
            Ok(message_id) => message_id,
            Err(error) => {
                log_err!(
                    self.iota_id as i64,
                    PrintType::Iota,
                    "Rejected malformed message: {}",
                    error
                );
                let response =
                    CommunicationValue::new(CommunicationType::ErrorInvalidData).without_id();
                self.send_message(&response).await;
                return;
            }
        };
        if cv.is_type(CommunicationType::Relay) {
            let wire_receiver = match cv.require_receiver() {
                Ok(next_hop) => next_hop,
                Err(error) => {
                    log_err!(
                        self.iota_id as i64,
                        PrintType::Iota,
                        "Rejected malformed relay: {}",
                        error
                    );
                    self.send_error_response(message_id, CommunicationType::ErrorInvalidData, None)
                        .await;
                    return;
                }
            };
            let route_target = relay_router::RouteTarget::from_wire_id(wire_receiver);
            let response = match relay_router::route_relay(
                &self.state,
                RelaySource::Iota {
                    iota_id: self.iota_id,
                },
                relay_router::ensure_relay_frame_id(cv),
            )
            .await
            {
                Ok(response) => response.with_id(message_id),
                Err(error) => {
                    relay_router::relay_route_error_response(message_id, route_target, &error)
                }
            };
            self.send_message(&response).await;
            return;
        }

        if matches!(
            crate::rho::relay_router::message_security_class(&cv),
            crate::rho::relay_router::MessageSecurityClass::RelayOnly
        ) {
            if matches!(
                cv.get_comm_type_enum(),
                Some(
                    CommunicationType::MessageLive
                        | CommunicationType::MessageState
                        | CommunicationType::MessageEditLive
                        | CommunicationType::MessageReactionLive
                        | CommunicationType::MessageDeleteLive
                )
            ) {
                self.forward_to_client(cv).await;
                return;
            }
            self.send_error_response(message_id, CommunicationType::ErrorInvalidData, None)
                .await;
            return;
        }

        if cv.is_type(CommunicationType::ChatSecretForward) {
            self.forward_to_client(cv).await;
            return;
        }

        log_cv_in!(PrintType::Iota, cv);

        if cv.is_type(CommunicationType::SyncedSettingChanged)
            || cv.is_type(CommunicationType::UserBlobChanged)
            || cv.is_type(CommunicationType::UserAssetChanged)
            || cv.is_type(CommunicationType::BlockedUsersChanged)
            || cv.is_type(CommunicationType::ReceiptPolicyChanged)
            || cv.is_type(CommunicationType::MessageStoragePolicyChanged)
            || cv.is_type(CommunicationType::PushNotification)
        {
            self.forward_to_client(cv).await;
            return;
        }

        let msg_id = message_id;
        if let Some((_, task)) = self.waiting_tasks.remove(&msg_id) {
            if (task)(msg_id, cv.clone()) {
                return;
            }
        }

        if cv.is_type(CommunicationType::AccountStateSnapshot) {
            let user_id = cv.receiver();
            let session_id = cv.get_data(DataType::SessionId).as_number();
            log_in!(
                self.iota_id as i64,
                PrintType::Iota,
                "AccountStateSnapshot user={:?} session={:?} stage=ignored_unsolicited",
                user_id,
                session_id
            );
            // Request-correlated state responses are consumed above by
            // `await_response`.  An unsolicited account-state snapshot cannot form
            // an initial snapshot because it has not crossed the Omega
            // presence barrier, so ClientConnection owns that transaction.
            return;
        }

        // Iota's UserIds field is an authoritative replacement snapshot for
        // the requesting client session, including contact mutations.
        if let Some((user_id, session_id, contact_ids)) = contact_snapshot(&cv) {
            self.update_presence_subscription(user_id, session_id, contact_ids);
        }

        if cv.is_type(CommunicationType::StateSubscribe) {
            self.send_error_response(
                message_id,
                CommunicationType::ErrorInvalidData,
                Some("StateSubscribe must come from an authoritative contact snapshot"),
            )
            .await;
            return;
        }

        // Handle GET_CHATS
        if cv.is_type(CommunicationType::GetChats) {
            self.handle_get_chats(cv).await;
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
                message_id
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
                    message_id,
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
                        "Omega completed registration (request_id={}, response_id={:?}, type={})",
                        message_id,
                        response_cv.id(),
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
                    /*
                     * A lost Success can follow a committed insert. Verify
                     * the requested identity and this authenticated Iota
                     * before adding a local binding.
                     */
                    let user_id = cv.get_data(DataType::UserId).as_number();
                    let username = cv.get_data(DataType::Username).as_str().map(str::to_owned);
                    let public_key = cv.get_data(DataType::PublicKey).as_str().map(str::to_owned);
                    if let Some(user_id) = user_id {
                        let verification = CommunicationValue::new(CommunicationType::GetUserData)
                            .with_sender(self.state.omega.omikron_id())
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
                                    == Some(user_id)
                                    && verified.get_data(DataType::IotaId).as_number()
                                        == Some(self.iota_id.into())
                                    && verified.get_data(DataType::Username).as_str()
                                        == username.as_deref()
                                    && verified.get_data(DataType::PublicKey).as_str()
                                        == public_key.as_deref() =>
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
                                        .with_id(message_id),
                                )
                                .await;
                                return;
                            }
                            Ok(verified) => log_err!(
                                self.iota_id as i64,
                                PrintType::Omega,
                                "Registration verification returned an unexpected user (request_id={:?}, response_id={:?})",
                                verification.id(),
                                verified.id()
                            ),
                            Err(verify_error) => log_err!(
                                self.iota_id as i64,
                                PrintType::Omega,
                                "Registration verification failed after request_id={:?}: {}",
                                verification.id(),
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
                        message_id,
                        CommunicationType::ErrorInternal,
                        Some(&format!("Omega forwarding failed: {error}")),
                    )
                    .await;
                }
            }
            return;
        }

        if is_iota_omega_management_operation(&cv) {
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
        log_err!(
            self.iota_id as i64,
            PrintType::Iota,
            "Rejected unsupported communication type {}",
            cv.get_type()
        );
        self.send_error_response(message_id, CommunicationType::ErrorInvalidData, None)
            .await;
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
    pub(crate) async fn close(&self) {
        let _ = self.sender.close();
    }

    async fn handle_omega_forward(self: Arc<Self>, cv: CommunicationValue) {
        let Ok(message_id) = cv.require_id() else {
            return;
        };
        let iota_for_closure = self.clone();
        let response_cv = self
            .state
            .omega
            .clone()
            .await_response(&cv.with_sender(self.iota_id), Some(Duration::from_secs(20)))
            .await;
        match response_cv {
            Ok(response_cv) => iota_for_closure.send_message(&response_cv).await,
            Err(error) => {
                log_err!(
                    self.iota_id as i64,
                    PrintType::Omega,
                    "Iota management forwarding failed: {}",
                    error
                );
                self.send_error_response(
                    message_id,
                    CommunicationType::ErrorInternal,
                    Some(&format!("Omega forwarding failed: {error}")),
                )
                .await;
            }
        }
    }

    async fn handle_omega_forward_without_sender(self: Arc<Self>, cv: CommunicationValue) {
        let Ok(message_id) = cv.require_id() else {
            return;
        };
        let iota_for_closure = self.clone();
        let request = registration_request(&cv, self.iota_id);
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
                message_id,
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
                    message_id,
                    CommunicationType::ErrorInternal,
                    Some(&format!("Omega forwarding failed: {error}")),
                )
                .await;
            }
        }
    }
    /// Handle GET_CHATS message
    async fn handle_get_chats(&self, cv: CommunicationValue) {
        let Ok(message_id) = cv.require_id() else {
            return;
        };
        let Ok(user_id) = cv.require_sender() else {
            log_err!(
                self.iota_id as i64,
                PrintType::Iota,
                "Rejected get_chats without an MTP sender"
            );
            return;
        };

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
        let Some(session_id) = cv
            .get_data(DataType::SessionId)
            .as_signed_number()
            .and_then(|id| i64::try_from(id).ok())
            .filter(|id| *id > 0)
        else {
            self.forward_to_client(
                CommunicationValue::new(CommunicationType::ErrorInvalidData)
                    .with_id(message_id)
                    .with_receiver(user_id),
            )
            .await;
            return;
        };
        let tm = TypeMap::latest();

        // Presence interest is the complete contact set, independent of
        // whether this account currently participates in a call.
        if let Some(DataValue::Array(users)) = cv.get_data(DataType::UserIds) {
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
            let (call_self, pending, members, pending_invitees) = {
                let state = call.state.read().await;
                (
                    state.members.get(&user_id).cloned(),
                    state.pending_invites.get(&user_id).cloned(),
                    state.members.keys().copied().collect::<Vec<_>>(),
                    state.pending_invites.keys().copied().collect::<Vec<_>>(),
                )
            };

            if call_self.is_none() && pending.is_none() {
                continue;
            }

            // Iota is authoritative for entitlement and the recipient envelope.
            let request = CommunicationValue::new(CommunicationType::CallEnvelopeGet)
                .with_id(crate::services::call_state::next_call_lookup_id())
                .add_typed_default(
                    DataType::ReceiverId,
                    DataValue::SignedNumber(user_id.into()),
                )
                .add_typed_default(DataType::CallId, DataValue::Str(call.call_id.to_string()));
            let secret = self
                .state
                .rho
                .get_for_user(user_id as i64)
                .await
                .map(|rho| rho.get_iota_connection().clone());
            let secret = match secret {
                Some(connection) => {
                    connection
                        .await_response(&request, Some(std::time::Duration::from_secs(8)))
                        .await
                }
                None => Err("Iota unavailable".into()),
            }
            .ok()
            .filter(|response| response.is_type(CommunicationType::CallEnvelopeGet))
            .and_then(|response| response.get_data(DataType::CallSecret).cloned());
            if let Some(secret) = secret {
                let timeout = call_self
                    .as_ref()
                    .and_then(|member| member.timeout_until_ms)
                    .unwrap_or(0);
                let admin = call_self
                    .as_ref()
                    .is_some_and(|member| member.role == crate::calls::call_group::CallRole::Admin);

                // List of all members in the call, plus pending invitees so
                // clients recognize joinable calls for a contact.
                let member_ids: Vec<DataValue> = members
                    .iter()
                    .chain(pending_invitees.iter())
                    .map(|id| DataValue::SignedNumber((*id).into()))
                    .collect();

                // Build base call container
                let mut base_call_map: BTreeMap<DataTypeId, DataValue> = BTreeMap::new();
                base_call_map.insert(
                    data_type_id(DataType::CallId, &tm),
                    DataValue::Str(call.call_id.to_string()),
                );
                base_call_map.insert(
                    data_type_id(DataType::OmikronId, &tm),
                    DataValue::SignedNumber((call.owner_omikron_id as i64).into()),
                );
                base_call_map.insert(
                    data_type_id(DataType::CallMembers, &tm),
                    DataValue::Array(member_ids),
                );
                base_call_map.insert(data_type_id(DataType::CallSecret, &tm), secret);
                base_call_map.insert(
                    data_type_id(DataType::CreatedAt, &tm),
                    DataValue::SignedNumber(call.created_at_ms.into()),
                );
                if let Some(pending) = pending {
                    base_call_map.insert(
                        data_type_id(DataType::CallInvited, &tm),
                        DataValue::Bool(true),
                    );
                    base_call_map.insert(
                        data_type_id(DataType::SenderId, &tm),
                        DataValue::SignedNumber(pending.inviter_id.into()),
                    );
                }

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

                // Add to global calls with only this user's recipient-specific secret.
                global_calls.push(DataValue::container_from_map(&base_call_map));

                // Attach this call to EVERY member of the call (other than ourselves)
                for member_id in members {
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
                Some(DataValue::Array(arr)) => DataValue::Array(arr.clone()),
                _ => DataValue::Array(vec![]),
            }
        } else {
            let mut enriched: Vec<DataValue> = Vec::new();

            if let Some(DataValue::Array(users)) = cv.get_data(DataType::UserIds) {
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
        if let Err(error) = self
            .replace_state_subscription(user_id as i64, session_id, interested_ids.clone())
            .await
        {
            log_err!(
                self.iota_id as i64,
                PrintType::Omega,
                "Failed to replace presence subscription for user {} session {}: {}",
                user_id,
                session_id,
                error
            );
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
        }
    }

    pub(crate) async fn augment_client_state_sync(
        &self,
        response: CommunicationValue,
    ) -> CommunicationValue {
        let mut output = response.clone();
        let Some(user_id) = response.receiver() else {
            log_err!(
                self.iota_id as i64,
                PrintType::Iota,
                "Discarded response without an MTP receiver"
            );
            return output;
        };

        let typed_data: Vec<_> = response.iter_typed_data().collect();
        let mut augmented_calls = false;
        let mut original_calls = None;
        for (key, value) in typed_data {
            if key == Some(DataType::Contacts) {
                if let Some(contacts) = value.as_array() {
                    let (contacts, global_calls) = self
                        .state
                        .call_state_aggregator
                        .augment_contacts(user_id, contacts.clone())
                        .await;
                    augmented_calls = true;
                    output =
                        output.add_typed_default(DataType::Contacts, DataValue::Array(contacts));
                    output =
                        output.add_typed_default(DataType::Calls, DataValue::Array(global_calls));
                    continue;
                }
            }
            // The Iota snapshot always carries an empty Calls array; the
            // augmented value above is authoritative. Re-adding the original
            // here would clobber it.
            if key == Some(DataType::Calls) {
                original_calls = Some(value.clone());
                continue;
            }
            if let Some(data_type) = key {
                output = output.add_typed_default(data_type, value.clone());
            }
        }
        if !augmented_calls {
            if let Some(calls) = original_calls {
                output = output.add_typed_default(DataType::Calls, calls);
            }
        }
        output
    }

    pub async fn handle_close(&self) {
        self.waiting_tasks.clear();
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

    fn reserve_response_id(&self, task: ResponseTask) -> u32 {
        let mut task = Some(task);
        loop {
            let candidate = self.next_response_id.fetch_add(1, Ordering::Relaxed);
            if candidate == 0 {
                continue;
            }
            match self.waiting_tasks.entry(candidate) {
                Entry::Occupied(_) => {}
                Entry::Vacant(entry) => {
                    entry.insert(task.take().expect("response task inserted once"));
                    return candidate;
                }
            }
        }
    }

    pub async fn await_response(
        self: Arc<Self>,
        cv: &CommunicationValue,
        timeout_duration: Option<Duration>,
    ) -> Result<CommunicationValue, String> {
        let external_id = cv
            .require_id()
            .map_err(|error| format!("request is missing correlation ID: {error}"))?;
        let (tx, mut rx) = mpsc::channel(1);
        let internal_id = self.reserve_response_id(Box::new(move |_, response| {
            tokio::spawn(async move {
                let _ = tx.send(response).await;
            });
            true
        }));
        self.send_message(&cv.clone().with_id(internal_id)).await;
        let timeout = timeout_duration.unwrap_or(Duration::from_secs(10));
        let result = tokio::time::timeout(timeout, rx.recv()).await;
        self.waiting_tasks.remove(&internal_id);
        match result {
            Ok(Some(response)) => Ok(response.with_id(external_id)),
            Ok(None) => Err("Iota response channel closed".into()),
            Err(_) => Err("Iota request timed out".into()),
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

#[cfg(test)]
mod tests {
    use super::{
        contact_snapshot, is_iota_omega_management_operation, registration_request,
        reserve_response_id_with,
    };
    use crate::util::data_type_id;
    use dashmap::DashMap;
    use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue, TypeMap};

    fn snapshot(user_ids: DataValue) -> CommunicationValue {
        CommunicationValue::new(CommunicationType::AccountStateSnapshot)
            .with_receiver(7)
            .add_typed_default(DataType::SessionId, DataValue::SignedNumber(11))
            .add_typed_default(DataType::UserIds, user_ids)
    }

    #[test]
    fn response_id_allocator_skips_collisions_and_zero() {
        let waiting = DashMap::new();
        waiting.insert(42, Box::new(|_, _| true) as super::ResponseTask);
        let mut candidates = [0, 42, 42, 73].into_iter();
        let id = reserve_response_id_with(
            &waiting,
            || candidates.next().unwrap(),
            Box::new(|_, _| true),
        );
        assert_eq!(id, 73);
        assert!(waiting.contains_key(&42));
        assert!(waiting.contains_key(&73));
        assert!(!waiting.contains_key(&0));
    }

    #[test]
    fn clearing_waiters_on_disconnect_closes_response_channels() {
        let waiting = DashMap::new();
        let (sender, receiver) = std::sync::mpsc::channel::<CommunicationValue>();
        reserve_response_id_with(
            &waiting,
            || 17,
            Box::new(move |_, response| {
                sender.send(response).unwrap();
                true
            }),
        );
        waiting.clear();
        assert!(receiver.recv().is_err());
    }

    #[test]
    fn same_external_ids_have_distinct_internal_correlations() {
        let waiting = DashMap::new();
        let mut candidates = [100, 100, 101].into_iter();
        let external_id = 42;
        let (first_tx, first_rx) = std::sync::mpsc::channel();
        let (second_tx, second_rx) = std::sync::mpsc::channel();
        let first = reserve_response_id_with(
            &waiting,
            || candidates.next().unwrap(),
            Box::new(move |_, response| {
                first_tx.send(response.with_id(external_id)).unwrap();
                true
            }),
        );
        let second = reserve_response_id_with(
            &waiting,
            || candidates.next().unwrap(),
            Box::new(move |_, response| {
                second_tx.send(response.with_id(external_id)).unwrap();
                true
            }),
        );
        assert_ne!(first, second);
        let (_, second_task) = waiting.remove(&second).unwrap();
        assert!(second_task(
            second,
            CommunicationValue::new(CommunicationType::Success).with_id(second)
        ));
        let (_, first_task) = waiting.remove(&first).unwrap();
        assert!(first_task(
            first,
            CommunicationValue::new(CommunicationType::ErrorInvalidData).with_id(first)
        ));
        let first_response = first_rx.recv().unwrap();
        let second_response = second_rx.recv().unwrap();
        assert_eq!(first_response.id(), Some(42));
        assert!(first_response.is_type(CommunicationType::ErrorInvalidData));
        assert_eq!(second_response.id(), Some(42));
        assert!(second_response.is_type(CommunicationType::Success));
    }

    #[test]
    fn contact_snapshot_deduplicates_flat_and_typed_ids() {
        let user_id_type = data_type_id(DataType::UserId, &TypeMap::latest());
        let parsed = contact_snapshot(&snapshot(DataValue::Array(vec![
            DataValue::SignedNumber(20),
            DataValue::Container(vec![(user_id_type, DataValue::SignedNumber(21))]),
            DataValue::SignedNumber(20),
        ])))
        .unwrap();

        assert_eq!(parsed, (7, 0, vec![20, 21]));
    }

    #[test]
    fn contact_snapshot_accepts_empty_contact_sets() {
        assert_eq!(
            contact_snapshot(&snapshot(DataValue::Array(Vec::new()))),
            Some((7, 0, Vec::new()))
        );
    }

    #[test]
    fn contact_snapshot_rejects_malformed_contact_sets() {
        assert_eq!(
            contact_snapshot(&snapshot(DataValue::Array(vec![DataValue::Str(
                "bad".into(),
            )]))),
            None
        );
    }

    #[test]
    fn authenticated_iota_forwards_all_invitation_management_operations() {
        for operation in [
            CommunicationType::CreateUserInvitation,
            CommunicationType::ListUserInvitations,
            CommunicationType::RevokeUserInvitation,
        ] {
            assert!(is_iota_omega_management_operation(
                &CommunicationValue::new(operation)
            ));
        }
    }

    #[test]
    fn registration_retry_keeps_operation_token_when_transport_id_changes() {
        let request = registration_request(
            &CommunicationValue::new(CommunicationType::GetRegister).with_id(42),
            7,
        );
        let first = request.clone().with_id(1001);
        let second = request.with_id(1002);

        assert_ne!(first.id(), second.id());
        assert_eq!(
            first.get_data(DataType::RegisterId),
            second.get_data(DataType::RegisterId)
        );
    }
}
