use crate::app_state::AppState;
use crate::calls::call_group::CallGroup;
use crate::log_cv_in;
use crate::log_cv_out;
use crate::log_err;
use crate::log_in;
use crate::log_out;
use crate::rho::connection::{
    GeneralConnection, MtpReceiver, MtpSender, OptionalDataValueExt, RequiredCommunicationFields,
};
use crate::rho::relay_router;
use crate::util::data_type_id;
use crate::util::logger::PrintType;
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
    /// Derived only from the MTP-authenticated transport key, never its numeric ID.
    pub(crate) node_id: Option<relay_router::IotaNodeId>,
    pub client_version: String,
    pub sender: Arc<MtpSender>,
    pub receiver: Arc<MtpReceiver>,
    pub(super) user_ids: Arc<RwLock<std::collections::HashSet<i64>>>,
    pub_key: Arc<RwLock<Option<Vec<u8>>>>,
    pub waiting_tasks: tau::ResponseCorrelator,
    pub rho_connection: Arc<RwLock<Option<Arc<RhoConnection>>>>,
    message_slots: Arc<tokio::sync::Semaphore>,
    tasks: super::tasks::MessageTasks,
    mutation_journal_path: std::path::PathBuf,
}

impl IotaConnection {
    pub async fn from_general(general: Arc<GeneralConnection>, iota_id: u64) -> Arc<Self> {
        let node_id = if general.connection_kind() == super::connection::ConnectionKind::Iota
            && general.mtp_connection.auth_state == mtp::host::AuthState::Authenticated
        {
            general
                .mtp_connection
                .client_public_key
                .as_ref()
                .and_then(|key| relay_router::IotaNodeId::from_public_keys(key).ok())
        } else {
            None
        };
        Arc::new(Self {
            state: general.state.clone(),
            _mtp_connection: Some(general.mtp_connection.clone()),
            pub_key: Arc::new(RwLock::new(None)),
            rho_connection: general.rho_connection.clone(),
            user_ids: Arc::new(RwLock::new(std::collections::HashSet::new())),
            sender: general.sender.clone(),
            receiver: general.receiver.clone(),
            iota_id,
            node_id,
            client_version: general.client_version.read().await.clone(),
            waiting_tasks: tau::ResponseCorrelator::with_next_id(rand::random::<u32>().max(1)),
            message_slots: Arc::new(tokio::sync::Semaphore::new(32)),
            tasks: super::tasks::MessageTasks::new(
                general.shutdown.subscribe(),
                general.state.config.message_drain,
            ),
            mutation_journal_path: crate::omega::mutation_journal_path(),
        })
    }
    pub async fn run(self: Arc<Self>) {
        let self_clone = self.clone();
        loop {
            match self_clone
                .tasks
                .while_connected(&self_clone.receiver, self_clone.receiver.receive())
                .await
            {
                Some(Ok(cv)) => {
                    let Some(Ok(permit)) = self_clone
                        .tasks
                        .while_connected(
                            &self_clone.receiver,
                            self_clone.message_slots.clone().acquire_owned(),
                        )
                        .await
                    else {
                        break;
                    };
                    let connection = self_clone.clone();
                    if let Err(error) = self_clone.tasks.spawn(async move {
                        let _permit = permit;
                        connection.handle_message_inner(cv).await;
                    }) {
                        log_err!(
                            self_clone.iota_id as i64,
                            PrintType::Iota,
                            "Iota message submission failed: {}",
                            error
                        );
                        self_clone.sender.close();
                        break;
                    }
                }
                Some(Err(error)) => {
                    log_err!(
                        self_clone.iota_id as i64,
                        PrintType::Iota,
                        "Iota receive loop ended: {}; transport close reason: {:?}",
                        error,
                        self_clone.receiver.close_reason()
                    );
                    break;
                }
                None => break,
            }
        }
        self_clone.waiting_tasks.close();
        self_clone.tasks.drain().await;
        self_clone.handle_close().await;
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
    #[cfg(test)]
    pub async fn get_user_ids(&self) -> Vec<u64> {
        let mut users: Vec<_> = self
            .user_ids
            .read()
            .await
            .iter()
            .filter_map(|id| u64::try_from(*id).ok())
            .collect();
        users.sort_unstable();
        users
    }

    pub async fn add_user_id(&self, user_id: u64) {
        let Ok(user_id) = i64::try_from(user_id) else {
            return;
        };
        let _ = self
            .state
            .rho
            .bind_user_to_iota(user_id, self.iota_id as i64)
            .await;
    }

    /// Set the RhoConnection reference
    pub async fn set_rho_connection(&self, rho_connection: Arc<RhoConnection>) {
        let mut rho_ref = self.rho_connection.write().await;
        *rho_ref = Some(rho_connection);
    }

    /// Get RhoConnection if available
    pub async fn get_rho_connection(&self) -> Option<Arc<RhoConnection>> {
        let rho_ref = self.rho_connection.read().await;
        rho_ref.as_ref().map(|weak_ref| weak_ref.clone())
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
        if let Err(error) = self.tasks.spawn_cancellable(async move {
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
        }) {
            log_err!(
                self.iota_id as i64,
                PrintType::Iota,
                "Presence task submission failed: {}",
                error
            );
            self.sender.close();
        }
    }

    /// Send a CommunicationValue to the Iota
    pub async fn send_message(&self, cv: &CommunicationValue) {
        log_cv_out!(PrintType::Iota, cv);
        if let Err(e) = self.sender.send(cv).await {
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
        let current = self.get_rho_connection().await.is_some_and(|rho| {
            std::ptr::eq(rho.get_iota_connection().as_ref(), self.as_ref())
                && self.state.rho.is_current_rho(&rho)
        });
        if !current {
            log_err!(
                self.iota_id as i64,
                PrintType::Iota,
                "Rejected message from replaced or unpublished Iota connection"
            );
            self.sender.close();
            return;
        }
        let message_id = match cv.require_id() {
            Ok(message_id) => message_id,
            Err(error) => {
                log_err!(
                    self.iota_id as i64,
                    PrintType::Iota,
                    "Rejected malformed message: {}",
                    error
                );
                let latest = TypeMap::latest();
                let response = tau::error_response(
                    &cv,
                    CommunicationType::ErrorInvalidData,
                    cv.type_map().unwrap_or(&latest),
                );
                self.send_message(&response).await;
                return;
            }
        };
        if matches!(
            relay_router::message_security_class(&cv),
            relay_router::MessageSecurityClass::Unsupported
        ) {
            // Correlated replies have their own request-specific type policy.
            if self.waiting_tasks.complete(message_id, cv.clone()) {
                return;
            }
            self.send_error_response(message_id, CommunicationType::ErrorInvalidData, None)
                .await;
            return;
        }
        if cv.is_type(CommunicationType::Relay) {
            let response = match relay_router::route_relay(
                &self.state,
                &self,
                relay_router::ensure_relay_frame_id(cv),
            )
            .await
            {
                Ok(response) => response.with_id(message_id),
                Err(error) => relay_router::relay_route_error_response(message_id, None, &error),
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
        if self.waiting_tasks.complete(msg_id, cv.clone()) {
            return;
        }

        if relay_router::is_relay_receipt_page(&cv) {
            // Account receipt pages are only released by their authenticated
            // request owner after its current-generation checks.
            return;
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
                    if response_cv.is_type(CommunicationType::Success)
                        && let Some(user_id) = cv.get_data(DataType::UserId).as_number()
                    {
                        self.add_user_id(user_id as u64).await;
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
        self.sender.close();
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
        if !i64::try_from(user_id)
            .ok()
            .is_some_and(|user| self.state.rho.owns_iota_user(user, self))
        {
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
                        .or_default()
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
                            && let Some(call_list) = invites.get(&(*id as i64))
                            && !call_list.is_empty()
                        {
                            user_map.insert(
                                data_type_id(DataType::Calls, &tm),
                                DataValue::Array(call_list.clone()),
                            );
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
            if key == Some(DataType::Contacts)
                && let Some(contacts) = value.as_array()
            {
                let (contacts, global_calls) = self
                    .state
                    .call_state_aggregator
                    .augment_contacts(user_id, contacts.clone())
                    .await;
                augmented_calls = true;
                output = output.add_typed_default(DataType::Contacts, DataValue::Array(contacts));
                output = output.add_typed_default(DataType::Calls, DataValue::Array(global_calls));
                continue;
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
        if !augmented_calls && let Some(calls) = original_calls {
            output = output.add_typed_default(DataType::Calls, calls);
        }
        output
    }

    pub async fn handle_close(&self) {
        self.waiting_tasks.close();
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

    pub async fn await_response(
        self: Arc<Self>,
        cv: &CommunicationValue,
        timeout_duration: Option<Duration>,
    ) -> Result<CommunicationValue, String> {
        let receipt_page = relay_router::is_relay_receipt_page(cv);
        let expected = cv
            .type_map()
            .and_then(|map| map.comm_enum_id(cv.get_type().0));
        let timeout = timeout_duration.unwrap_or(Duration::from_secs(10));
        // Read-only forwards can stop without remote reconciliation. Unknown
        // operations default to a durable uncertain intent, never automatic replay.
        let read_only = matches!(
            expected,
            Some(
                CommunicationType::RelayReceiptPage
                    | CommunicationType::AccountStateRequest
                    | CommunicationType::GetChatSecret
                    | CommunicationType::MessageGet
                    | CommunicationType::MessagesGet
                    | CommunicationType::SyncedSettingGet
                    | CommunicationType::SyncedSettingsList
                    | CommunicationType::UserBlobGet
                    | CommunicationType::UserBlobList
                    | CommunicationType::UserAssetUploadStatus
                    | CommunicationType::UserAssetGetChunk
                    | CommunicationType::UserAssetList
                    | CommunicationType::BlockedUsersGet
                    | CommunicationType::ReceiptPolicyGet
                    | CommunicationType::MessageStoragePolicyGet
                    | CommunicationType::PasswordEnrollmentStatus
                    | CommunicationType::CallEnvelopeGet
            )
        );
        let journal = if read_only {
            None
        } else {
            let journal = crate::omega::MutationJournal::open(&self.mutation_journal_path)?;
            let generation = self
                .state
                .rho
                .get_by_iota(self.iota_id as i64)
                .await
                .and_then(|rho| {
                    cv.sender()
                        .and_then(|user| self.state.rho.user_route_generation(user as i64, &rho))
                });
            let scope = format!("iota:{}", self.iota_id);
            let id = journal.begin(cv, &scope, generation)?;
            Some((journal, id))
        };
        let result = self
            .waiting_tasks
            .exchange(
                cv,
                timeout,
                move |response| {
                    if receipt_page && relay_router::is_relay_receipt_page(response) {
                        return true;
                    }
                    let actual = response
                        .type_map()
                        .and_then(|map| map.comm_enum_id(response.get_type().0));
                    actual.is_some() && actual == expected
                        || actual.is_some_and(tau::is_protocol_error)
                        || actual == Some(CommunicationType::Success)
                            && matches!(
                                expected,
                                Some(
                                    CommunicationType::Relay
                                        | CommunicationType::AccountStateApplied
                                        | CommunicationType::CallEnvelopeStore
                                        | CommunicationType::CallContactAccept
                                        | CommunicationType::MessageEdit
                                        | CommunicationType::MessageReactionAdd
                                        | CommunicationType::MessageReactionRemove
                                        | CommunicationType::MessageDeleteLive
                                        | CommunicationType::PasswordEnrollmentFinish
                                )
                            )
                        || matches!(
                            (expected, actual),
                            (
                                Some(CommunicationType::AccountStateRequest),
                                Some(CommunicationType::AccountStateSnapshot)
                            ) | (
                                Some(CommunicationType::GetChatSecret),
                                Some(CommunicationType::ChatSecretResponse)
                            ) | (
                                Some(CommunicationType::TAuthAuthorize),
                                Some(CommunicationType::TAuthAuthorizationResult)
                            ) | (
                                Some(CommunicationType::TAuthExchangeCode),
                                Some(CommunicationType::TAuthExchangeCodeResponse)
                            ) | (
                                Some(CommunicationType::PasswordEnrollmentStart),
                                Some(CommunicationType::PasswordEnrollmentResponse)
                            ) | (
                                Some(CommunicationType::PasswordProvisioningStart),
                                Some(CommunicationType::PasswordProvisioningResponse)
                            )
                        )
                },
                |outbound| {
                    let sender = &self.sender;
                    async move { sender.send(&outbound).await }
                },
            )
            .await
            .map_err(|error| error.to_string());
        if let (Some((journal, id)), Ok(response)) = (&journal, &result) {
            journal.resolve(id, response)?;
        }
        result
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
    #[tokio::test]
    async fn timed_out_forward_retains_intent_and_rejects_transport_id_retry() {
        use crate::rho::{
            connection::{GeneralConnection, admission_engine},
            test_support,
        };
        let state = test_support::state();
        let (host, peer, transport) = test_support::guest("anonymous").await;
        let general = GeneralConnection::admit(transport, state, &admission_engine()).unwrap();
        let iota = super::IotaConnection::from_general(general, 2).await;
        let request = CommunicationValue::new(CommunicationType::SyncedSettingSet)
            .with_sender(7)
            .add_typed_default(
                DataType::OpaqueMessage,
                DataValue::Bytes(b"private-setting".to_vec()),
            );
        let task = tokio::spawn({
            let iota = iota.clone();
            let request = request.clone();
            async move {
                iota.await_response(&request, Some(std::time::Duration::from_millis(50)))
                    .await
            }
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), peer.receive())
            .await
            .unwrap()
            .unwrap();
        assert!(task.await.unwrap().is_err());
        let journal = crate::omega::MutationJournal::open(&iota.mutation_journal_path).unwrap();
        assert_eq!(journal.unresolved().unwrap(), 1);
        let retry = iota
            .clone()
            .await_response(
                &request.with_id(123),
                Some(std::time::Duration::from_millis(50)),
            )
            .await;
        assert!(retry.unwrap_err().contains("uncertain outcome"));
        assert_eq!(journal.unresolved().unwrap(), 1);
        drop(journal);
        std::fs::remove_file(&iota.mutation_journal_path).unwrap();
        peer.sender.close().await;
        host.shutdown().await;
    }

    #[tokio::test]
    async fn receipt_page_response_is_correlated_and_rejects_assignment_aba() {
        use crate::rho::{
            connection::{GeneralConnection, admission_engine},
            rho_connection::RhoConnection,
            test_support,
        };
        use mtp::codec::{CommunicationType, CommunicationValue};
        use std::{sync::Arc, time::Duration};

        let state = test_support::state();
        let (host, peer, transport) = test_support::guest("anonymous").await;
        let general =
            GeneralConnection::admit(transport, state.clone(), &admission_engine()).unwrap();
        let iota = super::IotaConnection::from_general(general, 2).await;
        let rho = Arc::new(RhoConnection::new(iota.clone(), vec![7]).await);
        state.rho.add(rho.clone()).await;
        let mut bytes = CommunicationValue::new(CommunicationType::Success)
            .with_id(99)
            .with_sender(7)
            .to_bytes()
            .unwrap();
        bytes[4..6].copy_from_slice(&225u16.to_be_bytes());
        let page = CommunicationValue::from_bytes(&bytes).unwrap();
        for reassign in [false, true] {
            let task = tokio::spawn({
                let rho = rho.clone();
                let page = page.clone();
                async move { rho.await_peer_control(&page).await }
            });
            let outbound = tokio::time::timeout(Duration::from_secs(2), peer.receive())
                .await
                .unwrap()
                .unwrap();
            if reassign {
                state.rho.invalidate_user(7).await;
                state.rho.bind_user_to_iota(7, 2).await.unwrap();
            }
            assert!(
                iota.waiting_tasks
                    .complete(outbound.id().unwrap(), outbound)
            );
            let result = tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .unwrap()
                .unwrap();
            if reassign {
                assert!(result.unwrap_err().contains("route changed"));
            } else {
                assert_eq!(result.unwrap().id(), Some(99));
            }
        }
        peer.sender.close().await;
        host.shutdown().await;
    }
    use super::{contact_snapshot, is_iota_omega_management_operation, registration_request};
    use crate::util::data_type_id;
    use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue, TypeMap};

    fn snapshot(user_ids: DataValue) -> CommunicationValue {
        CommunicationValue::new(CommunicationType::AccountStateSnapshot)
            .with_receiver(7)
            .add_typed_default(DataType::SessionId, DataValue::SignedNumber(11))
            .add_typed_default(DataType::UserIds, user_ids)
    }

    #[test]
    fn response_id_allocator_skips_collisions_and_zero() {
        let waiting = tau::ResponseCorrelator::new();
        let occupied = waiting.reserve(|_| true).expect("registered");
        let id = waiting.reserve(|_| true).expect("allocated id");

        assert_ne!(id.id(), 0);
        assert_ne!(id.id(), occupied.id());
        assert!(waiting.complete(
            occupied.id(),
            CommunicationValue::new(CommunicationType::Success)
        ));
        assert!(waiting.complete(id.id(), CommunicationValue::new(CommunicationType::Success)));
        assert!(waiting.is_empty());
    }

    #[test]
    fn clearing_waiters_on_disconnect_closes_response_channels() {
        let waiting = tau::ResponseCorrelator::new();
        let (sender, receiver) = std::sync::mpsc::channel::<CommunicationValue>();
        let _pending = waiting
            .reserve(move |response| {
                sender.send(response).unwrap();
                true
            })
            .expect("internal id");
        waiting.clear();
        assert!(receiver.recv().is_err());
    }

    #[test]
    fn same_external_ids_have_distinct_internal_correlations() {
        let waiting = tau::ResponseCorrelator::new();
        let external_id = 42;
        let (first_tx, first_rx) = std::sync::mpsc::channel();
        let (second_tx, second_rx) = std::sync::mpsc::channel();
        let first = waiting
            .reserve(move |response| {
                first_tx.send(response.with_id(external_id)).unwrap();
                true
            })
            .expect("first internal id");
        let second = waiting
            .reserve(move |response| {
                second_tx.send(response.with_id(external_id)).unwrap();
                true
            })
            .expect("second internal id");
        assert_ne!(first.id(), second.id());
        assert!(waiting.complete(
            second.id(),
            CommunicationValue::new(CommunicationType::Success).with_id(second.id())
        ));
        assert!(waiting.complete(
            first.id(),
            CommunicationValue::new(CommunicationType::ErrorInvalidData).with_id(first.id())
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
