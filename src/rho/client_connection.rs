use crate::anonymous_clients::anonymous_manager;
use crate::app_state::AppState;
use crate::calls::{call_group::call_invite_secret_from_cv, call_manager::CallServiceError};
use crate::data::user::UserStatus;
use crate::omega::omega_connection::{AuthIdentity, AuthIdentityKind, InitialPresenceError};
use crate::rho::connection::{
    GeneralConnection, MtpReceiver, MtpSender, OptionalDataValueCompat, RequiredMtpFields,
};
use crate::rho::relay_router::{self, RelaySource};
use crate::rho::rho_connection::RhoConnection;
use crate::util::logger::PrintType;
use crate::{log_cv_in, log_cv_out, log_err, log_out};
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataTypeId, DataValue};
use mtp::crypto::PublicKeyBundle;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use std::{collections::VecDeque, str::FromStr};
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;

static NEXT_POLICY_REQUEST_ID: AtomicU32 = AtomicU32::new(1);
const MAX_CLIENT_STATE_SYNC_BUFFERED_EVENTS: usize = 1_024;

#[derive(Clone, Debug, Default)]
enum ClientStateSyncPhase {
    #[default]
    Idle,
    Requesting {
        device_id: String,
    },
    AwaitingAck {
        device_id: String,
        version: i64,
    },
    /// Iota's acknowledgement is in flight. Post-initial-state messages must
    /// remain queued until its durable commit succeeds.
    Committing {
        device_id: String,
        version: i64,
    },
    Draining,
}

#[derive(Default)]
struct ClientStateSyncState {
    phase: ClientStateSyncPhase,
    buffered_events: VecDeque<CommunicationValue>,
    overflowed: bool,
}

enum AckCommitStart {
    Started,
    Invalid,
    Overflowed,
}

fn next_policy_request_id() -> u32 {
    NEXT_POLICY_REQUEST_ID
        .fetch_add(1, Ordering::Relaxed)
        .max(1)
}

fn authenticated_peer_control_request(cv: &CommunicationValue, user_id: u64) -> CommunicationValue {
    cv.clone().with_sender(user_id)
}

fn is_client_omega_operation(value: &CommunicationValue) -> bool {
    matches!(
        value.get_comm_type_enum(),
        Some(
            CommunicationType::ChangeUserData
                | CommunicationType::GetNotifications
                | CommunicationType::GetUserData
                | CommunicationType::GetIotaData
                | CommunicationType::DeleteUser
        )
    )
}

fn call_error_type(error: &CallServiceError) -> CommunicationType {
    match error {
        CallServiceError::NotFound => CommunicationType::ErrorNotFound,
        CallServiceError::NotAuthorized | CallServiceError::TimedOut { .. } => {
            CommunicationType::ErrorNotAuthenticated
        }
        CallServiceError::InvalidUser => CommunicationType::ErrorInvalidUserId,
        CallServiceError::InvalidRequest => CommunicationType::ErrorInvalidData,
        CallServiceError::DeliveryFailed => CommunicationType::ErrorNotFound,
        CallServiceError::LiveKit(_) => CommunicationType::ErrorInternal,
    }
}

fn merge_initial_presence_snapshot(
    response: CommunicationValue,
    snapshot: CommunicationValue,
) -> CommunicationValue {
    let user_states = snapshot
        .get_data(DataType::UserStates)
        .cloned()
        .unwrap_or(DataValue::Array(Vec::new()));
    let missing_user_ids = snapshot
        .get_data(DataType::MissingUserIds)
        .cloned()
        .unwrap_or(DataValue::Array(Vec::new()));
    let complete = matches!(&missing_user_ids, DataValue::Array(ids) if ids.is_empty());

    response
        .add_typed_default(DataType::UserStates, user_states)
        .add_typed_default(DataType::MissingUserIds, missing_user_ids)
        .add_typed_default(
            DataType::PresenceSnapshotComplete,
            DataValue::Bool(complete),
        )
}

pub struct ClientConnection {
    pub state: Arc<AppState>,
    _mtp_connection: Option<Arc<mtp::webserver::WebMTPConnection>>,
    pub user_id: u64,
    pub session_id: u64,
    pub client_version: String,

    pub sender: Arc<MtpSender>,
    pub receiver: Arc<MtpReceiver>,
    pub_key: Arc<RwLock<Option<Vec<u8>>>>,
    pub rho_connection: Arc<RwLock<Option<Arc<RhoConnection>>>>,
    is_open: Arc<RwLock<bool>>,
    message_slots: Arc<tokio::sync::Semaphore>,
    client_state_sync: Arc<Mutex<ClientStateSyncState>>,
}

impl ClientConnection {
    /// Produces the one client-facing initial state response.  The Iota
    /// response is an internal input: presence is subscribed and fetched
    /// before this value is sent to the client.
    async fn compose_initial_client_state(
        &self,
        iota: Arc<crate::rho::iota_connection::IotaConnection>,
        response: CommunicationValue,
    ) -> Result<CommunicationValue, InitialPresenceError> {
        let response = iota.augment_client_state_sync(response).await;
        let Some((response_user_id, _, contacts)) =
            crate::rho::iota_connection::contact_snapshot(&response)
        else {
            return Err(InitialPresenceError::InvalidSnapshot(
                "ClientStateSync is missing a valid contact snapshot".into(),
            ));
        };
        if response_user_id != self.user_id as i64 {
            return Err(InitialPresenceError::InvalidSnapshot(
                "ClientStateSync does not belong to the authenticated session".into(),
            ));
        }

        match self
            .state
            .omega
            .initial_presence_snapshot(
                self.user_id as i64,
                self.session_id as i64,
                contacts.clone(),
            )
            .await
        {
            Ok(snapshot) => Ok(merge_initial_presence_snapshot(response, snapshot)),
            Err(error) => {
                self.state
                    .omega
                    .abort_initial_presence_sync(self.user_id as i64, self.session_id as i64);
                if matches!(
                    error,
                    InitialPresenceError::OrderingLost
                        | InitialPresenceError::AlreadyInProgress
                        | InitialPresenceError::InvalidSnapshot(_)
                        | InitialPresenceError::SubscriptionRejected(_)
                ) {
                    Err(error)
                } else {
                    // Omega can be unavailable without withholding the Iota
                    // state.  The response explicitly describes that its
                    // presence section is incomplete.
                    Ok(response
                        .add_typed_default(DataType::UserStates, DataValue::Array(Vec::new()))
                        .add_typed_default(
                            DataType::MissingUserIds,
                            DataValue::Array(
                                contacts
                                    .into_iter()
                                    .map(|id| DataValue::SignedNumber(id.into()))
                                    .collect(),
                            ),
                        )
                        .add_typed_default(
                            DataType::PresenceSnapshotComplete,
                            DataValue::Bool(false),
                        ))
                }
            }
        }
    }

    pub async fn from_general(general: Arc<GeneralConnection>, user_id: u64) -> Arc<Self> {
        Arc::new(Self {
            state: general.state.clone(),
            _mtp_connection: Some(general.mtp_connection.clone()),
            pub_key: Arc::new(RwLock::new(None)),
            rho_connection: general.rho_connection.clone(),
            is_open: Arc::new(RwLock::new(true)),
            sender: general.sender.clone(),
            receiver: general.receiver.clone(),
            user_id: user_id,
            session_id: general.session_id.read().await.clone(),
            client_version: general.client_version.read().await.clone(),
            message_slots: Arc::new(tokio::sync::Semaphore::new(32)),
            client_state_sync: Arc::new(Mutex::new(ClientStateSyncState::default())),
        })
    }
    pub fn start(self: Arc<Self>) {
        let self_clone = self.clone();
        tokio::spawn(async move {
            while let Ok(cv) = self_clone.receiver.receive().await {
                self_clone.clone().handle_message(cv).await;
            }
            self_clone.handle_close().await;
        });

        let self_clone2 = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            if self_clone2.get_rho_connection().await.is_none() {
                self_clone2
                    .send_error_response(0, CommunicationType::ErrorNoIota)
                    .await;
            }
        });
    }

    /// Get the user ID
    pub async fn get_user_id(&self) -> u64 {
        self.user_id
    }

    /// Get RhoConnection if available
    pub async fn get_rho_connection(&self) -> Option<Arc<RhoConnection>> {
        self.rho_connection.read().await.clone()
    }

    pub async fn set_rho_connection(&self, rho_connection: Arc<RhoConnection>) {
        *self.rho_connection.write().await = Some(rho_connection);
    }

    /// A membership snapshot can remove an account from an Iota while keeping
    /// its authenticated Omega connection alive.
    pub async fn clear_rho_connection(&self) {
        *self.rho_connection.write().await = None;
    }

    /// Send a CommunicationValue to the client
    pub async fn send_message(self: Arc<Self>, cv: &CommunicationValue) {
        if !*self.is_open.read().await {
            log_out!(
                self.user_id as i64,
                PrintType::Client,
                "Attempted to send message to a closed connection."
            );
            return;
        }
        log_cv_out!(PrintType::Client, &cv);
        let _ = self.sender.send(&cv).await;
    }

    /// Routes all post-initial-state messages behind the ClientStateAck barrier.
    /// The state response itself deliberately uses `send_message` directly.
    pub async fn send_or_buffer_post_initial_state(
        self: Arc<Self>,
        value: CommunicationValue,
    ) -> Result<(), ()> {
        let mut state = self.client_state_sync.lock().await;
        if matches!(state.phase, ClientStateSyncPhase::Idle) {
            drop(state);
            self.send_message(&value).await;
            return Ok(());
        }
        if state.overflowed || state.buffered_events.len() >= MAX_CLIENT_STATE_SYNC_BUFFERED_EVENTS
        {
            state.overflowed = true;
            return Err(());
        }
        state.buffered_events.push_back(value);
        Ok(())
    }

    async fn reset_client_state_sync(&self) {
        let mut state = self.client_state_sync.lock().await;
        *state = ClientStateSyncState::default();
    }

    /// Rolls back an ACK attempt that did not receive a successful response
    /// from Iota. Iota cannot have committed the acknowledgement in these
    /// paths, so the client may safely retry it.
    async fn restore_client_state_ack(&self) {
        let mut state = self.client_state_sync.lock().await;
        let ClientStateSyncPhase::Committing { device_id, version } = &state.phase else {
            return;
        };
        state.phase = ClientStateSyncPhase::AwaitingAck {
            device_id: device_id.clone(),
            version: *version,
        };
    }

    async fn drain_buffered_live_events(self: Arc<Self>) {
        loop {
            let next = {
                let mut state = self.client_state_sync.lock().await;
                match state.buffered_events.pop_front() {
                    Some(event) => Some(event),
                    None => {
                        state.phase = ClientStateSyncPhase::Idle;
                        state.overflowed = false;
                        None
                    }
                }
            };
            let Some(event) = next else {
                return;
            };
            self.clone().send_message(&event).await;
        }
    }

    pub async fn send_relay(&self, cv: &CommunicationValue) -> Result<(), String> {
        if !*self.is_open.read().await {
            return Err("client connection is closed".to_string());
        }
        self.sender
            .send(cv)
            .await
            .map_err(|error| error.to_string())
    }

    /// Handle incoming message from client
    pub async fn handle_message(self: Arc<Self>, cv: CommunicationValue) {
        let Ok(permit) = self.message_slots.clone().acquire_owned().await else {
            return;
        };
        tokio::spawn(async move {
            let _permit = permit;
            let message_id = match cv.require_id() {
                Ok(message_id) => message_id,
                Err(error) => {
                    log_err!(
                        self.user_id as i64,
                        PrintType::Client,
                        "Rejected malformed message: {}",
                        error
                    );
                    let response =
                        CommunicationValue::new(CommunicationType::ErrorInvalidData).without_id();
                    self.send_message(&response).await;
                    return;
                }
            };
            log_cv_in!(PrintType::Client, cv);

            let mut cv = cv;

            if cv.is_type(CommunicationType::Relay) {
                let next_hop = match cv.require_receiver() {
                    Ok(next_hop) => next_hop,
                    Err(error) => {
                        log_err!(
                            self.user_id as i64,
                            PrintType::Client,
                            "Rejected malformed relay: {}",
                            error
                        );
                        self.send_error_response(message_id, CommunicationType::ErrorInvalidData)
                            .await;
                        return;
                    }
                };
                cv = relay_router::ensure_relay_frame_id(cv);
                let result = match self.get_rho_connection().await {
                    Some(rho) => {
                        relay_router::route_relay(
                            &self.state,
                            RelaySource::Client {
                                iota_id: rho.get_iota_id().await,
                            },
                            cv,
                        )
                        .await
                    }
                    None => Err(relay_router::RelayRouteError::DestinationIotaNotLocal),
                };
                let response = match result {
                    Ok(response) => response.with_id(message_id),
                    Err(error) => {
                        log_err!(
                            self.user_id as i64,
                            PrintType::Client,
                            "Relay routing failed for destination Iota {}: {}",
                            next_hop,
                            error
                        );
                        relay_router::relay_route_error_response(
                            message_id,
                            relay_router::RouteTarget::from_wire_id(next_hop),
                            &error,
                        )
                    }
                };
                self.send_message(&response).await;
                return;
            }

            if cv.is_type(CommunicationType::Success) {
                if let Some(rho) = self.get_rho_connection().await {
                    rho.forward_relay_ack(self.user_id, message_id).await;
                }
                return;
            }

            if matches!(
                relay_router::message_security_class(&cv),
                relay_router::MessageSecurityClass::RelayOnly
            ) {
                self.send_error_response(message_id, CommunicationType::ErrorInvalidData)
                    .await;
                return;
            }

            if matches!(
                relay_router::message_security_class(&cv),
                relay_router::MessageSecurityClass::AuthenticatedPeerControl
            ) {
                let Some(rho) = self.get_rho_connection().await else {
                    self.send_error_response(message_id, CommunicationType::ErrorNoIota)
                        .await;
                    return;
                };
                match rho
                    .await_peer_control(&authenticated_peer_control_request(&cv, self.user_id))
                    .await
                {
                    Ok(response) => self.send_message(&response).await,
                    Err(_) => {
                        self.send_error_response(message_id, CommunicationType::ErrorInternal)
                            .await;
                    }
                }
                return;
            }

            // Compatibility for clients predating SetUserState.  The target
            // user fields, if present, are deliberately ignored: an
            // authenticated connection may only change its own state.
            if cv.is_type(CommunicationType::ClientChanged)
                && cv.get_data(DataType::UserState).is_some()
            {
                self.handle_set_user_state(
                    CommunicationValue::new(CommunicationType::ClientChanged)
                        .with_id(message_id)
                        .add_typed_default(
                            DataType::UserState,
                            cv.get_data(DataType::UserState)
                                .cloned()
                                .unwrap_or(DataValue::Null),
                        ),
                )
                .await;
                return;
            }

            // Handle call invites
            if cv.is_type(CommunicationType::CallInvite) {
                self.handle_call_invite(cv).await;
                return;
            }

            // Handle get call requests
            if cv.is_type(CommunicationType::CallToken) {
                self.handle_get_call(cv).await;
                return;
            }

            if cv.is_type(CommunicationType::CallData) {
                self.handle_get_call_data(cv).await;
                return;
            }

            if cv.is_type(CommunicationType::CallDisconnectUser) {
                self.handle_call_disconnect_user(cv).await;
                return;
            }

            if cv.is_type(CommunicationType::CallTimeoutUser) {
                self.handle_call_timeout_user(cv).await;
                return;
            }

            if cv.is_type(CommunicationType::CallSetAnonymousJoining) {
                self.handle_call_set_anonymous_joining(cv).await;
                return;
            }
            if cv.is_type(CommunicationType::EndCall) {
                self.handle_end_call(cv).await;
                return;
            }
            if matches!(
                cv.get_comm_type_enum(),
                Some(
                    CommunicationType::TAuthAuthorize
                        | CommunicationType::TAuthGrantList
                        | CommunicationType::TAuthGrantRevoke
                        | CommunicationType::TAuthGrantMetadataSet
                )
            ) {
                let Some(rho) = self.get_rho_connection().await else {
                    self.send_error_response(message_id, CommunicationType::ErrorNoIota)
                        .await;
                    return;
                };
                match rho
                    .get_iota_connection()
                    .clone()
                    .await_response(&cv.with_sender(self.user_id), Some(Duration::from_secs(20)))
                    .await
                {
                    Ok(response) => self.send_message(&response.with_id(message_id)).await,
                    Err(_) => {
                        self.send_error_response(message_id, CommunicationType::ErrorInternal)
                            .await
                    }
                }
                return;
            }
            if cv.is_type(CommunicationType::GetUserData) {
                if let Some(anonymous) = {
                    if let Some(user_id) = cv.get_data(DataType::UserId).as_signed_number() {
                        anonymous_manager::get_anonymous_user(user_id as u64).await
                    } else if let Some(username) = cv.get_data(DataType::Username).as_str() {
                        anonymous_manager::get_anonymous_user_by_name(username.to_string()).await
                    } else {
                        None
                    }
                } {
                    let response = CommunicationValue::new(CommunicationType::GetUserData)
                        .with_id(message_id)
                        .add_typed_default(
                            DataType::Username,
                            DataValue::Str(anonymous.get_user_name().await),
                        )
                        .add_typed_default(
                            DataType::UserId,
                            DataValue::SignedNumber(anonymous.get_user_id().into()),
                        )
                        .add_typed_default(
                            DataType::Display,
                            DataValue::Str(anonymous.get_display_name().await),
                        )
                        .add_typed_default(
                            DataType::Avatar,
                            DataValue::Str(anonymous.get_avatar().await),
                        )
                        .add_typed_default(
                            DataType::UserState,
                            DataValue::Str("online".to_string()),
                        );

                    self.send_message(&response).await;

                    return;
                }
            }

            if cv.is_type(CommunicationType::AccountStateRequest) {
                let can_request = {
                    let mut state = self.client_state_sync.lock().await;
                    if matches!(state.phase, ClientStateSyncPhase::Idle) {
                        state.phase = ClientStateSyncPhase::Requesting {
                            device_id: String::new(),
                        };
                        state.buffered_events.clear();
                        state.overflowed = false;
                        true
                    } else {
                        false
                    }
                };
                if !can_request {
                    self.send_error_response(message_id, CommunicationType::ErrorInvalidData)
                        .await;
                    return;
                }
                let Some(rho) = self.get_rho_connection().await else {
                    self.reset_client_state_sync().await;
                    self.send_error_response(message_id, CommunicationType::ErrorNoIota)
                        .await;
                    return;
                };
                let mut request = cv.clone();
                request.remove_data(DataType::SessionId);
                let request = request.with_sender(self.user_id).add_typed_default(
                    DataType::SessionId,
                    DataValue::UnsignedNumber(self.session_id.into()),
                );
                match rho
                    .get_iota_connection()
                    .clone()
                    .await_response(&request, Some(Duration::from_secs(20)))
                    .await
                {
                    Ok(response)
                        if response.is_type(CommunicationType::AccountStateSnapshot)
                            && response.receiver() == Some(self.user_id) =>
                    {
                        let response = match self
                            .compose_initial_client_state(
                                rho.get_iota_connection().clone(),
                                response,
                            )
                            .await
                        {
                            Ok(response) => response,
                            Err(_) => {
                                self.reset_client_state_sync().await;
                                self.send_error_response(
                                    message_id,
                                    CommunicationType::ErrorInternal,
                                )
                                .await;
                                return;
                            }
                        };
                        self.client_state_sync.lock().await.phase =
                            ClientStateSyncPhase::AwaitingAck {
                                device_id: String::new(),
                                version: 0,
                            };
                        self.clone().send_message(&response).await;
                    }
                    Ok(_) => {
                        self.reset_client_state_sync().await;
                        self.send_error_response(message_id, CommunicationType::ErrorInvalidData)
                            .await;
                    }
                    Err(_) => {
                        self.reset_client_state_sync().await;
                        self.send_error_response(message_id, CommunicationType::ErrorInternal)
                            .await;
                    }
                }
                return;
            }

            if cv.is_type(CommunicationType::AccountStateApplied) {
                let begin_commit = {
                    let mut state = self.client_state_sync.lock().await;
                    match &state.phase {
                        ClientStateSyncPhase::AwaitingAck { device_id, version } => {
                            if state.overflowed {
                                AckCommitStart::Overflowed
                            } else {
                                state.phase = ClientStateSyncPhase::Committing {
                                    device_id: device_id.clone(),
                                    version: *version,
                                };
                                AckCommitStart::Started
                            }
                        }
                        _ => AckCommitStart::Invalid,
                    }
                };
                match begin_commit {
                    AckCommitStart::Started => {}
                    AckCommitStart::Invalid => {
                        self.send_error_response(message_id, CommunicationType::ErrorInvalidData)
                            .await;
                        return;
                    }
                    AckCommitStart::Overflowed => {
                        self.state.omega.abort_initial_presence_sync(
                            self.user_id as i64,
                            self.session_id as i64,
                        );
                        self.reset_client_state_sync().await;
                        self.send_error_response(message_id, CommunicationType::ErrorInternal)
                            .await;
                        return;
                    }
                }
                let Some(rho) = self.get_rho_connection().await else {
                    self.restore_client_state_ack().await;
                    self.send_error_response(message_id, CommunicationType::ErrorNoIota)
                        .await;
                    return;
                };
                let mut request = cv.clone();
                request.remove_data(DataType::SessionId);
                let request = request.with_sender(self.user_id).add_typed_default(
                    DataType::SessionId,
                    DataValue::UnsignedNumber(self.session_id.into()),
                );
                if self.client_state_sync.lock().await.overflowed {
                    self.state
                        .omega
                        .abort_initial_presence_sync(self.user_id as i64, self.session_id as i64);
                    self.reset_client_state_sync().await;
                    self.send_error_response(message_id, CommunicationType::ErrorInternal)
                        .await;
                    return;
                }
                if self
                    .state
                    .omega
                    .finish_initial_presence_sync(self.user_id as i64, self.session_id as i64)
                    .await
                    .is_err()
                    || self.client_state_sync.lock().await.overflowed
                {
                    self.reset_client_state_sync().await;
                    self.send_error_response(message_id, CommunicationType::ErrorInternal)
                        .await;
                    return;
                }
                match rho
                    .get_iota_connection()
                    .clone()
                    .await_response(&request, Some(Duration::from_secs(20)))
                    .await
                {
                    Ok(response) => {
                        if response.is_type(CommunicationType::Success) {
                            if self.client_state_sync.lock().await.overflowed {
                                // Iota has committed its ACK, so a retry on
                                // this transport could incorrectly resume
                                // delivery. Reconnect to establish a fresh
                                // synchronization transaction.
                                self.close().await;
                                return;
                            }
                            self.client_state_sync.lock().await.phase =
                                ClientStateSyncPhase::Draining;
                            self.clone().send_message(&response).await;
                            self.clone().drain_buffered_live_events().await;
                        } else {
                            self.restore_client_state_ack().await;
                            self.send_message(&response).await;
                        }
                    }
                    Err(_) => {
                        self.restore_client_state_ack().await;
                        self.send_error_response(message_id, CommunicationType::ErrorInternal)
                            .await;
                    }
                }
                return;
            }

            if is_client_omega_operation(&cv) {
                let sender = self.get_user_id().await;
                self.handle_omega_forward(cv.with_sender(sender as u64))
                    .await;
                return;
            }

            let is_per_device_settings = cv.is_type(CommunicationType::SettingsSave)
                || cv.is_type(CommunicationType::SettingsLoad)
                || cv.is_type(CommunicationType::SettingsList);
            let is_global_settings = cv.is_type(CommunicationType::GlobalSettingsSave)
                || cv.is_type(CommunicationType::GlobalSettingsLoad);

            if is_per_device_settings || is_global_settings {
                let expected_session_id: i128 = self.session_id.into();
                let session_id = cv.get_data(DataType::SessionId).as_signed_number();

                if is_per_device_settings {
                    let Some(session_id) = session_id else {
                        let response = CommunicationValue::new(CommunicationType::ErrorInvalidData)
                            .with_id(message_id)
                            .with_receiver(self.user_id)
                            .add_typed_default(
                                DataType::Message,
                                DataValue::Str("Missing session_id".to_string()),
                            )
                            .add_typed_default(
                                DataType::SessionId,
                                DataValue::SignedNumber(expected_session_id),
                            );
                        self.send_message(&response).await;
                        return;
                    };

                    if session_id != expected_session_id {
                        let response = CommunicationValue::new(CommunicationType::ErrorInvalidData)
                            .with_id(message_id)
                            .with_receiver(self.user_id)
                            .add_typed_default(
                                DataType::Message,
                                DataValue::Str("session_id mismatch".to_string()),
                            )
                            .add_typed_default(
                                DataType::SessionId,
                                DataValue::SignedNumber(expected_session_id),
                            );
                        self.send_message(&response).await;
                        return;
                    }
                } else if let Some(session_id) = session_id {
                    if session_id != expected_session_id {
                        let response = CommunicationValue::new(CommunicationType::ErrorInvalidData)
                            .with_id(message_id)
                            .with_receiver(self.user_id)
                            .add_typed_default(
                                DataType::Message,
                                DataValue::Str("session_id mismatch".to_string()),
                            )
                            .add_typed_default(
                                DataType::SessionId,
                                DataValue::SignedNumber(expected_session_id),
                            );
                        self.send_message(&response).await;
                        return;
                    }
                } else {
                    cv = cv.add_typed_default(
                        DataType::SessionId,
                        DataValue::SignedNumber(expected_session_id),
                    );
                }
            }

            // Every Iota request is bound to the authenticated device.  A
            // caller may omit the field for compatibility, but can never
            // select a different device session.
            let expected_session_id = self.session_id as i128;
            if let Some(session_id) = cv.get_data(DataType::SessionId).as_signed_number() {
                if session_id != expected_session_id {
                    let response = CommunicationValue::new(CommunicationType::ErrorInvalidData)
                        .with_id(message_id)
                        .add_typed_default(
                            DataType::SessionId,
                            DataValue::SignedNumber(expected_session_id),
                        );
                    self.send_message(&response).await;
                    return;
                }
            } else {
                cv = cv.add_typed_default(
                    DataType::SessionId,
                    DataValue::SignedNumber(expected_session_id),
                );
            }

            log_err!(
                self.user_id as i64,
                PrintType::Client,
                "Rejected unsupported communication type {}",
                cv.get_type()
            );
            self.send_error_response(message_id, CommunicationType::ErrorInvalidData)
                .await;
        });
    }
    async fn handle_omega_forward(self: Arc<Self>, cv: CommunicationValue) {
        let Ok(request_id) = cv.require_id() else {
            return;
        };
        let delete_user = cv.is_type(CommunicationType::DeleteUser);
        let updated_key = if cv.is_type(CommunicationType::ChangeUserData) {
            match cv.get_data(DataType::PublicKey) {
                Some(DataValue::Str(key)) => PublicKeyBundle::from_base64(key).ok(),
                _ => None,
            }
        } else {
            None
        };
        match self.await_omega_response(cv).await {
            Ok(response_cv) => {
                let success = response_cv.is_type(CommunicationType::Success);
                if success && let Some(public_key) = updated_key {
                    self.state.omega.cache_authenticated_key(
                        AuthIdentity {
                            kind: AuthIdentityKind::Client,
                            id: self.user_id,
                        },
                        public_key,
                    );
                }
                self.clone().send_message(&response_cv).await;
                if success && delete_user {
                    self.close().await;
                }
            }
            Err(_) => {
                self.send_error_response(request_id, CommunicationType::ErrorInternal)
                    .await;
            }
        }
    }

    async fn await_omega_response(&self, cv: CommunicationValue) -> Result<CommunicationValue, ()> {
        self.state
            .omega
            .clone()
            .await_response(&cv.with_sender(self.user_id), Some(Duration::from_secs(20)))
            .await
            .map_err(|_| ())
    }

    async fn request_set_user_state(
        &self,
        cv: CommunicationValue,
    ) -> Result<CommunicationValue, CommunicationType> {
        let message_id = cv
            .require_id()
            .map_err(|_| CommunicationType::ErrorInvalidData)?;
        if !self.state.omega.is_ready().await {
            return Err(CommunicationType::ErrorInternal);
        }
        let Some(state) = cv
            .get_data(DataType::UserState)
            .as_str()
            .and_then(UserStatus::from_client_preference)
        else {
            return Err(CommunicationType::ErrorInvalidData);
        };
        let Some(_rho) = self.get_rho_connection().await else {
            return Err(CommunicationType::ErrorNoIota);
        };
        let request = CommunicationValue::new(CommunicationType::ChangeUserData)
            .with_id(message_id)
            .with_sender(self.user_id)
            .add_typed_default(DataType::OnlineStatus, DataValue::Str(state.to_string()));
        let response = self
            .state
            .omega
            .await_response(&request, Some(Duration::from_secs(20)))
            .await
            .map_err(|_| CommunicationType::ErrorInternal)?;
        if response.is_type(CommunicationType::Success) {
            return Ok(
                response.add_typed_default(DataType::UserState, DataValue::Str(state.to_string()))
            );
        }
        Ok(response)
    }

    async fn handle_set_user_state(self: Arc<Self>, cv: CommunicationValue) {
        let Ok(message_id) = cv.require_id() else {
            return;
        };
        match self.request_set_user_state(cv.clone()).await {
            Ok(response) => self.send_message(&response).await,
            Err(error_type) => self.send_error_response(message_id, error_type).await,
        }
    }

    /// Handle call invite
    async fn handle_call_invite(self: Arc<Self>, cv: CommunicationValue) {
        let Ok(message_id) = cv.require_id() else {
            return;
        };
        let receiver_id: i128 = cv.get_data(DataType::ReceiverId).as_number().unwrap_or(0);
        if receiver_id == 0 {
            self.send_error_response(message_id, CommunicationType::ErrorNoUserId)
                .await;
            return;
        }

        let call_id = match cv.get_data(DataType::CallId) {
            Some(DataValue::Str(id_str)) => match Uuid::parse_str(id_str) {
                Ok(id) => id,
                Err(_) => {
                    self.send_error_response(message_id, CommunicationType::ErrorInvalidCallId)
                        .await;
                    return;
                }
            },
            _ => {
                self.send_error_response(message_id, CommunicationType::ErrorNoCallId)
                    .await;
                return;
            }
        };

        let secret = match call_invite_secret_from_cv(&cv) {
            Some(secret) => secret,
            None => {
                self.send_error_response(message_id, CommunicationType::BadRequest)
                    .await;
                return;
            }
        };
        // Resolve the recipient before creating call state. Without the
        // recipient Iota, policy cannot be evaluated and delivery must fail.
        let target_rho = match self.state.rho.get_for_user(receiver_id as i64).await {
            Some(rho) => rho,
            None => {
                self.send_error_response(message_id, CommunicationType::ErrorNoIota)
                    .await;
                return;
            }
        };
        let sender_id = self.get_user_id().await as i64;
        let policy_request = CommunicationValue::new(CommunicationType::UserBlockCheck)
            .with_id(next_policy_request_id())
            .add_typed_default(
                DataType::SenderId,
                DataValue::SignedNumber(sender_id.into()),
            )
            .add_typed_default(DataType::ReceiverId, DataValue::SignedNumber(receiver_id));
        let policy_response = target_rho
            .get_iota_connection()
            .clone()
            .await_response(&policy_request, Some(Duration::from_secs(8)))
            .await;
        let blocked = match policy_response {
            Ok(response) if response.is_type(CommunicationType::UserBlockCheck) => {
                response.get_data(DataType::IsBlocked).as_bool()
            }
            _ => None,
        };
        match blocked {
            Some(true) => {
                self.send_error_response(message_id, CommunicationType::ErrorNotAuthenticated)
                    .await;
                return;
            }
            Some(false) => {}
            None => {
                self.send_error_response(message_id, CommunicationType::ErrorInternal)
                    .await;
                return;
            }
        }
        let invited = self
            .state
            .call_manager
            .add_invite(call_id, self.user_id, receiver_id as u64, secret.clone())
            .await;
        if let Err(error) = invited {
            self.send_error_response(message_id, call_error_type(&error))
                .await;
            return;
        }

        if !self
            .state
            .call_manager
            .should_forward_invite(self.user_id, receiver_id as u64)
        {
            let response = CommunicationValue::new(CommunicationType::Success).with_id(message_id);
            self.send_message(&response).await;
            return;
        }

        // Create and send call distribution message
        let forward = CommunicationValue::new(CommunicationType::CallInvite)
            .with_receiver(receiver_id as u64)
            .with_sender(sender_id as u64)
            .add_typed_default(DataType::CallSecret, secret.to_data_value())
            .add_typed_default(DataType::CallId, DataValue::Str(call_id.to_string()))
            .add_typed_default(
                DataType::ReceiverId,
                DataValue::SignedNumber(receiver_id.into()),
            )
            .add_typed_default(
                DataType::SenderId,
                DataValue::SignedNumber(sender_id.into()),
            )
            .add_typed_default(
                DataType::OmikronId,
                DataValue::SignedNumber((self.state.call_manager.owner_omikron_id as i64).into()),
            );

        if target_rho
            .send_to_local_user(receiver_id as u64, &forward)
            .await
            .is_err()
        {
            self.state
                .call_manager
                .rollback_invite(call_id, receiver_id as u64)
                .await;
            self.send_error_response(message_id, CommunicationType::ErrorNotFound)
                .await;
            return;
        }

        let response = CommunicationValue::new(CommunicationType::Success).with_id(message_id);
        self.send_message(&response).await;
    }

    /// Handle get call request
    async fn handle_get_call(self: Arc<Self>, cv: CommunicationValue) {
        let Ok(message_id) = cv.require_id() else {
            return;
        };
        let user_id = self.get_user_id().await;

        let call_id = match cv.get_data(DataType::CallId) {
            Some(DataValue::Str(id_str)) => match Uuid::parse_str(id_str) {
                Ok(id) => id,
                Err(_) => {
                    self.send_error_response(message_id, CommunicationType::ErrorInvalidCallId)
                        .await;
                    return;
                }
            },
            _ => {
                self.send_error_response(message_id, CommunicationType::ErrorNoCallId)
                    .await;
                return;
            }
        };

        let creator_value = cv.get_data(DataType::CallSecret);
        let creator =
            creator_value.and_then(crate::calls::call_group::CallSecretEnvelope::from_data_value);
        log::debug!(
            "CallToken call_id={call_id} user_id={user_id} owner_omikron_id={} exists_locally={} creator_secret_present={} creator_secret_parsed={}",
            self.state.call_manager.owner_omikron_id,
            self.state.call_manager.get_call(call_id).await.is_some(),
            creator_value.is_some(),
            creator.is_some(),
        );

        match self
            .state
            .call_manager
            .get_or_create_token(user_id, call_id, creator)
            .await
        {
            Ok(token) => {
                let response = CommunicationValue::new(CommunicationType::CallToken)
                    .with_id(message_id)
                    .with_receiver(user_id as u64)
                    .add_typed_default(DataType::CallToken, DataValue::Str(token))
                    .add_typed_default(
                        DataType::OmikronId,
                        DataValue::SignedNumber(
                            (self.state.call_manager.owner_omikron_id as i64).into(),
                        ),
                    )
                    .add_data(
                        DataTypeId(189),
                        DataValue::Str(
                            self.state
                                .config
                                .livekit
                                .as_ref()
                                .map(|config| config.client_url.clone())
                                .unwrap_or_default(),
                        ),
                    );
                match response {
                    Ok(response) => self.send_message(&response).await,
                    Err(_) => {
                        self.send_error_response(message_id, CommunicationType::ErrorInternal)
                            .await
                    }
                }
            }
            Err(error) => {
                log::warn!("Unable to create call token for {}: {}", call_id, error);
                let mut error_cv = CommunicationValue::new(call_error_type(&error))
                    .with_id(message_id)
                    .add_typed_default(DataType::CallId, DataValue::Str(call_id.to_string()));
                if let CallServiceError::TimedOut { until_ms } = error {
                    error_cv = error_cv.add_typed_default(
                        DataType::Timeout,
                        DataValue::SignedNumber(until_ms.into()),
                    );
                }
                self.send_message(&error_cv).await;
            }
        }
    }
    async fn handle_get_call_data(self: Arc<Self>, cv: CommunicationValue) {
        let Ok(message_id) = cv.require_id() else {
            return;
        };
        let user_id = self.get_user_id().await;

        let call_id = match cv.get_data(DataType::CallId) {
            Some(DataValue::Str(id_str)) => match Uuid::parse_str(id_str) {
                Ok(id) => id,
                Err(_) => {
                    self.send_error_response(message_id, CommunicationType::ErrorInvalidCallId)
                        .await;
                    return;
                }
            },
            _ => {
                self.send_error_response(message_id, CommunicationType::ErrorNoCallId)
                    .await;
                return;
            }
        };

        match self.state.call_manager.call_data(call_id, user_id).await {
            Ok(member_ids) => {
                let user_ids = member_ids
                    .into_iter()
                    .map(|id| DataValue::SignedNumber(id.into()))
                    .collect();
                let response = CommunicationValue::new(CommunicationType::CallData)
                    .with_id(message_id)
                    .with_receiver(user_id as u64)
                    .add_typed_default(DataType::UserIds, DataValue::Array(user_ids));
                self.send_message(&response).await;
            }
            Err(error) => {
                self.send_error_response(message_id, call_error_type(&error))
                    .await;
            }
        }
    }

    async fn handle_call_timeout_user(self: Arc<Self>, cv: CommunicationValue) {
        let Ok(message_id) = cv.require_id() else {
            return;
        };
        let Ok(call_id) = Uuid::from_str(cv.get_data(DataType::CallId).as_str().unwrap_or(""))
        else {
            self.send_error_response(message_id, CommunicationType::ErrorInvalidCallId)
                .await;
            return;
        };
        let user_id = cv
            .get_data(DataType::UserId)
            .as_signed_number()
            .unwrap_or(0);
        let untill = cv
            .get_data(DataType::Untill)
            .as_signed_number()
            .unwrap_or(0);

        if user_id <= 0 || untill <= 0 {
            self.send_error_response(message_id, CommunicationType::ErrorInvalidData)
                .await;
            return;
        }
        match self
            .state
            .call_manager
            .timeout_user(call_id, self.user_id, user_id as u64, untill as i64)
            .await
        {
            Ok(()) => {
                self.send_message(
                    &CommunicationValue::new(CommunicationType::Success).with_id(message_id),
                )
                .await
            }
            Err(error) => {
                self.send_error_response(message_id, call_error_type(&error))
                    .await
            }
        }
    }
    async fn handle_call_disconnect_user(self: Arc<Self>, cv: CommunicationValue) {
        let Ok(message_id) = cv.require_id() else {
            return;
        };
        let Ok(call_id) = Uuid::from_str(cv.get_data(DataType::CallId).as_str().unwrap_or(""))
        else {
            self.send_error_response(message_id, CommunicationType::ErrorInvalidCallId)
                .await;
            return;
        };
        let user_id = cv
            .get_data(DataType::UserId)
            .as_signed_number()
            .unwrap_or(0);

        if user_id <= 0 {
            self.send_error_response(message_id, CommunicationType::ErrorInvalidUserId)
                .await;
            return;
        }
        match self
            .state
            .call_manager
            .disconnect_user(call_id, self.user_id, user_id as u64)
            .await
        {
            Ok(()) => {
                self.send_message(
                    &CommunicationValue::new(CommunicationType::Success).with_id(message_id),
                )
                .await
            }
            Err(error) => {
                self.send_error_response(message_id, call_error_type(&error))
                    .await
            }
        }
    }
    async fn handle_call_set_anonymous_joining(self: Arc<Self>, cv: CommunicationValue) {
        let Ok(message_id) = cv.require_id() else {
            return;
        };
        let Ok(call_id) = Uuid::from_str(cv.get_data(DataType::CallId).as_str().unwrap_or(""))
        else {
            self.send_error_response(message_id, CommunicationType::ErrorInvalidCallId)
                .await;
            return;
        };
        let enable = cv.get_data(DataType::Enabled).as_bool().unwrap_or(true);

        let Some(call) = self.state.call_manager.get_call(call_id).await else {
            self.send_error_response(message_id, CommunicationType::ErrorNotFound)
                .await;
            return;
        };
        if call.member(self.user_id).await.is_none()
            || call
                .member(self.user_id)
                .await
                .map(|member| member.role == crate::calls::call_group::CallRole::Admin)
                != Some(true)
        {
            self.send_error_response(message_id, CommunicationType::ErrorNotAuthenticated)
                .await;
            return;
        }
        match call.set_anonymous_joining(enable, &self.state.omega).await {
            Ok(link) => {
                let mut response =
                    CommunicationValue::new(CommunicationType::CallSetAnonymousJoining)
                        .with_id(message_id)
                        .add_typed_default(DataType::CallId, DataValue::Str(call_id.to_string()))
                        .add_typed_default(DataType::Enabled, DataValue::Bool(enable));
                if let Some(link) = link {
                    response = response.add_typed_default(DataType::Link, DataValue::Str(link));
                }
                self.send_message(&response).await;
            }
            Err(_) => {
                self.send_error_response(message_id, CommunicationType::ErrorInternal)
                    .await
            }
        }
    }

    async fn handle_end_call(self: Arc<Self>, cv: CommunicationValue) {
        let Ok(message_id) = cv.require_id() else {
            return;
        };
        let Some(id) = cv
            .get_data(DataType::CallId)
            .and_then(|value| value.as_str())
        else {
            self.send_error_response(message_id, CommunicationType::ErrorNoCallId)
                .await;
            return;
        };
        let Ok(call_id) = Uuid::parse_str(id) else {
            self.send_error_response(message_id, CommunicationType::ErrorInvalidCallId)
                .await;
            return;
        };
        match self
            .state
            .call_manager
            .end_call(call_id, self.user_id)
            .await
        {
            Ok(()) => {
                self.send_message(
                    &CommunicationValue::new(CommunicationType::Success).with_id(message_id),
                )
                .await
            }
            Err(error) => {
                self.send_error_response(message_id, call_error_type(&error))
                    .await
            }
        }
    }

    /// Send error response
    async fn send_error_response(self: Arc<Self>, message_id: u32, error_type: CommunicationType) {
        let error = CommunicationValue::new(error_type).with_id(message_id);
        self.send_message(&error).await;
    }

    /// Close the connection
    pub async fn close(&self) {
        let mut is_open_guard = self.is_open.write().await;
        if !*is_open_guard {
            return;
        }
        *is_open_guard = false;

        let _ = self.sender.close();
    }

    /// Handle connection close
    pub async fn handle_close(self: Arc<Self>) {
        let user_id = self.get_user_id().await;
        if let Some(rho_conn) = self.state.rho.get_for_user(user_id as i64).await {
            rho_conn.close_client_connection(self.clone()).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        authenticated_peer_control_request, is_client_omega_operation,
        merge_initial_presence_snapshot,
    };
    use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};

    #[test]
    fn peer_control_requests_replace_a_client_supplied_sender() {
        let request = CommunicationValue::new(CommunicationType::SyncedSettingSet)
            .with_sender(99)
            .add_typed_default(DataType::UserId, DataValue::SignedNumber(99));

        let authenticated = authenticated_peer_control_request(&request, 7);

        assert_eq!(authenticated.sender(), Some(7));
        assert_eq!(
            authenticated
                .get_data(DataType::UserId)
                .and_then(|value| value.as_number()),
            Some(99)
        );
    }

    #[test]
    fn normal_clients_cannot_manage_invitations() {
        for operation in [
            CommunicationType::CreateUserInvitation,
            CommunicationType::ListUserInvitations,
            CommunicationType::RevokeUserInvitation,
        ] {
            assert!(!is_client_omega_operation(&CommunicationValue::new(
                operation
            )));
        }
    }

    #[test]
    fn initial_state_composition_preserves_iota_state_and_marks_missing_presence_incomplete() {
        let iota_state = CommunicationValue::new(CommunicationType::AccountStateSnapshot)
            .add_typed_default(DataType::VersionNumber, DataValue::SignedNumber(12));
        let presence = CommunicationValue::new(CommunicationType::GetStates)
            .add_typed_default(
                DataType::UserStates,
                DataValue::Array(vec![DataValue::Str("online".into())]),
            )
            .add_typed_default(
                DataType::MissingUserIds,
                DataValue::Array(vec![DataValue::SignedNumber(44)]),
            );

        let result = merge_initial_presence_snapshot(iota_state, presence);

        assert!(result.is_type(CommunicationType::AccountStateSnapshot));
        assert_eq!(
            result
                .get_data(DataType::VersionNumber)
                .and_then(DataValue::as_number),
            Some(12)
        );
        assert!(matches!(
            result.get_data(DataType::UserStates),
            Some(DataValue::Array(states)) if states.len() == 1
        ));
        assert_eq!(
            result.get_data(DataType::PresenceSnapshotComplete),
            Some(&DataValue::Bool(false))
        );
    }
}

// Implement Clone to make it easier to work with Arc<ClientConnection>
impl Clone for ClientConnection {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
            _mtp_connection: self._mtp_connection.clone(),
            sender: Arc::clone(&self.sender),
            receiver: Arc::clone(&self.receiver),
            user_id: self.user_id,
            session_id: self.session_id,
            client_version: self.client_version.clone(),
            pub_key: Arc::clone(&self.pub_key),
            rho_connection: Arc::clone(&self.rho_connection),
            is_open: Arc::clone(&self.is_open),
            message_slots: Arc::clone(&self.message_slots),
            client_state_sync: Arc::clone(&self.client_state_sync),
        }
    }
}
