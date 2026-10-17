use crate::anonymous_clients::anonymous_manager;
use crate::app_state::AppState;
use crate::calls::{call_group::call_invite_secret_from_cv, call_manager::CallServiceError};
use crate::data::user::UserStatus;
use crate::omega::omega_connection::{AuthIdentity, AuthIdentityKind, InitialPresenceError};
use crate::rho::connection::{
    GeneralConnection, MtpReceiver, MtpSender, OptionalDataValueExt, RequiredCommunicationFields,
    positive_data_i64,
};
use crate::rho::relay_router;
use crate::rho::rho_connection::RhoConnection;
use crate::util::logger::PrintType;
use crate::{log_cv_in, log_cv_out, log_err, log_out};
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataTypeId, DataValue};
use mtp::crypto::PublicKeyBundle;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use std::{collections::VecDeque, str::FromStr};
use tokio::sync::{Mutex, RwLock, oneshot};
use uuid::Uuid;

static NEXT_POLICY_REQUEST_ID: AtomicU32 = AtomicU32::new(1);
const MAX_CLIENT_STATE_SYNC_BUFFERED_EVENTS: usize = 1_024;

#[derive(Clone, Debug, Default)]
enum ClientStateSyncPhase {
    #[default]
    Idle,
    Requesting {
        #[expect(
            dead_code,
            reason = "retain requesting device context until sync acknowledgement"
        )]
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeviceClass {
    Desktop,
    Mobile,
    Web,
}

#[derive(Clone, Debug)]
pub struct SessionActivity {
    pub reported: bool,
    pub device_class: DeviceClass,
    pub notification_capable: bool,
}

impl Default for SessionActivity {
    fn default() -> Self {
        Self {
            reported: false,
            device_class: DeviceClass::Web,
            notification_capable: false,
        }
    }
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
        CallServiceError::ResourceLimit => CommunicationType::ErrorInternal,
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
    pub(super) is_open: Arc<RwLock<bool>>,
    message_slots: Arc<tokio::sync::Semaphore>,
    tasks: Arc<super::tasks::MessageTasks>,
    client_state_sync: Arc<Mutex<ClientStateSyncState>>,
    session_activity: Arc<RwLock<SessionActivity>>,
    pub(super) foreground_requests: Arc<Mutex<HashMap<u32, oneshot::Sender<bool>>>>,
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
            user_id,
            session_id: *general.session_id.read().await,
            client_version: general.client_version.read().await.clone(),
            message_slots: Arc::new(tokio::sync::Semaphore::new(32)),
            tasks: Arc::new(super::tasks::MessageTasks::new(
                general.shutdown.subscribe(),
                general.state.config.message_drain,
            )),
            client_state_sync: Arc::new(Mutex::new(ClientStateSyncState::default())),
            session_activity: Arc::new(RwLock::new(SessionActivity::default())),
            foreground_requests: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub async fn session_activity(&self) -> SessionActivity {
        self.session_activity.read().await.clone()
    }

    pub(crate) fn notify_connected(self: &Arc<Self>, iota_id: u64) {
        let client = self.clone();
        if let Err(error) = self.tasks.spawn(async move {
            if let Err(error) = client
                .state
                .omega
                .user_connected(
                    client.user_id as i64,
                    client.session_id as i64,
                    iota_id as i64,
                )
                .await
            {
                log_err!(
                    client.user_id as i64,
                    PrintType::Client,
                    "Client activation notification failed: {}",
                    error
                );
            }
        }) {
            log_err!(
                self.user_id as i64,
                PrintType::Client,
                "Client activation notification rejected: {}",
                error
            );
            self.sender.close();
        }
    }

    pub async fn foreground(&self) -> bool {
        let id = NEXT_POLICY_REQUEST_ID.fetch_add(1, Ordering::Relaxed) | 0x8000_0000;
        let (sender, receiver) = oneshot::channel();
        self.foreground_requests.lock().await.insert(id, sender);
        let request = CommunicationValue::new(CommunicationType::SessionActivitySet).with_id(id);
        let foreground = tokio::time::timeout(Duration::from_secs(1), async {
            self.send_relay(&request).await.ok()?;
            receiver.await.ok()
        })
        .await
        .ok()
        .flatten()
        .unwrap_or(false);
        self.foreground_requests.lock().await.remove(&id);
        foreground
    }
    pub async fn run(self: Arc<Self>) {
        let self_clone2 = self.clone();
        if let Err(error) = self.tasks.spawn_cancellable(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            if self_clone2.get_rho_connection().await.is_none() {
                self_clone2
                    .send_error_response(0, CommunicationType::ErrorNoIota)
                    .await;
            }
        }) {
            log_err!(
                self.user_id as i64,
                PrintType::Client,
                "Client route check rejected: {}",
                error
            );
            self.close().await;
        }
        while let Some(Ok(cv)) = self
            .tasks
            .while_connected(&self.receiver, self.receiver.receive())
            .await
        {
            self.clone().handle_message(cv).await;
        }
        self.tasks.drain().await;
        self.close().await;
        self.reset_client_state_sync().await;
        self.clone().handle_close().await;
    }

    /// Get the user ID
    pub async fn get_user_id(&self) -> u64 {
        self.user_id
    }

    /// Get RhoConnection if available
    pub async fn get_rho_connection(&self) -> Option<Arc<RhoConnection>> {
        let rho = self.rho_connection.read().await.clone()?;
        let current = self.state.rho.get_for_user(self.user_id as i64).await?;
        Arc::ptr_eq(&rho, &current).then_some(rho)
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
        let _ = self.sender.send(cv).await;
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
        if !*self.is_open.read().await {
            return;
        }
        let Some(Ok(permit)) = self
            .tasks
            .while_connected(&self.receiver, self.message_slots.clone().acquire_owned())
            .await
        else {
            return;
        };
        let tasks = self.tasks.clone();
        let connection = self.clone();
        if let Err(error) = tasks.spawn(async move {
            let _permit = permit;
            if !*self.is_open.read().await {
                return;
            }
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

            if cv.is_type(CommunicationType::RegisteringClientAuthenticate) {
                self.send_error_response(message_id, CommunicationType::ErrorNotAuthenticated)
                    .await;
                return;
            }

            let mut cv = cv;

            if matches!(
                cv.get_comm_type_enum(),
                Some(
                    CommunicationType::ProvisioningBindAccount
                        | CommunicationType::QrProvisioningConfirm
                        | CommunicationType::ProvisioningCredential
                        | CommunicationType::ProvisioningCancel
                )
            ) {
                if let Err(reason) =
                    super::provisioning_connection::handle_authenticated_login(&self, &cv).await
                {
                    log_err!(
                        self.user_id as i64,
                        PrintType::Client,
                        "QR login rejected: {}",
                        reason
                    );
                    self.sender
                        .send(
                            &CommunicationValue::new(CommunicationType::ErrorInvalidData)
                                .with_id(message_id)
                                .add_typed_default(
                                    DataType::ErrorType,
                                    DataValue::Str(reason.into()),
                                ),
                        )
                        .await
                        .ok();
                }
                return;
            }

            if cv.is_type(CommunicationType::Relay) {
                // Client authentication does not establish a canonical Iota source.
                self.send_error_response(message_id, CommunicationType::ErrorNotAuthenticated)
                    .await;
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
                    | relay_router::MessageSecurityClass::Unsupported
            ) {
                self.send_error_response(message_id, CommunicationType::ErrorInvalidData)
                    .await;
                return;
            }

            if cv.is_type(CommunicationType::SessionActivitySet) {
                if let Some(reply) = self.foreground_requests.lock().await.remove(&message_id) {
                    let _ =
                        reply.send(cv.get_data(DataType::Foreground).as_bool().unwrap_or(false));
                    return;
                }
                let device_class = match cv.get_data(DataType::DeviceClass).as_str() {
                    Some("desktop") => DeviceClass::Desktop,
                    Some("mobile") => DeviceClass::Mobile,
                    Some("web") => DeviceClass::Web,
                    _ => {
                        self.send_error_response(message_id, CommunicationType::ErrorInvalidData)
                            .await;
                        return;
                    }
                };
                let Some(notification_capable) =
                    cv.get_data(DataType::NotificationCapable).as_bool()
                else {
                    self.send_error_response(message_id, CommunicationType::ErrorInvalidData)
                        .await;
                    return;
                };
                *self.session_activity.write().await = SessionActivity {
                    reported: true,
                    device_class,
                    notification_capable,
                };
                self.send_message(
                    &CommunicationValue::new(CommunicationType::Success).with_id(message_id),
                )
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
                let generation = self
                    .state
                    .rho
                    .user_route_generation(self.user_id as i64, &rho);
                if generation.is_none() || !rho.owns_client(&self) {
                    return;
                }
                let mut request = authenticated_peer_control_request(&cv, self.user_id);
                if relay_router::is_relay_receipt_page(&request) {
                    request.remove_data(DataType::SessionId);
                    request = request.add_typed_default(
                        DataType::SessionId,
                        DataValue::UnsignedNumber(self.session_id.into()),
                    );
                }
                match rho.await_peer_control(&request).await {
                    Ok(response) => {
                        // Assignment publication needs this write lock. Keep the
                        // authorization check valid through account-data delivery.
                        let _route = self.rho_connection.read().await;
                        // Reassignment away and back must not release an old page or
                        // snapshot, nor may a replaced session receive account data.
                        if self
                            .state
                            .rho
                            .user_route_generation(self.user_id as i64, &rho)
                            == generation
                            && rho.owns_client(&self)
                            && (!relay_router::is_relay_receipt_page(&response)
                                || response.receiver() == Some(self.user_id))
                        {
                            self.clone().send_message(&response).await;
                        }
                    }
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
            if cv.is_type(CommunicationType::CallReserve) {
                let result = self.state.call_manager.reserve(self.user_id).await;
                match result {
                    Ok(id) => {
                        self.clone()
                            .send_message(
                                &CommunicationValue::new(CommunicationType::CallReserve)
                                    .with_id(message_id)
                                    .add_typed_default(
                                        DataType::CallId,
                                        DataValue::Str(id.to_string()),
                                    )
                                    .add_typed_default(
                                        DataType::OmikronId,
                                        DataValue::SignedNumber(
                                            (self.state.call_manager.owner_omikron_id as i64)
                                                .into(),
                                        ),
                                    ),
                            )
                            .await
                    }
                    Err(error) => {
                        self.send_error_response(message_id, call_error_type(&error))
                            .await
                    }
                }
                return;
            }
            if cv.is_type(CommunicationType::CallActivate) {
                self.handle_call_activate(cv).await;
                return;
            }
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
                    CommunicationType::PasswordEnrollmentStart
                        | CommunicationType::PasswordEnrollmentFinish
                        | CommunicationType::PasswordEnrollmentStatus
                        | CommunicationType::PasswordEnrollmentDisable
                )
            ) {
                let Some(rho) = self.get_rho_connection().await else {
                    self.send_error_response(message_id, CommunicationType::ErrorNoIota)
                        .await;
                    return;
                };
                if cv.receiver() != Some(rho.get_iota_id().await)
                    || cv.payload().as_encrypted().is_none()
                {
                    self.send_error_response(message_id, CommunicationType::ErrorInvalidData)
                        .await;
                    return;
                }
                match rho
                    .get_iota_connection()
                    .clone()
                    .await_response(&cv, Some(Duration::from_secs(30)))
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
            if cv.is_type(CommunicationType::GetUserData)
                && let Some(anonymous) = {
                    if let Some(user_id) = cv
                        .get_data(DataType::UserId)
                        .as_signed_number()
                        .and_then(|id| u64::try_from(id).ok())
                        .filter(|id| *id > 0)
                    {
                        anonymous_manager::get_anonymous_user(user_id).await
                    } else if let Some(username) = cv.get_data(DataType::Username).as_str() {
                        anonymous_manager::get_anonymous_user_by_name(username.to_string()).await
                    } else {
                        None
                    }
                }
            {
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
                    .add_typed_default(DataType::UserState, DataValue::Str("online".to_string()));

                self.send_message(&response).await;

                return;
            }

            if cv.is_type(CommunicationType::AccountStateRequest) {
                let device_class = match cv.get_data(DataType::DeviceClass).as_str() {
                    Some("desktop") => Some(DeviceClass::Desktop),
                    Some("mobile") => Some(DeviceClass::Mobile),
                    Some("web") => Some(DeviceClass::Web),
                    _ => None,
                };
                let notification_capable = cv.get_data(DataType::NotificationCapable).as_bool();
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
                if let (Some(device_class), Some(notification_capable)) =
                    (device_class, notification_capable)
                {
                    *self.session_activity.write().await = SessionActivity {
                        reported: true,
                        device_class,
                        notification_capable,
                    };
                }
                let Some(rho) = self.get_rho_connection().await else {
                    self.reset_client_state_sync().await;
                    self.send_error_response(message_id, CommunicationType::ErrorNoIota)
                        .await;
                    return;
                };
                let generation = self
                    .state
                    .rho
                    .user_route_generation(self.user_id as i64, &rho);
                if generation.is_none() || !rho.owns_client(&self) {
                    self.reset_client_state_sync().await;
                    return;
                }
                let mut request = cv.clone();
                request.remove_data(DataType::SessionId);
                request.remove_data(DataType::DeviceClass);
                request.remove_data(DataType::NotificationCapable);
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
                        let _route = self.rho_connection.read().await;
                        if self
                            .state
                            .rho
                            .user_route_generation(self.user_id as i64, &rho)
                            != generation
                            || !rho.owns_client(&self)
                        {
                            self.reset_client_state_sync().await;
                            return;
                        }
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
        }) {
            log_err!(
                connection.user_id as i64,
                PrintType::Client,
                "Client message task rejected: {}",
                error
            );
            connection.close().await;
        }
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
    async fn handle_call_activate(self: Arc<Self>, cv: CommunicationValue) {
        let Ok(message_id) = cv.require_id() else {
            return;
        };
        let Some(id) = cv
            .get_data(DataType::CallId)
            .as_str()
            .and_then(|id| Uuid::parse_str(id).ok())
        else {
            self.send_error_response(message_id, CommunicationType::ErrorInvalidCallId)
                .await;
            return;
        };
        let Some(secret) = call_invite_secret_from_cv(&cv) else {
            self.send_error_response(message_id, CommunicationType::ErrorInvalidData)
                .await;
            return;
        };
        let created_at = match self
            .state
            .call_manager
            .reservation_created_at(self.user_id, id)
            .await
        {
            Ok(created_at) => created_at,
            Err(error) => {
                self.send_error_response(message_id, call_error_type(&error))
                    .await;
                return;
            }
        };
        if self
            .store_call_envelope(self.user_id, self.user_id, id, created_at, &secret)
            .await
            .is_err()
        {
            self.send_error_response(message_id, CommunicationType::ErrorNoIota)
                .await;
            return;
        }
        match self
            .state
            .call_manager
            .activate(self.user_id, id, created_at)
            .await
        {
            Ok(token) => {
                let created_at = self
                    .state
                    .call_manager
                    .get_call(id)
                    .await
                    .map(|group| group.created_at_ms)
                    .unwrap_or_default();
                let mut response = CommunicationValue::new(CommunicationType::CallActivate)
                    .with_id(message_id)
                    .add_typed_default(DataType::CallToken, DataValue::Str(token))
                    .add_typed_default(
                        DataType::CreatedAt,
                        DataValue::SignedNumber(created_at.into()),
                    )
                    .add_typed_default(
                        DataType::OmikronId,
                        DataValue::SignedNumber(
                            (self.state.call_manager.owner_omikron_id as i64).into(),
                        ),
                    );
                response = response
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
                    )
                    .expect("CallEndpoint is defined in the type map");
                self.send_message(&response).await;
            }
            Err(error) => {
                self.send_error_response(message_id, call_error_type(&error))
                    .await
            }
        }
    }

    async fn store_call_envelope(
        &self,
        recipient: u64,
        inviter: u64,
        id: Uuid,
        created_at: i64,
        secret: &crate::calls::call_group::CallSecretEnvelope,
    ) -> Result<(), ()> {
        let rho = self
            .state
            .rho
            .get_for_user(recipient as i64)
            .await
            .ok_or(())?;
        let response = rho
            .get_iota_connection()
            .clone()
            .await_response(
                &CommunicationValue::new(CommunicationType::CallEnvelopeStore)
                    .with_id(next_policy_request_id())
                    .add_typed_default(
                        DataType::ReceiverId,
                        DataValue::SignedNumber((recipient as i64).into()),
                    )
                    .add_typed_default(
                        DataType::CallInviterId,
                        DataValue::SignedNumber((inviter as i64).into()),
                    )
                    .add_typed_default(DataType::CallId, DataValue::Str(id.to_string()))
                    .add_typed_default(
                        DataType::CreatedAt,
                        DataValue::SignedNumber(created_at.into()),
                    )
                    .add_typed_default(DataType::CallSecret, secret.to_data_value()),
                Some(Duration::from_secs(20)),
            )
            .await
            .map_err(|_| ())?;
        response
            .is_type(CommunicationType::Success)
            .then_some(())
            .ok_or(())
    }

    async fn get_call_envelope(
        &self,
        recipient: u64,
        id: Uuid,
    ) -> Result<crate::calls::call_group::CallSecretEnvelope, ()> {
        let rho = self
            .state
            .rho
            .get_for_user(recipient as i64)
            .await
            .ok_or(())?;
        let response = rho
            .get_iota_connection()
            .clone()
            .await_response(
                &CommunicationValue::new(CommunicationType::CallEnvelopeGet)
                    .with_id(next_policy_request_id())
                    .add_typed_default(
                        DataType::ReceiverId,
                        DataValue::SignedNumber((recipient as i64).into()),
                    )
                    .add_typed_default(DataType::CallId, DataValue::Str(id.to_string())),
                Some(Duration::from_secs(8)),
            )
            .await
            .map_err(|_| ())?;
        if !response.is_type(CommunicationType::CallEnvelopeGet) {
            return Err(());
        }
        crate::calls::call_group::CallSecretEnvelope::from_data_value(
            response.get_data(DataType::CallSecret).ok_or(())?,
        )
        .ok_or(())
    }

    async fn handle_call_invite(self: Arc<Self>, cv: CommunicationValue) {
        let Ok(message_id) = cv.require_id() else {
            return;
        };
        let Ok(receiver_id) = positive_data_i64(&cv, DataType::ReceiverId, "receiver_id") else {
            self.send_error_response(message_id, CommunicationType::ErrorNoUserId)
                .await;
            return;
        };

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
        let target_rho = match self.state.rho.get_for_user(receiver_id).await {
            Some(rho) => rho,
            None => {
                self.send_error_response(message_id, CommunicationType::ErrorNoIota)
                    .await;
                return;
            }
        };
        let sender_id = self.get_user_id().await as i64;
        let Some(sender_rho) = self.state.rho.get_for_user(sender_id).await else {
            self.send_error_response(message_id, CommunicationType::ErrorNoIota)
                .await;
            return;
        };
        let contact_response = sender_rho
            .get_iota_connection()
            .clone()
            .await_response(
                &CommunicationValue::new(CommunicationType::CallContactCheck)
                    .with_id(next_policy_request_id())
                    .add_typed_default(
                        DataType::SenderId,
                        DataValue::SignedNumber(sender_id.into()),
                    )
                    .add_typed_default(
                        DataType::ReceiverId,
                        DataValue::SignedNumber(receiver_id.into()),
                    ),
                Some(Duration::from_secs(20)),
            )
            .await;
        if !matches!(contact_response, Ok(ref response) if response.is_type(CommunicationType::CallContactCheck) && response.get_data(DataType::IsBlocked).as_bool() == Some(true))
        {
            self.send_error_response(message_id, CommunicationType::ErrorNotFound)
                .await;
            return;
        }
        let policy_request = CommunicationValue::new(CommunicationType::UserBlockCheck)
            .with_id(next_policy_request_id())
            .add_typed_default(
                DataType::SenderId,
                DataValue::SignedNumber(sender_id.into()),
            )
            .add_typed_default(
                DataType::ReceiverId,
                DataValue::SignedNumber(receiver_id.into()),
            );
        let policy_response = target_rho
            .get_iota_connection()
            .clone()
            .await_response(&policy_request, Some(Duration::from_secs(20)))
            .await;
        let blocked = match &policy_response {
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
                crate::log_event!(
                    0,
                    crate::util::logger::PrintType::Call,
                    crate::util::logger::LogLevel::Warn,
                    "call.invite_block_check_unavailable",
                    "call_id={} sender_user_id={} recipient_user_id={} response={:?}",
                    call_id,
                    sender_id,
                    receiver_id,
                    policy_response
                        .as_ref()
                        .map(|response| response.get_type_name())
                        .map_err(|error| error.as_str())
                );
                self.send_error_response(message_id, CommunicationType::ErrorNoIota)
                    .await;
                return;
            }
        }
        let Some(group) = self.state.call_manager.get_call(call_id).await else {
            self.send_error_response(message_id, CommunicationType::ErrorNotFound)
                .await;
            return;
        };
        let relation = match self
            .state
            .call_manager
            .check_invite(call_id, self.user_id, receiver_id as u64)
            .await
        {
            Ok((_, relation)) => relation,
            Err(error) => {
                self.send_error_response(message_id, call_error_type(&error))
                    .await;
                return;
            }
        };
        let forward_secret = match relation {
            crate::calls::call_manager::InviteRelation::New => {
                if self
                    .store_call_envelope(
                        receiver_id as u64,
                        self.user_id,
                        call_id,
                        group.created_at_ms,
                        &secret,
                    )
                    .await
                    .is_err()
                {
                    self.send_error_response(message_id, CommunicationType::ErrorNoIota)
                        .await;
                    return;
                }
                if let Err(error) = self
                    .state
                    .call_manager
                    .add_invite(call_id, self.user_id, receiver_id.unsigned_abs())
                    .await
                {
                    self.send_error_response(message_id, call_error_type(&error))
                        .await;
                    return;
                }
                secret
            }
            relation => {
                // Members and pending invitees already hold an envelope on
                // their Iota. A re-invite must replay exactly that ciphertext,
                // not freshly randomized bytes they cannot decrypt.
                if relation == crate::calls::call_manager::InviteRelation::Pending {
                    // Refresh the recorded inviter so the badge names the latest inviter.
                    if let Err(error) = self
                        .state
                        .call_manager
                        .add_invite(call_id, self.user_id, receiver_id.unsigned_abs())
                        .await
                    {
                        self.send_error_response(message_id, call_error_type(&error))
                            .await;
                        return;
                    }
                }
                match self.get_call_envelope(receiver_id as u64, call_id).await {
                    Ok(stored) => stored,
                    Err(()) => {
                        self.send_error_response(message_id, CommunicationType::ErrorNoIota)
                            .await;
                        return;
                    }
                }
            }
        };

        if !self
            .state
            .call_manager
            .should_forward_invite(self.user_id, receiver_id.unsigned_abs())
        {
            let response = CommunicationValue::new(CommunicationType::Success).with_id(message_id);
            self.send_message(&response).await;
            return;
        }

        // Create and send call distribution message
        let forward = CommunicationValue::new(CommunicationType::CallInvite)
            .with_id(next_policy_request_id())
            .with_receiver(receiver_id.unsigned_abs())
            .with_sender(sender_id as u64)
            .add_typed_default(DataType::CallSecret, forward_secret.to_data_value())
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

        let response = CommunicationValue::new(CommunicationType::Success).with_id(message_id);
        self.clone().send_message(&response).await;

        // The invitation is durable. A stalled client must not delay the sender's acknowledgement.
        if let Err(error) = self.tasks.spawn_cancellable(async move {
            match tokio::time::timeout(
                Duration::from_secs(8),
                target_rho.send_to_local_user(receiver_id.unsigned_abs(), &forward),
            )
            .await
            {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => crate::log_event!(
                    0,
                    crate::util::logger::PrintType::Call,
                    crate::util::logger::LogLevel::Warn,
                    "call.invite_live_delivery_failed",
                    "call_id={} recipient_user_id={} error={}",
                    call_id,
                    receiver_id,
                    error
                ),
                Err(_) => crate::log_event!(
                    0,
                    crate::util::logger::PrintType::Call,
                    crate::util::logger::LogLevel::Warn,
                    "call.invite_live_delivery_failed",
                    "call_id={} recipient_user_id={} error=timeout",
                    call_id,
                    receiver_id
                ),
            }
        }) {
            log_err!(
                self.user_id as i64,
                PrintType::Client,
                "Call invitation delivery task rejected: {}",
                error
            );
        }
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

        let Some(group) = self.state.call_manager.get_call(call_id).await else {
            self.send_error_response(message_id, CommunicationType::ErrorNotFound)
                .await;
            return;
        };
        if !group.is_related(user_id).await
            || self.get_call_envelope(user_id, call_id).await.is_err()
        {
            self.send_error_response(message_id, CommunicationType::ErrorNotFound)
                .await;
            return;
        }
        let pending = group.member(user_id).await.is_none();
        if pending {
            let inviter = group
                .state
                .read()
                .await
                .pending_invites
                .get(&user_id)
                .map(|invite| invite.inviter_id);
            let Some(inviter) = inviter else {
                self.send_error_response(message_id, CommunicationType::ErrorNotFound)
                    .await;
                return;
            };
            let Some(rho) = self.state.rho.get_for_user(user_id as i64).await else {
                self.send_error_response(message_id, CommunicationType::ErrorNotFound)
                    .await;
                return;
            };
            let response = rho
                .get_iota_connection()
                .clone()
                .await_response(
                    &CommunicationValue::new(CommunicationType::CallContactAccept)
                        .with_id(next_policy_request_id())
                        .add_typed_default(
                            DataType::ReceiverId,
                            DataValue::SignedNumber(user_id.into()),
                        )
                        .add_typed_default(
                            DataType::CallInviterId,
                            DataValue::SignedNumber(inviter.into()),
                        ),
                    Some(Duration::from_secs(8)),
                )
                .await;
            if !matches!(response, Ok(response) if response.is_type(CommunicationType::Success)) {
                self.send_error_response(message_id, CommunicationType::ErrorNotFound)
                    .await;
                return;
            }
        }

        match self
            .state
            .call_manager
            .get_call_token(user_id, call_id)
            .await
        {
            Ok(token) => {
                let created_at = self
                    .state
                    .call_manager
                    .get_call(call_id)
                    .await
                    .map(|group| group.created_at_ms)
                    .unwrap_or_default();
                let response = CommunicationValue::new(CommunicationType::CallToken)
                    .with_id(message_id)
                    .with_receiver(user_id as u64)
                    .add_typed_default(DataType::CallToken, DataValue::Str(token))
                    .add_typed_default(
                        DataType::CreatedAt,
                        DataValue::SignedNumber(created_at.into()),
                    )
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
                crate::log_event!(
                    0,
                    crate::util::logger::PrintType::Call,
                    crate::util::logger::LogLevel::Warn,
                    "call.token_failed",
                    "message_id={} call_id={} user_id={} error={}",
                    message_id,
                    call_id,
                    user_id,
                    error
                );
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

        let secret = match self.get_call_envelope(user_id, call_id).await {
            Ok(secret) => secret,
            Err(()) => {
                self.send_error_response(message_id, CommunicationType::ErrorNotFound)
                    .await;
                return;
            }
        };
        match self.state.call_manager.call_data(call_id, user_id).await {
            Ok((member_ids, created_at)) => {
                let user_ids = member_ids
                    .into_iter()
                    .map(|id| DataValue::SignedNumber(id.into()))
                    .collect();
                let response = CommunicationValue::new(CommunicationType::CallData)
                    .with_id(message_id)
                    .with_receiver(user_id as u64)
                    .add_typed_default(DataType::UserIds, DataValue::Array(user_ids))
                    .add_typed_default(
                        DataType::CreatedAt,
                        DataValue::SignedNumber(created_at.into()),
                    )
                    .add_typed_default(DataType::CallSecret, secret.to_data_value());
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
        let (Ok(user_id), Ok(untill)) = (
            positive_data_i64(&cv, DataType::UserId, "user_id"),
            positive_data_i64(&cv, DataType::Untill, "untill"),
        ) else {
            self.send_error_response(message_id, CommunicationType::ErrorInvalidData)
                .await;
            return;
        };
        match self
            .state
            .call_manager
            .timeout_user(call_id, self.user_id, user_id.unsigned_abs(), untill)
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
        let Ok(user_id) = positive_data_i64(&cv, DataType::UserId, "user_id") else {
            self.send_error_response(message_id, CommunicationType::ErrorInvalidUserId)
                .await;
            return;
        };
        let previous = self.state.call_manager.get_call(call_id).await;
        match self
            .state
            .call_manager
            .disconnect_user(call_id, self.user_id, user_id.unsigned_abs())
            .await
        {
            Ok(()) => {
                if self.state.call_manager.get_call(call_id).await.is_none() {
                    self.notify_call_ended(call_id, previous).await;
                }
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
    async fn notify_call_ended(
        &self,
        id: Uuid,
        group: Option<Arc<crate::calls::call_group::CallGroup>>,
    ) {
        let Some(group) = group else {
            return;
        };
        let state = group.state.read().await;
        let users = state
            .members
            .keys()
            .chain(state.pending_invites.keys())
            .copied()
            .collect::<std::collections::BTreeSet<_>>();
        for user in users {
            if let Some(rho) = self.state.rho.get_for_user(user as i64).await {
                let event = CommunicationValue::new(CommunicationType::CallEnded)
                    .with_receiver(user)
                    .add_typed_default(DataType::CallId, DataValue::Str(id.to_string()));
                let _ = rho.send_to_local_user(user, &event).await;
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
        match self
            .state
            .call_manager
            .set_anonymous_joining(call_id, enable, &self.state.omega)
            .await
        {
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
            Err(error) => {
                self.send_error_response(message_id, call_error_type(&error))
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
        let previous = self.state.call_manager.get_call(call_id).await;
        match self
            .state
            .call_manager
            .end_call(call_id, self.user_id)
            .await
        {
            Ok(()) => {
                self.notify_call_ended(call_id, previous).await;
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
        let mut requests = self.foreground_requests.lock().await;
        if !*is_open_guard {
            return;
        }
        *is_open_guard = false;
        requests.clear();

        self.sender.close();
    }

    /// Handle connection close
    pub async fn handle_close(self: Arc<Self>) {
        let provisioning = self
            .state
            .provisioning
            .for_participant(self.session_id)
            .ok();
        let route = self.rho_connection.read().await.clone();
        if let Some(rho_conn) = route {
            if !rho_conn.close_client_connection(self.clone()).await {
                return;
            }
        } else {
            let _mutation = self.state.rho.mutation_guard().await;
            if self.state.rho.has_replacement_client(&self) {
                return;
            }
            self.cleanup_local();
        }
        if let Some(session) = provisioning
            && let Some(sender) = session.contact.and_then(|peer| peer.sender.upgrade())
        {
            super::tasks::finish_cleanup(self.state.config.cleanup_timeout, async {
                let _ = sender
                    .send(
                        &CommunicationValue::new(CommunicationType::ProvisioningCancel)
                            .add_typed_default(
                                DataType::Uuid,
                                DataValue::Str(session.id.to_string()),
                            ),
                    )
                    .await;
            })
            .await;
        }
    }

    pub(crate) fn cleanup_local(&self) {
        self.state
            .omega
            .invalidate_client_presence(self.user_id as i64, self.session_id as i64);
        self.state.provisioning.remove_participant(self.session_id);
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
            tasks: Arc::clone(&self.tasks),
            client_state_sync: Arc::clone(&self.client_state_sync),
            session_activity: Arc::clone(&self.session_activity),
            foreground_requests: Arc::clone(&self.foreground_requests),
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

    #[tokio::test]
    async fn local_cleanup_outlives_notification_budget_without_omega() {
        use crate::{
            provisioning::session::{
                ProvisioningMethod, ProvisioningParticipant, ProvisioningRole,
            },
            rho::{
                connection::{GeneralConnection, admission_engine},
                iota_connection::IotaConnection,
                rho_connection::RhoConnection,
                test_support,
            },
        };
        use std::{sync::Arc, time::Duration};

        let mut state = test_support::state();
        Arc::get_mut(&mut state).unwrap().config.cleanup_timeout = Duration::from_millis(10);
        assert!(!state.omega.is_ready().await);
        let (host, peer, transport) = test_support::guest("anonymous").await;
        let general =
            GeneralConnection::admit(transport, state.clone(), &admission_engine()).unwrap();
        *general.session_id.write().await = 42;
        let rho = Arc::new(
            RhoConnection::new(
                IotaConnection::from_general(general.clone(), 2).await,
                vec![7],
            )
            .await,
        );
        state.rho.add(rho.clone()).await;
        *general.rho_connection.write().await = Some(rho.clone());
        let client = super::ClientConnection::from_general(general, 7).await;
        rho.add_client_connection(client.clone()).await;
        state
            .provisioning
            .create(
                ProvisioningMethod::QrOwnerCreated,
                ProvisioningParticipant {
                    id: client.session_id,
                    role: ProvisioningRole::Owner,
                    temporary_public_key: mtp::crypto::Keyring::generate().public_key_bundle(),
                    sender: Arc::downgrade(&client.sender),
                },
            )
            .unwrap();

        let mutation = state.rho.mutation_guard().await;
        let cleanup = tokio::spawn(client.clone().handle_close());
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!cleanup.is_finished());
        assert!(state.provisioning.for_participant(42).is_ok());
        drop(mutation);
        tokio::time::timeout(Duration::from_secs(2), cleanup)
            .await
            .unwrap()
            .unwrap();
        assert!(rho.get_client_connection(7, 42).await.is_none());
        assert!(state.provisioning.for_participant(42).is_err());
        // Disconnecting a device must preserve its account's Iota assignment.
        assert!(state.rho.get_for_user(7).await.is_some());
        peer.sender.close().await;
        host.shutdown().await;
    }

    #[tokio::test]
    async fn disconnected_client_bounds_drain_and_preserves_pending_mutations() {
        use crate::rho::{
            connection::{GeneralConnection, admission_engine},
            test_support,
        };
        use std::{
            sync::{
                Arc,
                atomic::{AtomicUsize, Ordering},
            },
            time::Duration,
        };
        for finish_during_drain in [false, true] {
            let state = test_support::state();
            let (host, peer, accepted) = test_support::guest("anonymous").await;
            let general =
                GeneralConnection::admit(accepted, state.clone(), &admission_engine()).unwrap();
            let connection = super::ClientConnection::from_general(general.clone(), 7).await;
            let writes = Arc::new(AtomicUsize::new(0));
            let (started, ready) = tokio::sync::oneshot::channel();
            let (finish, blocked) = tokio::sync::oneshot::channel();
            let (alive, mut cancelled) = tokio::sync::oneshot::channel::<()>();
            let (completed, completion) = tokio::sync::oneshot::channel();
            connection
                .tasks
                .spawn({
                    let writes = writes.clone();
                    async move {
                        let _alive = alive;
                        started.send(()).unwrap();
                        let _ = blocked.await;
                        writes.fetch_add(1, Ordering::SeqCst);
                        completed.send(()).unwrap();
                    }
                })
                .unwrap();
            let global = state
                .rho_connection_limits
                .all
                .clone()
                .try_acquire_owned()
                .unwrap();
            let guest = state
                .rho_connection_limits
                .anonymous
                .clone()
                .try_acquire_owned()
                .unwrap();
            let handlers = connection.tasks.clone();
            let task = tokio::spawn(async move {
                let _permits = (global, guest);
                connection.run().await;
            });
            ready.await.unwrap();
            peer.sender.close().await;
            tokio::time::sleep(Duration::from_millis(150)).await;
            assert!(!task.is_finished());
            assert_eq!(state.rho_connection_limits.all.available_permits(), 1);
            assert_eq!(state.rho_connection_limits.anonymous.available_permits(), 0);
            let pending_mutation = if finish_during_drain {
                finish.send(()).unwrap();
                None
            } else {
                handlers.drain_expired.notified().await;
                Some(finish)
            };
            tokio::time::timeout(Duration::from_secs(4), task)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(state.rho_connection_limits.all.available_permits(), 2);
            assert_eq!(state.rho_connection_limits.anonymous.available_permits(), 1);
            if let Some(finish) = pending_mutation {
                assert!(matches!(
                    cancelled.try_recv(),
                    Err(tokio::sync::oneshot::error::TryRecvError::Empty)
                ));
                assert_eq!(writes.load(Ordering::SeqCst), 0);
                finish.send(()).unwrap();
            }
            tokio::time::timeout(Duration::from_secs(4), completion)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(writes.load(Ordering::SeqCst), 1);
            host.shutdown().await;
        }
    }

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
