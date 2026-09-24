use super::capabilities::PeerCapabilities;
use crate::{
    config::{Config, OfflineAuthPolicy, TransportConfig},
    log_cv_in, log_cv_out, log_err, log_in, log_out,
    rho::connection::{OptionalDataValueCompat, RequiredMtpFields},
    rho::relay_router,
    rho::rho_manager::RhoManager,
    util::{data_type_id, logger::PrintType},
};
use dashmap::DashMap;
use mtp::client::{Client, MTPConnection, Sender};
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use mtp::{
    client::ClientConfig,
    files::{load_public_key_bundle, save_public_key_bundle},
    host::{Policy, SendMode},
};
use mtp_native::ConnectionHandle;
use rand::RngExt;
use std::{
    collections::VecDeque,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::{Mutex, RwLock, oneshot, watch},
    task::JoinHandle,
    time::{Instant, sleep},
};

use uuid::Uuid;

const RECONNECT_DELAY: Duration = Duration::from_secs(5);
const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(300);
const RECONNECT_JITTER: Duration = Duration::from_secs(1);
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);
const CAPABILITY_NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(1);
const PING_INTERVAL: Duration = Duration::from_secs(5);
const TASK_CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
const MAX_INITIAL_PRESENCE_BUFFERED_EVENTS: usize = 1_024;
const TASK_MAX_AGE: Duration = Duration::from_secs(60);
const MAX_CONCURRENT_REQUESTS: usize = 128;
const CIRCUIT_BREAKER_FAILURE_THRESHOLD: u32 = 3;
const CIRCUIT_BREAKER_COOLDOWN: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthIdentityKind {
    Client,
    Iota,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuthIdentity {
    pub kind: AuthIdentityKind,
    pub id: u64,
}

#[cfg(unix)]
fn authenticated_cache_file_trusted(path: &std::path::Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(path).is_ok_and(|metadata| {
        metadata.file_type().is_file()
            && metadata.mode() & 0o077 == 0
            && metadata.uid() == unsafe { libc::geteuid() }
    })
}

#[cfg(not(unix))]
fn authenticated_cache_file_trusted(_: &std::path::Path) -> bool {
    false
}

fn authenticated_key_path(identity: AuthIdentity) -> std::path::PathBuf {
    let kind = match identity.kind {
        AuthIdentityKind::Client => "client",
        AuthIdentityKind::Iota => "iota",
    };

    crate::WORKING_DIR
        .join("authenticated-public-keys")
        .join(kind)
        .join(format!("{}.mpkb", identity.id))
}

fn authenticated_key_timestamp_path(identity: AuthIdentity) -> std::path::PathBuf {
    authenticated_key_path(identity).with_extension("mpkb.cached-at")
}

#[derive(Clone)]
struct CachedAuthenticatedKey {
    public_key: mtp::crypto::PublicKeyBundle,
    cached_at: SystemTime,
}

fn cached_at_is_fresh(now: SystemTime, cached_at: SystemTime, max_age: Duration) -> bool {
    now.duration_since(cached_at)
        .is_ok_and(|age| age <= max_age)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionOutcome {
    HealthySessionEnded,
    FailedBeforeHealthy,
}

fn reconnect_base_after_outcome(current: Duration, outcome: ConnectionOutcome) -> Duration {
    match outcome {
        ConnectionOutcome::HealthySessionEnded => RECONNECT_DELAY,
        ConnectionOutcome::FailedBeforeHealthy => current,
    }
}

fn reconnect_delay_with_jitter(delay: Duration) -> Duration {
    let max_jitter_ms = std::cmp::min(delay, RECONNECT_JITTER).as_millis() as u64;
    delay + Duration::from_millis(rand::rng().random_range(0..=max_jitter_ms))
}

fn client_changed_target(value: &CommunicationValue) -> Option<(i64, i64)> {
    if !value.is_type(CommunicationType::ClientChanged) {
        return None;
    }
    let receiver = i64::try_from(value.receiver()?).ok().filter(|id| *id > 0)?;
    let session_id = value
        .get_data(DataType::SessionId)
        .as_signed_number()
        .and_then(|id| i64::try_from(id).ok())
        .filter(|id| *id > 0)?;
    value
        .get_data(DataType::UserId)
        .as_signed_number()
        .and_then(|id| i64::try_from(id).ok())
        .filter(|id| *id > 0)?;
    value.get_data(DataType::UserState).as_str()?;
    Some((receiver, session_id))
}

fn signed_positive_iota_id(value: &CommunicationValue) -> Option<i64> {
    value
        .get_data(DataType::IotaId)
        .as_signed_number()
        .and_then(|id| i64::try_from(id).ok())
        .filter(|id| *id > 0)
}

fn deleted_user_id(value: &CommunicationValue) -> Option<i64> {
    value
        .is_type(CommunicationType::DeleteUser)
        .then(|| value.get_data(DataType::UserId).as_signed_number())
        .flatten()
        .and_then(|id| i64::try_from(id).ok())
        .filter(|id| *id > 0)
}

fn iota_user_snapshot(value: &CommunicationValue) -> Option<(i64, Vec<i64>)> {
    if !value.is_type(CommunicationType::IotaUserData) {
        return None;
    }
    iota_snapshot_data(value)
}

fn iota_activation_snapshot(value: &CommunicationValue) -> Option<(i64, Vec<i64>)> {
    if !value.is_type(CommunicationType::Success) {
        return None;
    }
    iota_snapshot_data(value)
}

fn iota_snapshot_data(value: &CommunicationValue) -> Option<(i64, Vec<i64>)> {
    let iota_id = value
        .get_data(DataType::IotaId)
        .as_signed_number()
        .and_then(|id| i64::try_from(id).ok())
        .filter(|id| *id > 0)?;
    let Some(DataValue::Array(values)) = value.get_data(DataType::UserIds) else {
        return None;
    };
    let mut user_ids = Vec::with_capacity(values.len());
    for value in values {
        let DataValue::SignedNumber(user_id) = value else {
            return None;
        };
        let user_id = i64::try_from(*user_id)
            .ok()
            .filter(|user_id| *user_id > 0)?;
        user_ids.push(user_id);
    }
    user_ids.sort_unstable();
    user_ids.dedup();
    Some((iota_id, user_ids))
}

fn parse_omega_capability_response(value: &CommunicationValue) -> Result<PeerCapabilities, String> {
    if !value.is_type(CommunicationType::IdentificationResponse) {
        return Err("not an identification response".to_string());
    }
    PeerCapabilities::from_omega_identification_description(
        value.get_data(DataType::Description).as_str(),
    )
    .map_err(|_| "Omega advertised an invalid capability set".to_string())
}

// ============================================================================
// Waiting Task System
// ============================================================================

pub struct WaitingTask {
    pub original_id: u32,
    pub sender: oneshot::Sender<CommunicationValue>,
    pub inserted_at: Instant,
}

fn allocate_omega_request_id(
    next_request_id: &AtomicU32,
    waiting_tasks: &DashMap<u32, WaitingTask>,
) -> u32 {
    loop {
        let candidate = next_request_id.fetch_add(1, Ordering::Relaxed);
        if candidate != 0 && !waiting_tasks.contains_key(&candidate) {
            return candidate;
        }
    }
}

fn complete_waiting_task(
    waiting_tasks: &DashMap<u32, WaitingTask>,
    omega_id: u32,
    response: CommunicationValue,
) -> bool {
    let Some((_, task)) = waiting_tasks.remove(&omega_id) else {
        return false;
    };
    let _ = task.sender.send(response.with_id(task.original_id));
    true
}

struct CircuitBreaker {
    consecutive_failures: u32,
    open_until: Option<Instant>,
}

impl CircuitBreaker {
    fn allow_request(&mut self) -> bool {
        if self.open_until.is_some_and(|until| until > Instant::now()) {
            return false;
        }
        self.open_until = None;
        true
    }

    fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.open_until = None;
    }

    fn record_failure(&mut self) {
        self.consecutive_failures += 1;
        if self.consecutive_failures >= CIRCUIT_BREAKER_FAILURE_THRESHOLD {
            self.open_until = Some(Instant::now() + CIRCUIT_BREAKER_COOLDOWN);
        }
    }
}

pub fn start_task_cleanup_loop(omega: Arc<OmegaConnection>) {
    tokio::spawn(async move {
        loop {
            sleep(TASK_CLEANUP_INTERVAL).await;
            omega
                .waiting_tasks
                .retain(|_, v| v.inserted_at.elapsed() < TASK_MAX_AGE);
        }
    });
}

// ============================================================================
// Connection State
// ============================================================================

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Identifying,
    SynchronizingRoutes,
    SynchronizingSubscriptions,
    Ready,
}

#[allow(unused_variables)]
impl ConnectionState {
    pub fn is_connected(&self) -> bool {
        !matches!(
            self,
            ConnectionState::Disconnected | ConnectionState::Connecting
        )
    }

    #[allow(dead_code)]
    pub fn is_identified(&self) -> bool {
        matches!(
            self,
            ConnectionState::SynchronizingRoutes
                | ConnectionState::SynchronizingSubscriptions
                | ConnectionState::Ready
        )
    }

    pub fn is_ready(&self) -> bool {
        matches!(self, ConnectionState::Ready)
    }
}

// ============================================================================
// Omega Connection (Client-side with auto-reconnect)
// ============================================================================
#[allow(dead_code)]
pub struct OmegaConnection {
    state: Arc<RwLock<ConnectionState>>,
    sender: Arc<RwLock<Option<Arc<Sender>>>>,
    connection_loop_handle: Arc<Mutex<Option<JoinHandle<()>>>>,
    host: String,
    port: u16,
    omikron_id: u64,
    sync_timeout: Duration,
    sync_retries: u32,
    transport_config: TransportConfig,
    offline_auth: OfflineAuthPolicy,
    pub connection_id: Uuid,
    shutdown_tx: Arc<Mutex<Option<watch::Sender<bool>>>>,
    // Track if we should reconnect on close
    reconnect_on_close: Arc<RwLock<bool>>,
    request_slots: tokio::sync::Semaphore,
    circuit_breaker: Mutex<CircuitBreaker>,
    sync_lock: Mutex<()>,
    keyring: mtp::crypto::Keyring,
    rho: Arc<RhoManager>,
    authenticated_key_cache: DashMap<AuthIdentity, CachedAuthenticatedKey>,
    missing_key_cache: DashMap<AuthIdentity, Instant>,
    waiting_tasks: DashMap<u32, WaitingTask>,
    next_request_id: AtomicU32,
    session_presence: DashMap<(i64, i64), SessionPresenceState>,
    presence_delivery_locks: DashMap<(i64, i64), Arc<Mutex<()>>>,
    initial_presence_barriers: DashMap<(i64, i64), Arc<Mutex<InitialPresenceBarrier>>>,
    peer_capabilities: Arc<RwLock<PeerCapabilities>>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SessionPresenceState {
    pub subscribed_user_ids: Vec<i64>,
    pub pending: bool,
    pub generation: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum InitialPresenceError {
    #[error("Omega is unavailable: {0}")]
    OmegaUnavailable(String),
    #[error("presence subscription was rejected: {0}")]
    SubscriptionRejected(String),
    #[error("invalid GetStates snapshot: {0}")]
    InvalidSnapshot(String),
    #[error("initial presence synchronization is already in progress")]
    AlreadyInProgress,
    #[error("initial presence event ordering was lost")]
    OrderingLost,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PresenceBufferResult {
    NotBuffered,
    Buffered,
    OrderingLost,
}

fn normalize_presence_user_ids(mut user_ids: Vec<i64>) -> Result<Vec<i64>, String> {
    if user_ids.iter().any(|id| *id <= 0) {
        return Err("presence subscription contains invalid user id".into());
    }
    user_ids.sort_unstable();
    user_ids.dedup();
    Ok(user_ids)
}

fn omega_transport_policy(config: &TransportConfig) -> Policy {
    Policy::default()
        .with_send_mode(SendMode::SingleStreamPerMessage)
        .with_max_message_size(config.max_message_size)
        .with_handshake_max_message_size(config.handshake_max_message_size)
        .with_timeouts(
            Duration::from_millis(5_000),
            Duration::from_millis(5_000),
            Duration::from_millis(30_000),
        )
        .with_keep_alive(Some(Duration::from_secs(6)))
        .with_max_idle_timeout(Some(Duration::from_secs(30)))
        .with_receiver_queue_capacity(1000)
        .with_max_concurrent_stream_tasks(64)
        .with_persistent_stream_retries(5, Duration::from_secs(5))
}

#[derive(Default)]
struct InitialPresenceBarrier {
    queued: VecDeque<CommunicationValue>,
    live: bool,
    overflowed: bool,
}

impl OmegaConnection {
    pub fn omikron_id(&self) -> u64 {
        self.omikron_id
    }

    pub fn from_config(
        config: &Config,
        keyring: mtp::crypto::Keyring,
        rho: Arc<RhoManager>,
    ) -> Self {
        let (shutdown_tx, _) = watch::channel(false);

        OmegaConnection {
            state: Arc::new(RwLock::new(ConnectionState::Disconnected)),
            sender: Arc::new(RwLock::new(None)),
            connection_loop_handle: Arc::new(Mutex::new(None)),
            host: config.omega_host.clone(),
            port: config.omega_port,
            omikron_id: config.omikron_id,
            sync_timeout: config.omega_sync_timeout,
            sync_retries: config.omega_sync_retries,
            transport_config: config.omega_transport.clone(),
            offline_auth: config.offline_auth.clone(),
            connection_id: Uuid::new_v4(),
            shutdown_tx: Arc::new(Mutex::new(Some(shutdown_tx))),
            reconnect_on_close: Arc::new(RwLock::new(true)),
            request_slots: tokio::sync::Semaphore::new(MAX_CONCURRENT_REQUESTS),
            circuit_breaker: Mutex::new(CircuitBreaker {
                consecutive_failures: 0,
                open_until: None,
            }),
            sync_lock: Mutex::new(()),
            keyring,
            rho,
            authenticated_key_cache: DashMap::new(),
            missing_key_cache: DashMap::new(),
            waiting_tasks: DashMap::new(),
            next_request_id: AtomicU32::new(1),
            session_presence: DashMap::new(),
            presence_delivery_locks: DashMap::new(),
            initial_presence_barriers: DashMap::new(),
            peer_capabilities: Arc::new(RwLock::new(PeerCapabilities::default())),
        }
    }

    // -------------------------------------------------------------------------
    // Connection Management
    // -------------------------------------------------------------------------

    pub async fn start(self: Arc<Self>) {
        // Cancel any existing connection loop
        if let Some(handle) = self.connection_loop_handle.lock().await.take() {
            handle.abort();
        }

        // Recreate shutdown_tx if it was taken by stop()
        if self.shutdown_tx.lock().await.is_none() {
            let (shutdown_tx, _) = watch::channel(false);
            *self.shutdown_tx.lock().await = Some(shutdown_tx);
        }

        // Set reconnect flag
        *self.reconnect_on_close.write().await = true;

        let self_clone = self.clone();
        let handle = tokio::spawn(async move {
            self_clone.connection_loop().await;
        });

        *self.connection_loop_handle.lock().await = Some(handle);
    }

    #[allow(dead_code)]
    pub async fn stop(&self) {
        // Disable reconnection
        *self.reconnect_on_close.write().await = false;

        if let Some(tx) = self.shutdown_tx.lock().await.take() {
            let _ = tx.send(true);
        }

        if let Some(handle) = self.connection_loop_handle.lock().await.take() {
            handle.abort();
        }

        // Close sender if connected
        if let Some(sender) = self.sender.read().await.as_ref() {
            sender.close().await;
        }

        *self.state.write().await = ConnectionState::Disconnected;
        *self.sender.write().await = None;
    }

    async fn connection_loop(self: Arc<Self>) {
        let mut reconnect_delay = RECONNECT_DELAY;
        let shutdown_rx = self.shutdown_tx.lock().await.as_ref().unwrap().subscribe();
        let mut shutdown_rx = shutdown_rx;

        loop {
            if *shutdown_rx.borrow() {
                log_in!(0, PrintType::Omega, "Connection loop shutting down");
                break;
            }

            // Check if reconnection is enabled
            if !*self.reconnect_on_close.read().await {
                log_in!(0, PrintType::Omega, "Reconnection disabled, exiting loop");
                break;
            }

            match self.clone().connect_once().await {
                Ok(outcome) => {
                    reconnect_delay = reconnect_base_after_outcome(reconnect_delay, outcome);
                    match outcome {
                        ConnectionOutcome::HealthySessionEnded => {
                            log_err!(
                                0,
                                PrintType::Omega,
                                "Healthy Omega connection ended; reconnecting"
                            );
                        }
                        ConnectionOutcome::FailedBeforeHealthy => {
                            log_err!(
                                0,
                                PrintType::Omega,
                                "Omega connection failed before synchronization"
                            );
                        }
                    }
                }
                Err(error) => {
                    log_err!(0, PrintType::Omega, "Connection failed: {}", error);
                }
            }

            if !*self.reconnect_on_close.read().await {
                log_in!(0, PrintType::Omega, "Connection closed, not reconnecting");
                break;
            }

            let retry_delay = reconnect_delay_with_jitter(reconnect_delay);
            log_err!(
                0,
                PrintType::Omega,
                "Retrying Omega connection in {:?}...",
                retry_delay
            );

            tokio::select! {
                _ = sleep(retry_delay) => {}
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
            }

            reconnect_delay = std::cmp::min(reconnect_delay * 2, MAX_RECONNECT_DELAY);
        }
    }

    async fn connect_once(self: Arc<Self>) -> Result<ConnectionOutcome, String> {
        *self.state.write().await = ConnectionState::Connecting;

        let client_config = ClientConfig::new(format!("https://{}:{}", self.host, self.port))
            .with_client_id(self.omikron_id)
            .with_description(PeerCapabilities::current().identification_description())
            .with_policy(omega_transport_policy(&self.transport_config))
            .with_ping_interval(PING_INTERVAL);

        let host_public_key = load_public_key_bundle("./omega.mpkb")
            .map_err(|e| format!("Failed to load omega.mpkb: {}", e))?;

        let connection = Client::auth_connect(client_config, &self.keyring, &host_public_key)
            .await
            .map_err(|e| format!("Connection failed: {}", e))?;

        log_in!(
            0,
            PrintType::Omega,
            "QUIC connection established to {}",
            format!("https://{}:{}", self.host, self.port)
        );

        // Store sender
        let sender_arc = Arc::new(connection.sender.clone());
        *self.sender.write().await = Some(sender_arc.clone());
        // A new authenticated transport gets a fresh request circuit. A
        // previous transport can have failed while synchronizing and must not
        // prevent this connection from making its initial requests.
        self.circuit_breaker.lock().await.record_success();
        *self.state.write().await = ConnectionState::Identifying;

        // Get handle for close monitoring
        let sender_handle = sender_arc.handle().clone();
        let connection = Arc::new(connection);
        let (capability_tx, capability_rx) = oneshot::channel();

        // Start read loop
        let read_self = self.clone();
        let read_handle = tokio::spawn(async move {
            read_self
                .read_loop(connection, sender_handle, Some(capability_tx))
                .await;
        });

        let negotiated_capabilities =
            match tokio::time::timeout(CAPABILITY_NEGOTIATION_TIMEOUT, capability_rx).await {
                Ok(Ok(Ok(capabilities))) => capabilities,
                Ok(Ok(Err(error))) => {
                    self.fail_synchronization("capability negotiation", error)
                        .await;
                    let _ = read_handle.await;
                    return Ok(ConnectionOutcome::FailedBeforeHealthy);
                }
                Ok(Err(_)) | Err(_) => {
                    // An Omega from before capability negotiation sends no second
                    // identification response. Fall back to its documented
                    // legacy contracts rather than guessing modern support.
                    PeerCapabilities::default()
                }
            };
        *self.peer_capabilities.write().await = negotiated_capabilities;

        // Tell omega our current state now that we're actually connected -
        // doing this after teardown (as before) sent into a sender that had
        // already been cleared, silently dropping the sync every time.
        let reached_healthy_state = self.clone().sync_client_iota_status().await;

        // Wait for read loop to complete (connection closed)
        let result = read_handle.await;

        // Cleanup
        let close_reason = sender_arc.close_reason();
        if let Some(reason) = close_reason {
            log_err!(
                0,
                PrintType::Omega,
                "Omega transport ended with close reason: {:?}",
                reason
            );
        } else {
            log_in!(
                0,
                PrintType::Omega,
                "Omega transport ended without a close reason"
            );
        }
        *self.sender.write().await = None;
        *self.state.write().await = ConnectionState::Disconnected;
        self.waiting_tasks.clear();

        match result {
            Ok(()) if reached_healthy_state => Ok(ConnectionOutcome::HealthySessionEnded),
            Ok(()) => Ok(ConnectionOutcome::FailedBeforeHealthy),
            Err(e) => Err(format!("Read loop error: {}", e)),
        }
    }

    async fn sync_client_iota_status(&self) -> bool {
        let _sync_guard = self.sync_lock.lock().await;
        *self.state.write().await = ConnectionState::SynchronizingRoutes;
        let mut connected_iota_ids: Vec<DataValue> = Vec::new();
        let mut connected_sessions: Vec<DataValue> = Vec::new();
        let mut connected_user_ids: Vec<DataValue> = Vec::new();

        let iota_ids = self.rho.iota_ids().await;
        let rho_connections = self.rho.connections().await;

        for iota_id in iota_ids {
            connected_iota_ids.push(DataValue::SignedNumber(iota_id.into()));
        }

        for rho in rho_connections {
            for client_conn in rho.get_client_connections().await {
                let type_map = mtp::codec::TypeMap::latest();
                let user_id = DataValue::SignedNumber(client_conn.get_user_id().await.into());
                let session_id = DataValue::SignedNumber((client_conn.session_id as i128).into());
                let iota_id = DataValue::SignedNumber((rho.get_iota_id().await as i128).into());
                let peer_capabilities = self.peer_capabilities.read().await.clone();
                if peer_capabilities.session_snapshot_v1 {
                    connected_sessions.push(DataValue::Container(vec![
                        (data_type_id(DataType::UserId, &type_map), user_id),
                        (data_type_id(DataType::SessionId, &type_map), session_id),
                        (data_type_id(DataType::IotaId, &type_map), iota_id),
                    ]));
                } else {
                    connected_user_ids.push(user_id);
                }
            }
        }

        let peer_capabilities = self.peer_capabilities.read().await.clone();
        let sync_msg = if peer_capabilities.session_snapshot_v1 {
            CommunicationValue::new(CommunicationType::SyncClientIotaStatus)
                .add_typed_default(DataType::IotaIds, DataValue::Array(connected_iota_ids))
                .add_typed_default(DataType::UserStates, DataValue::Array(connected_sessions))
                .add_typed_default(
                    DataType::RhoConnections,
                    DataValue::SignedNumber(self.rho.connection_count().await as i128),
                )
        } else {
            // Legacy Omega has no request/response contract for this message.
            // Its exact snapshot is IotaIds + UserIds + RhoConnections.
            CommunicationValue::new(CommunicationType::SyncClientIotaStatus)
                .add_typed_default(DataType::IotaIds, DataValue::Array(connected_iota_ids))
                .add_typed_default(DataType::UserIds, DataValue::Array(connected_user_ids))
                .add_typed_default(
                    DataType::RhoConnections,
                    DataValue::SignedNumber(self.rho.connection_count().await as i128),
                )
        };

        if !peer_capabilities.session_snapshot_v1 {
            if let Err(error) = self.send_message_result(&sync_msg).await {
                self.fail_synchronization("legacy route synchronization", error)
                    .await;
                return false;
            }
            *self.state.write().await = ConnectionState::SynchronizingSubscriptions;
            if let Err(error) = self.restore_presence_subscriptions().await {
                self.fail_synchronization("subscription restoration", error)
                    .await;
                return false;
            }
            *self.state.write().await = ConnectionState::Ready;
            return true;
        }

        let mut response = Err("route synchronization did not start".to_string());
        for attempt in 0..self.sync_retries {
            response = self
                .await_response(&sync_msg, Some(self.sync_timeout))
                .await;
            match &response {
                Ok(value) if value.is_type(CommunicationType::Success) => break,
                Ok(value) if value.is_type(CommunicationType::ErrorInvalidData) => break,
                _ if attempt + 1 < self.sync_retries => {
                    sleep(Duration::from_millis(250 * 2u64.pow(attempt))).await
                }
                _ => break,
            }
        }
        match response {
            Ok(response) if response.is_type(CommunicationType::Success) => {
                *self.state.write().await = ConnectionState::SynchronizingSubscriptions;
                if let Err(error) = self.restore_presence_subscriptions().await {
                    log_err!(
                        0,
                        PrintType::Omega,
                        "Presence subscription restoration failed: {}",
                        error
                    );
                    self.fail_synchronization("subscription restoration", error)
                        .await;
                    return false;
                }
                *self.state.write().await = ConnectionState::Ready;
            }
            Ok(response) => {
                let error = format!(
                    "Omega rejected presence snapshot with {}",
                    response.get_type()
                );
                self.fail_synchronization("route synchronization", error)
                    .await;
                return false;
            }
            Err(error) => {
                self.fail_synchronization("route synchronization", error)
                    .await;
                return false;
            }
        }
        true
    }

    async fn fail_synchronization(&self, phase: &str, error: String) {
        log_err!(
            0,
            PrintType::Omega,
            "Omega {} failed after {} attempts: {}; closing transport for reconnect",
            phase,
            self.sync_retries,
            error
        );
        *self.state.write().await = ConnectionState::Disconnected;
        self.waiting_tasks.clear();
        if let Some(sender) = self.sender.read().await.as_ref() {
            sender.close().await;
        }
    }

    // -------------------------------------------------------------------------
    // Read Loop
    // -------------------------------------------------------------------------

    async fn read_loop(
        self: Arc<Self>,
        connection: Arc<MTPConnection>,
        sender_handle: Arc<ConnectionHandle>,
        mut capability_tx: Option<oneshot::Sender<Result<PeerCapabilities, String>>>,
    ) {
        // Monitor both receiver and sender handle for close
        let mut close_rx = sender_handle.subscribe_close();

        loop {
            tokio::select! {
                result = connection.receive() => {
                    match result {
                        Ok(cv) => {
                            log_cv_in!(PrintType::Omega, &cv);

                            if cv.is_type(CommunicationType::IdentificationResponse) {
                                if let Some(tx) = capability_tx.take() {
                                    let result = parse_omega_capability_response(&cv);
                                    let _ = tx.send(result);
                                }
                                continue;
                            }

                            if let Some(user_id) = deleted_user_id(&cv) {
                                self.rho.invalidate_user(user_id).await;
                                self.invalidate_authenticated_key(AuthIdentity {
                                    kind: AuthIdentityKind::Client,
                                    id: user_id as u64,
                                });
                                continue;
                            }

                            if cv.is_type(CommunicationType::DeleteIota)
                                && let Some(iota_id) = signed_positive_iota_id(&cv)
                            {
                                if let Some(rho) = self.rho.get_by_iota(iota_id).await {
                                    rho.close_deleted_iota_connection().await;
                                }
                                self.invalidate_authenticated_key(AuthIdentity {
                                    kind: AuthIdentityKind::Iota,
                                    id: iota_id as u64,
                                });
                                continue;
                            }

                            if let Some((iota_id, user_ids)) = iota_user_snapshot(&cv) {
                                self.rho.replace_users_for_iota(iota_id, user_ids).await;
                                continue;
                            }

                            if cv.is_type(CommunicationType::Relay) {
                                let request_id = match cv.require_id() {
                                    Ok(request_id) => request_id,
                                    Err(error) => {
                                        log_err!(
                                            self.omikron_id as i64,
                                            PrintType::Omega,
                                            "Rejected malformed relay: {}",
                                            error
                                        );
                                        let response =
                                            CommunicationValue::new(CommunicationType::ErrorInvalidData)
                                                .without_id();
                                        let _ = self.send_message_result(&response).await;
                                        continue;
                                    }
                                };
                                let destination_iota = match cv.require_receiver() {
                                    Ok(destination_iota) => destination_iota,
                                    Err(error) => {
                                        log_err!(
                                            self.omikron_id as i64,
                                            PrintType::Omega,
                                            "Rejected malformed relay: {}",
                                            error
                                        );
                                        let response = CommunicationValue::new(
                                            CommunicationType::ErrorInvalidData,
                                        )
                                        .with_id(request_id);
                                        let _ = self.send_message_result(&response).await;
                                        continue;
                                    }
                                };
                                let response = match relay_router::route_from_omega(&self.rho, cv).await {
                                    Ok(response) => response.with_id(request_id),
                                    Err(error) => {
                                        log_err!(
                                            self.omikron_id as i64,
                                            PrintType::Omega,
                                            "Relay routing failed for destination Iota {}: {}",
                                            destination_iota,
                                            error
                                        );
                                        CommunicationValue::new(
                                            relay_router::error_response_type(&error),
                                        )
                                        .with_id(request_id)
                                    }
                                };
                                if let Err(send_error) = self.send_message_result(&response).await {
                                    log_err!(
                                        self.omikron_id as i64,
                                        PrintType::Omega,
                                        "Relay routing response failed: {}",
                                        send_error
                                    );
                                }
                                continue;
                            }

                            let msg_id = match cv.require_id() {
                                Ok(msg_id) => msg_id,
                                Err(error) => {
                                    log_err!(
                                        self.omikron_id as i64,
                                        PrintType::Omega,
                                        "Discarded response without an MTP id: {}",
                                        error
                                    );
                                    continue;
                                }
                            };
                            if complete_waiting_task(&self.waiting_tasks, msg_id, cv.clone()) {
                                continue;
                            }

                            if cv.is_type(CommunicationType::EraseHostedUserData) {
                                let Some(iota_id) = signed_positive_iota_id(&cv)
                                else {
                                    log_err!(0, PrintType::Omega, "Discarded hosted-data erasure without IotaId");
                                    continue;
                                };
                                if let Some(rho) = self.rho.get_by_iota(iota_id).await {
                                    rho.get_iota_connection().send_message(&cv).await;
                                } else {
                                    log_err!(iota_id, PrintType::Omega, "Hosted-data erasure is pending because the Iota is offline");
                                }
                                continue;
                            }
                            if cv.is_type(CommunicationType::ProvisionIotaUser) {
                                let Some(iota_id) = signed_positive_iota_id(&cv)
                                else {
                                    log_err!(
                                        0,
                                        PrintType::Omega,
                                        "Discarded user provisioning without a valid IotaId"
                                    );
                                    continue;
                                };
                                if let Some(rho) = self.rho.get_by_iota(iota_id).await {
                                    rho.get_iota_connection().send_message(&cv).await;
                                } else {
                                    log_err!(
                                        iota_id,
                                        PrintType::Omega,
                                        "User provisioning is pending because the Iota is offline"
                                    );
                                }
                                continue;
                            }
                            if cv.is_type(CommunicationType::ClientChanged) {
                                let Some((receiver, session_id)) = client_changed_target(&cv)
                                else {
                                    continue;
                                };
                                match self
                                    .buffer_initial_presence_event((receiver, session_id), cv.clone())
                                    .await
                                {
                                    PresenceBufferResult::NotBuffered => {
                                        self.forward_client_changed(receiver, session_id, &cv).await;
                                    }
                                    PresenceBufferResult::Buffered
                                    | PresenceBufferResult::OrderingLost => {}
                                }
                                continue;
                            }
                        }
                        Err(e) => {
                            log_err!(0, PrintType::Omega, "Receive error: {}", e);
                            break;
                        }
                    }
                }
                _ = close_rx.changed() => {
                    // Connection was closed by either side
                    if let Some(reason) = close_rx.borrow().clone() {
                        log_err!(0, PrintType::Omega, "Connection closed: {:?}", reason);
                    } else {
                        log_in!(0, PrintType::Omega, "Connection closed cleanly");
                    }
                    break;
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    async fn try_send_message(&self, cv: &CommunicationValue) -> Result<(), String> {
        log_cv_out!(PrintType::Omega, &cv);

        let sender_guard = self.sender.read().await;
        if let Some(sender) = sender_guard.as_ref() {
            // Check if closed before sending
            if sender.is_closed() {
                log_err!(0, PrintType::Omega, "Cannot send: connection closed");
                drop(sender_guard);
                // Trigger reconnection by closing the connection state
                if let Some(sender) = self.sender.write().await.take() {
                    sender.close().await;
                }
                return Err("connection is closed".to_string());
            }

            let sender_clone = Arc::clone(sender);
            drop(sender_guard);

            if let Err(e) = sender_clone.send(cv).await {
                log_err!(0, PrintType::Omega, "Send failed: {}", e);
                return Err(e.to_string());
            }
        } else {
            log_err!(0, PrintType::Omega, "Cannot send: not connected");
            return Err("not connected".to_string());
        }
        Ok(())
    }

    pub async fn send_message(&self, cv: &CommunicationValue) {
        let _ = self.try_send_message(cv).await;
    }

    pub async fn send_message_result(&self, cv: &CommunicationValue) -> Result<(), String> {
        self.try_send_message(cv).await
    }

    #[allow(dead_code)]
    pub async fn supports_set_user_state(&self) -> bool {
        self.peer_capabilities.read().await.set_user_state_v1
    }

    pub async fn await_connection(&self, timeout_duration: Option<Duration>) -> Result<(), String> {
        if self.state.read().await.is_connected() {
            return Ok(());
        }

        let timeout = timeout_duration.unwrap_or(CONNECTION_TIMEOUT);
        let start = Instant::now();

        loop {
            if self.state.read().await.is_connected() {
                return Ok(());
            }

            if start.elapsed() >= timeout {
                return Err(format!(
                    "Connection not established within {} seconds",
                    timeout.as_secs()
                ));
            }

            sleep(Duration::from_millis(100)).await;
        }
    }

    pub async fn await_response(
        &self,
        cv: &CommunicationValue,
        timeout_duration: Option<Duration>,
    ) -> Result<CommunicationValue, String> {
        let _permit = self
            .request_slots
            .acquire()
            .await
            .map_err(|_| "Omega request queue is unavailable".to_string())?;

        if !self.circuit_breaker.lock().await.allow_request() {
            return Err("Omega circuit breaker is open".to_string());
        }

        let result = self.await_response_inner(cv, timeout_duration).await;
        let mut breaker = self.circuit_breaker.lock().await;
        if result.is_ok() {
            breaker.record_success();
        } else {
            breaker.record_failure();
        }
        result
    }

    async fn await_response_inner(
        &self,
        cv: &CommunicationValue,
        timeout_duration: Option<Duration>,
    ) -> Result<CommunicationValue, String> {
        let original_id = cv
            .require_id()
            .map_err(|error| format!("request is missing correlation id: {error}"))?;
        self.await_connection(timeout_duration).await?;

        let omega_id = allocate_omega_request_id(&self.next_request_id, &self.waiting_tasks);
        let outbound = cv.clone().with_id(omega_id);
        let (tx, rx) = oneshot::channel();

        self.waiting_tasks.insert(
            omega_id,
            WaitingTask {
                original_id,
                sender: tx,
                inserted_at: Instant::now(),
            },
        );

        if let Err(error) = self.try_send_message(&outbound).await {
            self.waiting_tasks.remove(&omega_id);
            return Err(format!("failed to send request: {error}"));
        }
        log_out!(
            0,
            PrintType::Omega,
            "Sent Omega request (request_id={}, original_id={}, type={})",
            omega_id,
            original_id,
            outbound
                .get_comm_type_enum()
                .map(|kind| kind.to_string())
                .unwrap_or_else(|| outbound.get_type().to_string())
        );

        let timeout = timeout_duration.unwrap_or(Duration::from_secs(10));

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(response_cv)) => Ok(response_cv),
            Ok(Err(_)) => Err("Channel closed".to_string()),
            Err(_) => {
                self.waiting_tasks.remove(&omega_id);
                Err("Request timed out".to_string())
            }
        }
    }

    #[allow(dead_code)]
    pub async fn is_connected(&self) -> bool {
        self.state.read().await.is_connected()
    }
    #[allow(dead_code)]
    pub async fn is_identified(&self) -> bool {
        self.state.read().await.is_identified()
    }

    pub async fn is_ready(&self) -> bool {
        self.state.read().await.is_ready()
    }

    pub fn recently_missing_key(&self, identity: AuthIdentity) -> bool {
        if self
            .missing_key_cache
            .get(&identity)
            .is_some_and(|timestamp| timestamp.elapsed() < Duration::from_secs(5))
        {
            return true;
        }
        self.missing_key_cache.remove(&identity);
        false
    }

    pub fn cache_missing_key(&self, identity: AuthIdentity) {
        if self.missing_key_cache.len() >= 1024 {
            self.missing_key_cache
                .retain(|_, timestamp| timestamp.elapsed() < Duration::from_secs(5));
            if self.missing_key_cache.len() >= 1024 {
                self.missing_key_cache.clear();
            }
        }
        self.missing_key_cache.insert(identity, Instant::now());
    }

    pub fn cached_authenticated_key(
        &self,
        identity: AuthIdentity,
    ) -> Option<mtp::crypto::PublicKeyBundle> {
        let max_age = match identity.kind {
            AuthIdentityKind::Client => Some(self.offline_auth.client_max_age),
            AuthIdentityKind::Iota => self.offline_auth.iota_max_age,
        }?;
        if let Some(key) = self.authenticated_key_cache.get(&identity) {
            if cached_at_is_fresh(SystemTime::now(), key.cached_at, max_age) {
                return Some(key.public_key.clone());
            }
        }
        self.authenticated_key_cache.remove(&identity);

        if !authenticated_cache_file_trusted(&authenticated_key_path(identity))
            || !authenticated_cache_file_trusted(&authenticated_key_timestamp_path(identity))
        {
            return None;
        }
        let cached_at = std::fs::read_to_string(authenticated_key_timestamp_path(identity))
            .ok()?
            .trim()
            .parse::<u64>()
            .ok()
            .map(|seconds| UNIX_EPOCH + Duration::from_secs(seconds))?;
        if !cached_at_is_fresh(SystemTime::now(), cached_at, max_age) {
            self.invalidate_authenticated_key(identity);
            return None;
        }
        let key = load_public_key_bundle(&authenticated_key_path(identity)).ok()?;
        self.authenticated_key_cache.insert(
            identity,
            CachedAuthenticatedKey {
                public_key: key.clone(),
                cached_at,
            },
        );
        Some(key)
    }

    pub fn cache_authenticated_key(
        &self,
        identity: AuthIdentity,
        public_key: mtp::crypto::PublicKeyBundle,
    ) {
        self.missing_key_cache.remove(&identity);
        let path = authenticated_key_path(identity);
        if let Some(parent) = path.parent() {
            if let Err(error) = std::fs::create_dir_all(parent) {
                log_err!(
                    identity.id as i64,
                    PrintType::General,
                    "Create authenticated key cache directory failed: {}",
                    error
                );
                return;
            }
        }
        if let Err(error) = save_public_key_bundle(&public_key, &path) {
            log_err!(
                identity.id as i64,
                PrintType::General,
                "Persist authenticated key cache failed: {}",
                error
            );
            return;
        }
        #[cfg(unix)]
        if std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .is_err()
        {
            self.invalidate_authenticated_key(identity);
            return;
        }
        let cached_at = SystemTime::now();
        let timestamp = match cached_at.duration_since(UNIX_EPOCH) {
            Ok(timestamp) => timestamp.as_secs().to_string(),
            Err(error) => {
                log_err!(
                    identity.id as i64,
                    PrintType::General,
                    "Create authenticated key cache timestamp failed: {}",
                    error
                );
                self.invalidate_authenticated_key(identity);
                return;
            }
        };
        if let Err(error) = std::fs::write(authenticated_key_timestamp_path(identity), timestamp) {
            log_err!(
                identity.id as i64,
                PrintType::General,
                "Persist authenticated key cache timestamp failed: {}",
                error
            );
            self.invalidate_authenticated_key(identity);
            return;
        }
        #[cfg(unix)]
        if std::fs::set_permissions(
            authenticated_key_timestamp_path(identity),
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .is_err()
        {
            self.invalidate_authenticated_key(identity);
            return;
        }
        self.authenticated_key_cache.insert(
            identity,
            CachedAuthenticatedKey {
                public_key,
                cached_at,
            },
        );
    }

    pub fn invalidate_authenticated_key(&self, identity: AuthIdentity) {
        self.authenticated_key_cache.remove(&identity);
        for path in [
            authenticated_key_path(identity),
            authenticated_key_timestamp_path(identity),
        ] {
            if let Err(error) = std::fs::remove_file(&path)
                && error.kind() != std::io::ErrorKind::NotFound
            {
                log_err!(
                    identity.id as i64,
                    PrintType::General,
                    "Remove authenticated key cache {} failed: {}",
                    path.display(),
                    error
                );
            }
        }
    }

    #[allow(dead_code)]
    pub async fn close_iota(&self, iota_id: i64) -> Result<(), String> {
        let cv = CommunicationValue::new(CommunicationType::IotaDisconnected)
            .add_typed_default(DataType::IotaId, DataValue::SignedNumber(iota_id.into()));
        let request_id = cv.require_id().map_err(|error| error.to_string())?;
        let result = self.lifecycle_request(&cv).await;
        if let Err(error) = &result {
            self.log_lifecycle_failure("IotaDisconnected", iota_id, None, request_id, error);
            self.sync_client_iota_status().await;
        }
        result
    }

    pub async fn client_disconnected(&self, user_id: i64, session_id: i64) -> Result<(), String> {
        self.session_presence.remove(&(user_id, session_id));
        self.presence_delivery_locks.remove(&(user_id, session_id));
        self.initial_presence_barriers
            .remove(&(user_id, session_id));
        let cv = CommunicationValue::new(CommunicationType::UserDisconnected)
            .add_typed_default(DataType::UserId, DataValue::SignedNumber(user_id.into()))
            .add_typed_default(
                DataType::SessionId,
                DataValue::SignedNumber(session_id.into()),
            );
        let request_id = cv.require_id().map_err(|error| error.to_string())?;
        let result = self.lifecycle_request(&cv).await;
        if let Err(error) = &result {
            self.log_lifecycle_failure(
                "UserDisconnected",
                user_id,
                Some(session_id),
                request_id,
                error,
            );
            self.sync_client_iota_status().await;
        }
        result
    }

    pub async fn user_connected(
        &self,
        user_id: i64,
        session_id: i64,
        iota_id: i64,
    ) -> Result<(), String> {
        let request = CommunicationValue::new(CommunicationType::UserConnected)
            .add_typed_default(DataType::UserId, DataValue::SignedNumber(user_id.into()))
            .add_typed_default(
                DataType::SessionId,
                DataValue::SignedNumber(session_id.into()),
            )
            .add_typed_default(DataType::IotaId, DataValue::SignedNumber(iota_id.into()))
            .add_typed_default(
                DataType::UserState,
                DataValue::Str("user_online".to_string()),
            )
            .add_typed_default(
                DataType::UpdatedAt,
                DataValue::SignedNumber(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as i128,
                ),
            );
        let request_id = request.require_id().map_err(|error| error.to_string())?;
        let result = self.lifecycle_request(&request).await;
        if let Err(error) = &result {
            self.log_lifecycle_failure(
                "UserConnected",
                user_id,
                Some(session_id),
                request_id,
                error,
            );
            self.sync_client_iota_status().await;
        }
        result
    }

    pub async fn iota_connected(&self, iota_id: i64) -> Result<Vec<i64>, String> {
        let request = CommunicationValue::new(CommunicationType::IotaConnected)
            .add_typed_default(DataType::IotaId, DataValue::SignedNumber(iota_id.into()));
        let request_id = request.require_id().map_err(|error| error.to_string())?;
        if !self.is_ready().await {
            return Err("Omega is not synchronized".to_string());
        }
        let result = self
            .await_response(&request, Some(Duration::from_secs(20)))
            .await
            .and_then(|response| {
                iota_activation_snapshot(&response)
                    .filter(|(response_iota_id, _)| *response_iota_id == iota_id)
                    .map(|(_, user_ids)| user_ids)
                    .ok_or_else(|| format!("Omega rejected {}", response.get_type()))
            });
        if let Err(error) = &result {
            self.log_lifecycle_failure("IotaConnected", iota_id, None, request_id, error);
            self.sync_client_iota_status().await;
        }
        result
    }

    #[allow(dead_code)]
    pub async fn reconcile_routes(&self) {
        self.sync_client_iota_status().await;
    }

    async fn lifecycle_request(&self, request: &CommunicationValue) -> Result<(), String> {
        if !self.is_ready().await {
            return Err("Omega is not synchronized".to_string());
        }
        if !self.peer_capabilities.read().await.session_snapshot_v1 {
            // Legacy Omega handles lifecycle messages as notifications and
            // never returns Success. A transport-level send result is the
            // only acknowledgement available under that contract.
            return self.send_message_result(request).await;
        }
        let response = self
            .await_response(request, Some(Duration::from_secs(20)))
            .await?;
        if response.is_type(CommunicationType::Success) {
            Ok(())
        } else {
            Err(format!("Omega rejected {}", response.get_type()))
        }
    }

    fn log_lifecycle_failure(
        &self,
        operation: &str,
        entity_id: i64,
        session_id: Option<i64>,
        request_id: u32,
        error: &str,
    ) {
        log_err!(
            0,
            PrintType::Omega,
            "Lifecycle operation={} entity_id={} session_id={:?} request_id={} failed: {}",
            operation,
            entity_id,
            session_id,
            request_id,
            error
        );
    }

    pub async fn replace_state_subscription(
        &self,
        user_id: i64,
        session_id: i64,
        user_ids: Vec<i64>,
    ) -> Result<(), String> {
        if user_id <= 0 || session_id <= 0 {
            return Err("invalid user or session id".to_string());
        }

        let user_ids = normalize_presence_user_ids(user_ids)?;

        let key = (user_id, session_id);
        // Store the latest authoritative snapshot before checking readiness.
        // A client can synchronize while the transport is reconnecting.
        let generation = self.replace_desired_presence_state(key, user_ids.clone());

        if !self.is_ready().await {
            return Err("Omega is not synchronized".to_string());
        }

        self.deliver_state_subscription(key, user_ids, generation)
            .await
            .map_err(|error| error.to_string())
    }

    /// Installs the subscription before retrieving the snapshot so no presence
    /// transition is missed between those operations.  The caller composes the
    /// returned snapshot into its initial state response.
    pub async fn initial_presence_snapshot(
        &self,
        user_id: i64,
        session_id: i64,
        user_ids: Vec<i64>,
    ) -> Result<CommunicationValue, InitialPresenceError> {
        let key = (user_id, session_id);
        let user_ids =
            normalize_presence_user_ids(user_ids).map_err(InitialPresenceError::InvalidSnapshot)?;
        let generation = self.replace_desired_presence_state(key, user_ids.clone());
        if !self.is_ready().await {
            return Err(InitialPresenceError::OmegaUnavailable(
                "Omega is not synchronized".into(),
            ));
        }
        if self.initial_presence_barriers.contains_key(&key) {
            return Err(InitialPresenceError::AlreadyInProgress);
        }
        self.initial_presence_barriers
            .insert(key, Arc::new(Mutex::new(InitialPresenceBarrier::default())));
        let subscription = CommunicationValue::new(CommunicationType::StateSubscribe)
            .with_sender(user_id as u64)
            .add_typed_default(
                DataType::SessionId,
                DataValue::SignedNumber(session_id.into()),
            )
            .add_typed_default(
                DataType::UserIds,
                DataValue::Array(
                    user_ids
                        .iter()
                        .map(|id| DataValue::SignedNumber((*id).into()))
                        .collect(),
                ),
            );
        if self.peer_capabilities.read().await.state_subscribe_v1 {
            let subscribed = self
                .await_response(&subscription, Some(Duration::from_secs(20)))
                .await
                .map_err(InitialPresenceError::OmegaUnavailable)?;
            if !subscribed.is_type(CommunicationType::Success) {
                self.abort_initial_presence_sync(user_id, session_id);
                return Err(InitialPresenceError::SubscriptionRejected(
                    subscribed.get_type().to_string(),
                ));
            }
        }
        let response = self
            .fetch_user_states_snapshot(user_id, session_id, &user_ids)
            .await?;
        if let Some(barrier) = self
            .initial_presence_barriers
            .get(&key)
            .map(|entry| entry.clone())
            && barrier.lock().await.overflowed
        {
            self.abort_initial_presence_sync(user_id, session_id);
            return Err(InitialPresenceError::OrderingLost);
        }
        if !self.is_current_presence_generation(key, generation) {
            self.abort_initial_presence_sync(user_id, session_id);
            return Err(InitialPresenceError::InvalidSnapshot(
                "presence subscription changed while the snapshot was fetched".into(),
            ));
        }
        self.mark_presence_delivered(key, generation).await;
        Ok(response)
    }

    fn replace_desired_presence_state(&self, key: (i64, i64), user_ids: Vec<i64>) -> u64 {
        self.session_presence
            .entry(key)
            .and_modify(|entry| {
                entry.subscribed_user_ids = user_ids.clone();
                entry.pending = true;
                entry.generation = entry.generation.saturating_add(1);
            })
            .or_insert_with(|| SessionPresenceState {
                subscribed_user_ids: user_ids,
                pending: true,
                generation: 1,
            })
            .generation
    }

    async fn buffer_initial_presence_event(
        &self,
        key: (i64, i64),
        event: CommunicationValue,
    ) -> PresenceBufferResult {
        let Some(barrier) = self
            .initial_presence_barriers
            .get(&key)
            .map(|entry| entry.clone())
        else {
            return PresenceBufferResult::NotBuffered;
        };
        let mut barrier = barrier.lock().await;
        if barrier.live {
            return PresenceBufferResult::NotBuffered;
        }
        if barrier.overflowed {
            return PresenceBufferResult::OrderingLost;
        }
        if barrier.queued.len() >= MAX_INITIAL_PRESENCE_BUFFERED_EVENTS {
            barrier.overflowed = true;
            return PresenceBufferResult::OrderingLost;
        }
        barrier.queued.push_back(event);
        PresenceBufferResult::Buffered
    }

    async fn forward_client_changed(
        &self,
        user_id: i64,
        session_id: i64,
        event: &CommunicationValue,
    ) {
        if let Some(client) = self.rho.get_client_connection(user_id, session_id).await {
            let _ = client
                .send_or_buffer_post_initial_state(event.clone())
                .await;
        }
    }

    pub async fn finish_initial_presence_sync(
        &self,
        user_id: i64,
        session_id: i64,
    ) -> Result<(), InitialPresenceError> {
        let key = (user_id, session_id);
        let Some(barrier) = self
            .initial_presence_barriers
            .get(&key)
            .map(|entry| entry.clone())
        else {
            return Ok(());
        };
        loop {
            let next = {
                let mut state = barrier.lock().await;
                if state.overflowed {
                    drop(state);
                    self.abort_initial_presence_sync(user_id, session_id);
                    return Err(InitialPresenceError::OrderingLost);
                }
                match state.queued.pop_front() {
                    Some(event) => Some(event),
                    None => {
                        state.live = true;
                        None
                    }
                }
            };
            let Some(event) = next else {
                self.initial_presence_barriers.remove(&key);
                return Ok(());
            };
            self.forward_client_changed(user_id, session_id, &event)
                .await;
        }
    }

    pub fn abort_initial_presence_sync(&self, user_id: i64, session_id: i64) {
        self.initial_presence_barriers
            .remove(&(user_id, session_id));
    }

    async fn deliver_state_subscription(
        &self,
        key: (i64, i64),
        user_ids: Vec<i64>,
        generation: u64,
    ) -> Result<(), InitialPresenceError> {
        let (user_id, session_id) = key;
        let delivery_lock = self
            .presence_delivery_locks
            .entry(key)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone();
        let _delivery_guard = delivery_lock.lock().await;

        // Replacements can be requested concurrently.  Serializing transport
        // side effects ensures that the current generation is installed last.
        if !self.is_current_presence_generation(key, generation) {
            return Ok(());
        }

        if !self.peer_capabilities.read().await.state_subscribe_v1 {
            let result = self
                .request_user_states(user_id, session_id, user_ids, generation)
                .await;
            if result.is_ok() {
                self.mark_presence_delivered(key, generation).await;
            }
            return result;
        }

        let subscription = CommunicationValue::new(CommunicationType::StateSubscribe)
            .with_sender(user_id as u64)
            .add_typed_default(
                DataType::SessionId,
                DataValue::SignedNumber(session_id.into()),
            )
            .add_typed_default(
                DataType::UserIds,
                DataValue::Array(
                    user_ids
                        .iter()
                        .map(|user_id| DataValue::SignedNumber((*user_id).into()))
                        .collect(),
                ),
            );
        log_out!(
            user_id,
            PrintType::Omega,
            "PresenceSync user={} session={} stage=subscribe",
            user_id,
            session_id
        );
        let response = self
            .await_response(&subscription, Some(Duration::from_secs(20)))
            .await
            .map_err(InitialPresenceError::OmegaUnavailable)?;
        if !response.is_type(CommunicationType::Success) {
            return Err(InitialPresenceError::SubscriptionRejected(format!(
                "StateSubscribe rejected with {}",
                response.get_type()
            )));
        }

        self.request_user_states(user_id, session_id, user_ids, generation)
            .await?;
        self.mark_presence_delivered(key, generation).await;
        Ok(())
    }

    async fn restore_presence_subscriptions(&self) -> Result<(), String> {
        let mut active = Vec::new();
        for rho in self.rho.connections().await {
            active.extend(rho.get_client_connections().await);
        }
        let active_keys: std::collections::HashSet<_> = active
            .iter()
            .map(|client| (client.user_id as i64, client.session_id as i64))
            .collect();

        // Do not replay subscriptions for sessions that disappeared while the
        // transport was down.
        self.session_presence
            .retain(|key, _| active_keys.contains(key));

        // A fresh Omega transport has no connection-local subscription state.
        // Every desired subscription must be installed again, even one that was
        // delivered successfully on the previous transport.
        for mut entry in self.session_presence.iter_mut() {
            entry.pending = true;
        }

        loop {
            let pending: Vec<_> = active_keys
                .iter()
                .filter_map(|key| {
                    self.session_presence.get(key).and_then(|entry| {
                        entry
                            .pending
                            .then(|| (*key, entry.subscribed_user_ids.clone(), entry.generation))
                    })
                })
                .collect();
            if pending.is_empty() {
                break;
            }
            for (key, user_ids, generation) in pending {
                self.deliver_state_subscription(key, user_ids, generation)
                    .await
                    .map_err(|error| error.to_string())?;
            }
        }
        Ok(())
    }

    async fn mark_presence_delivered(&self, key: (i64, i64), generation: u64) {
        if let Some(mut entry) = self.session_presence.get_mut(&key)
            && entry.generation == generation
        {
            entry.pending = false;
        }
    }

    async fn fetch_user_states_snapshot(
        &self,
        user_id: i64,
        session_id: i64,
        user_ids: &[i64],
    ) -> Result<CommunicationValue, InitialPresenceError> {
        let request = CommunicationValue::new(CommunicationType::GetStates)
            .add_typed_default(
                DataType::SessionId,
                DataValue::SignedNumber(session_id.into()),
            )
            .add_typed_default(
                DataType::UserIds,
                DataValue::Array(
                    user_ids
                        .iter()
                        .map(|user_id| DataValue::SignedNumber((*user_id).into()))
                        .collect(),
                ),
            );
        log_out!(
            user_id,
            PrintType::Omega,
            "PresenceSync user={} session={} stage=get_states",
            user_id,
            session_id
        );
        let mut response = self
            .await_response(&request, Some(Duration::from_secs(20)))
            .await
            .map_err(InitialPresenceError::OmegaUnavailable)?;
        if !response.is_type(CommunicationType::GetStates) {
            return Err(InitialPresenceError::InvalidSnapshot(
                "expected GetStates response".into(),
            ));
        }
        let legacy_peer = !self.peer_capabilities.read().await.client_state_push_v1;
        match response.get_data(DataType::SessionId).as_number() {
            Some(id) if id == session_id as i128 => {}
            None if legacy_peer => {
                response = response.add_typed_default(
                    DataType::SessionId,
                    DataValue::SignedNumber(session_id.into()),
                );
            }
            _ => {
                return Err(InitialPresenceError::InvalidSnapshot(
                    "GetStates response had the wrong session".into(),
                ));
            }
        }
        if !matches!(
            response.get_data(DataType::UserStates),
            Some(DataValue::Array(_))
        ) {
            return Err(InitialPresenceError::InvalidSnapshot(
                "GetStates response is missing UserStates".into(),
            ));
        }
        if !matches!(
            response.get_data(DataType::MissingUserIds),
            Some(DataValue::Array(_))
        ) {
            if legacy_peer && response.get_data(DataType::MissingUserIds).is_none() {
                response = response
                    .add_typed_default(DataType::MissingUserIds, DataValue::Array(Vec::new()));
            } else {
                return Err(InitialPresenceError::InvalidSnapshot(
                    "GetStates response is missing or has invalid MissingUserIds".into(),
                ));
            }
        }
        Ok(response)
    }

    async fn request_user_states(
        &self,
        user_id: i64,
        session_id: i64,
        user_ids: Vec<i64>,
        generation: u64,
    ) -> Result<(), InitialPresenceError> {
        let response = self
            .fetch_user_states_snapshot(user_id, session_id, &user_ids)
            .await?;

        if self.is_current_presence_generation((user_id, session_id), generation)
            && let Some(client) = self.rho.get_client_connection(user_id, session_id).await
        {
            client
                .send_or_buffer_post_initial_state(response)
                .await
                .map_err(|_| InitialPresenceError::OrderingLost)?;
            log_out!(
                user_id,
                PrintType::Client,
                "PresenceSync user={} session={} stage=get_states_forwarded",
                user_id,
                session_id
            );
        }
        Ok(())
    }

    fn is_current_presence_generation(&self, key: (i64, i64), generation: u64) -> bool {
        self.session_presence
            .get(&key)
            .is_some_and(|entry| entry.generation == generation)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AuthIdentity, AuthIdentityKind, CachedAuthenticatedKey, ConnectionOutcome,
        MAX_RECONNECT_DELAY, PeerCapabilities, RECONNECT_DELAY, WaitingTask,
        allocate_omega_request_id, authenticated_key_path, cached_at_is_fresh,
        client_changed_target, complete_waiting_task, iota_activation_snapshot, iota_user_snapshot,
        omega_transport_policy, parse_omega_capability_response, reconnect_base_after_outcome,
        reconnect_delay_with_jitter, signed_positive_iota_id,
    };
    use crate::config::TransportConfig;
    use dashmap::DashMap;
    use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
    use mtp::crypto::Keyring;
    use std::{
        sync::atomic::{AtomicU32, Ordering},
        time::{Duration, SystemTime},
    };
    use tokio::{sync::oneshot, time::Instant};

    #[test]
    fn omega_transport_policy_uses_configured_message_limits() {
        let policy = omega_transport_policy(&TransportConfig {
            max_message_size: 123,
            handshake_max_message_size: 45,
        });

        assert_eq!(policy.max_message_size, 123);
        assert_eq!(policy.handshake_max_message_size, 45);
    }

    #[tokio::test]
    async fn transport_ids_keep_matching_local_request_ids_separate() {
        let waiting_tasks = DashMap::new();
        let next_request_id = AtomicU32::new(0);
        let (first_tx, first_rx) = oneshot::channel();
        let first_omega_id = allocate_omega_request_id(&next_request_id, &waiting_tasks);
        waiting_tasks.insert(
            first_omega_id,
            WaitingTask {
                original_id: 42,
                sender: first_tx,
                inserted_at: Instant::now(),
            },
        );
        next_request_id.store(first_omega_id, Ordering::Relaxed);
        let (second_tx, second_rx) = oneshot::channel();
        let second_omega_id = allocate_omega_request_id(&next_request_id, &waiting_tasks);
        waiting_tasks.insert(
            second_omega_id,
            WaitingTask {
                original_id: 42,
                sender: second_tx,
                inserted_at: Instant::now(),
            },
        );

        assert_ne!(first_omega_id, second_omega_id);
        assert!(complete_waiting_task(
            &waiting_tasks,
            second_omega_id,
            CommunicationValue::new(CommunicationType::Success).with_id(second_omega_id),
        ));
        assert!(complete_waiting_task(
            &waiting_tasks,
            first_omega_id,
            CommunicationValue::new(CommunicationType::ErrorInternal).with_id(first_omega_id),
        ));

        let Ok(first) = first_rx.await else {
            panic!("first response channel closed");
        };
        let Ok(second) = second_rx.await else {
            panic!("second response channel closed");
        };
        assert_eq!(first.id(), Some(42));
        assert!(first.is_type(CommunicationType::ErrorInternal));
        assert_eq!(second.id(), Some(42));
        assert!(second.is_type(CommunicationType::Success));
    }

    #[test]
    fn authenticated_key_cache_separates_clients_and_iotas_with_the_same_id() {
        let cache = DashMap::<AuthIdentity, CachedAuthenticatedKey>::new();
        let client = AuthIdentity {
            kind: AuthIdentityKind::Client,
            id: 42,
        };
        let iota = AuthIdentity {
            kind: AuthIdentityKind::Iota,
            id: 42,
        };
        let client_key = Keyring::generate().public_key_bundle();
        let iota_key = Keyring::generate().public_key_bundle();

        cache.insert(
            client,
            CachedAuthenticatedKey {
                public_key: client_key.clone(),
                cached_at: SystemTime::now(),
            },
        );
        cache.insert(
            iota,
            CachedAuthenticatedKey {
                public_key: iota_key.clone(),
                cached_at: SystemTime::now(),
            },
        );

        assert_eq!(cache.len(), 2);
        assert_eq!(
            cache
                .get(&client)
                .unwrap()
                .public_key
                .try_as_bytes()
                .unwrap(),
            client_key.try_as_bytes().unwrap()
        );
        assert_eq!(
            cache.get(&iota).unwrap().public_key.try_as_bytes().unwrap(),
            iota_key.try_as_bytes().unwrap()
        );
    }

    #[test]
    fn authenticated_key_cache_rejects_expired_and_future_timestamps() {
        let now = SystemTime::now();
        let max_age = Duration::from_secs(24 * 60 * 60);
        assert!(cached_at_is_fresh(now, now, max_age));
        assert!(!cached_at_is_fresh(
            now,
            now - max_age - Duration::from_secs(1),
            max_age
        ));
        assert!(!cached_at_is_fresh(
            now,
            now + Duration::from_secs(1),
            max_age
        ));
    }

    #[test]
    fn authenticated_key_paths_use_separate_namespaces() {
        let client_path = authenticated_key_path(AuthIdentity {
            kind: AuthIdentityKind::Client,
            id: 42,
        });
        let iota_path = authenticated_key_path(AuthIdentity {
            kind: AuthIdentityKind::Iota,
            id: 42,
        });

        assert_ne!(client_path, iota_path);
        assert!(client_path.ends_with("authenticated-public-keys/client/42.mpkb"));
        assert!(iota_path.ends_with("authenticated-public-keys/iota/42.mpkb"));
    }

    fn notification() -> CommunicationValue {
        CommunicationValue::new(CommunicationType::ClientChanged)
            .with_receiver(7)
            .add_typed_default(DataType::SessionId, DataValue::SignedNumber(11))
            .add_typed_default(DataType::UserId, DataValue::SignedNumber(20))
            .add_typed_default(DataType::UserState, DataValue::Str("user_online".into()))
    }

    #[test]
    fn client_changed_target_requires_all_routing_fields() {
        assert_eq!(client_changed_target(&notification()), Some((7, 11)));

        let mut missing_session = notification();
        missing_session.remove_data(DataType::SessionId);
        assert_eq!(client_changed_target(&missing_session), None);

        let mut missing_state = notification();
        missing_state.remove_data(DataType::UserState);
        assert_eq!(client_changed_target(&missing_state), None);

        let missing_receiver = notification().without_receiver();
        assert_eq!(client_changed_target(&missing_receiver), None);
    }

    #[test]
    fn client_changed_target_rejects_non_positive_ids() {
        let invalid = CommunicationValue::new(CommunicationType::ClientChanged)
            .with_receiver(0)
            .add_typed_default(DataType::SessionId, DataValue::SignedNumber(11))
            .add_typed_default(DataType::UserId, DataValue::SignedNumber(20))
            .add_typed_default(DataType::UserState, DataValue::Str("user_online".into()));
        assert_eq!(client_changed_target(&invalid), None);
    }

    #[test]
    fn iota_user_snapshot_requires_its_iota_and_valid_user_ids() {
        let snapshot = CommunicationValue::new(CommunicationType::IotaUserData)
            .add_typed_default(DataType::IotaId, DataValue::SignedNumber(8))
            .add_typed_default(
                DataType::UserIds,
                DataValue::Array(vec![
                    DataValue::SignedNumber(20),
                    DataValue::SignedNumber(19),
                    DataValue::SignedNumber(20),
                ]),
            );
        assert_eq!(iota_user_snapshot(&snapshot), Some((8, vec![19, 20])));

        let activation = CommunicationValue::new(CommunicationType::Success)
            .add_typed_default(DataType::IotaId, DataValue::SignedNumber(8))
            .add_typed_default(
                DataType::UserIds,
                DataValue::Array(vec![DataValue::SignedNumber(20)]),
            );
        assert_eq!(iota_activation_snapshot(&activation), Some((8, vec![20])));

        let missing_iota = CommunicationValue::new(CommunicationType::IotaUserData)
            .add_typed_default(DataType::UserIds, DataValue::Array(Vec::new()));
        assert_eq!(iota_user_snapshot(&missing_iota), None);

        let malformed_user = CommunicationValue::new(CommunicationType::IotaUserData)
            .add_typed_default(DataType::IotaId, DataValue::SignedNumber(8))
            .add_typed_default(
                DataType::UserIds,
                DataValue::Array(vec![DataValue::Str("not-a-user".into())]),
            );
        assert_eq!(iota_user_snapshot(&malformed_user), None);
    }

    #[test]
    fn erasure_route_reads_omega_signed_iota_id() {
        let frame = CommunicationValue::new(CommunicationType::EraseHostedUserData)
            .add_typed_default(DataType::IotaId, DataValue::SignedNumber(8));
        assert_eq!(signed_positive_iota_id(&frame), Some(8));

        let unsigned = CommunicationValue::new(CommunicationType::EraseHostedUserData)
            .add_typed_default(DataType::IotaId, DataValue::UnsignedNumber(8));
        assert_eq!(signed_positive_iota_id(&unsigned), None);
    }

    #[test]
    fn reconnect_jitter_is_bounded_without_changing_the_base_delay() {
        for _ in 0..32 {
            let delay = reconnect_delay_with_jitter(RECONNECT_DELAY);
            assert!(delay >= RECONNECT_DELAY);
            assert!(delay <= RECONNECT_DELAY + std::time::Duration::from_secs(1));
        }

        assert!(MAX_RECONNECT_DELAY > RECONNECT_DELAY);
    }

    #[test]
    fn healthy_session_resets_accumulated_reconnect_backoff() {
        let mut delay = RECONNECT_DELAY;
        for _ in 0..4 {
            delay = std::cmp::min(delay * 2, MAX_RECONNECT_DELAY);
        }
        assert!(delay > RECONNECT_DELAY);

        assert_eq!(
            reconnect_base_after_outcome(delay, ConnectionOutcome::FailedBeforeHealthy),
            delay
        );
        assert_eq!(
            reconnect_base_after_outcome(delay, ConnectionOutcome::HealthySessionEnded),
            RECONNECT_DELAY
        );
    }

    #[test]
    fn capability_response_negotiates_new_omega() {
        let response = CommunicationValue::new(CommunicationType::IdentificationResponse)
            .add_typed_default(
                DataType::Description,
                DataValue::Str(
                    "omega;caps=set_user_state_v1,state_subscribe_v1,session_snapshot_v1,client_state_push_v1"
                        .into(),
                ),
            );
        let capabilities = parse_omega_capability_response(&response).unwrap();
        assert!(capabilities.state_subscribe_v1);
        assert!(capabilities.client_state_push_v1);
    }

    #[test]
    fn missing_capability_response_is_legacy() {
        let response = CommunicationValue::new(CommunicationType::IdentificationResponse);
        let capabilities = parse_omega_capability_response(&response).unwrap();
        assert_eq!(capabilities, PeerCapabilities::default());
    }

    #[test]
    fn unsupported_capability_response_is_rejected() {
        let response = CommunicationValue::new(CommunicationType::IdentificationResponse)
            .add_typed_default(
                DataType::Description,
                DataValue::Str("omega;caps=unsupported_v9".into()),
            );
        assert!(parse_omega_capability_response(&response).is_err());
    }
}
