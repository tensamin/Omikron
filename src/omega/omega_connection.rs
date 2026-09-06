use super::capabilities::PeerCapabilities;
use crate::{
    config::Config,
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
use std::{sync::Arc, time::Duration};
use tokio::{
    sync::{Mutex, RwLock, mpsc, oneshot, watch},
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
const TASK_MAX_AGE: Duration = Duration::from_secs(60);
const MAX_CONCURRENT_REQUESTS: usize = 128;
const CIRCUIT_BREAKER_FAILURE_THRESHOLD: u32 = 3;
const CIRCUIT_BREAKER_COOLDOWN: Duration = Duration::from_secs(30);

fn authenticated_key_path(client_id: u64) -> std::path::PathBuf {
    crate::WORKING_DIR
        .join("iota-public-keys")
        .join(format!("{client_id}.mpkb"))
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

fn iota_user_snapshot(value: &CommunicationValue) -> Option<(i64, Vec<i64>)> {
    if !value.is_type(CommunicationType::IotaUserData) {
        return None;
    }
    let iota_id = value
        .get_data(DataType::IotaId)
        .as_number()
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
    pub task: Box<dyn Fn(Arc<OmegaConnection>, CommunicationValue) -> bool + Send + Sync>,
    pub inserted_at: Instant,
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
    pub connection_id: Uuid,
    shutdown_tx: Arc<Mutex<Option<watch::Sender<bool>>>>,
    // Track if we should reconnect on close
    reconnect_on_close: Arc<RwLock<bool>>,
    request_slots: tokio::sync::Semaphore,
    circuit_breaker: Mutex<CircuitBreaker>,
    keyring: mtp::crypto::Keyring,
    rho: Arc<RhoManager>,
    authenticated_key_cache: DashMap<u64, mtp::crypto::PublicKeyBundle>,
    waiting_tasks: DashMap<u32, WaitingTask>,
    session_presence: DashMap<(i64, i64), SessionPresenceState>,
    peer_capabilities: Arc<RwLock<PeerCapabilities>>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SessionPresenceState {
    pub subscribed_user_ids: Vec<i64>,
    pub pending: bool,
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
            connection_id: Uuid::new_v4(),
            shutdown_tx: Arc::new(Mutex::new(Some(shutdown_tx))),
            reconnect_on_close: Arc::new(RwLock::new(true)),
            request_slots: tokio::sync::Semaphore::new(MAX_CONCURRENT_REQUESTS),
            circuit_breaker: Mutex::new(CircuitBreaker {
                consecutive_failures: 0,
                open_until: None,
            }),
            keyring,
            rho,
            authenticated_key_cache: DashMap::new(),
            waiting_tasks: DashMap::new(),
            session_presence: DashMap::new(),
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
            .with_policy(
                Policy::default()
                    .with_send_mode(SendMode::SingleStreamPerMessage)
                    .with_timeouts(
                        Duration::from_millis(5_000),
                        Duration::from_millis(5_000),
                        Duration::from_millis(30_000),
                    )
                    .with_keep_alive(Some(Duration::from_secs(6)))
                    .with_max_idle_timeout(Some(Duration::from_secs(30)))
                    .with_receiver_queue_capacity(1000)
                    .with_max_concurrent_stream_tasks(64)
                    .with_persistent_stream_retries(5, Duration::from_secs(5)),
            )
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

        match result {
            Ok(()) if reached_healthy_state => Ok(ConnectionOutcome::HealthySessionEnded),
            Ok(()) => Ok(ConnectionOutcome::FailedBeforeHealthy),
            Err(e) => Err(format!("Read loop error: {}", e)),
        }
    }

    async fn sync_client_iota_status(&self) -> bool {
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
                            if let Some((_, task)) = self.waiting_tasks.remove(&msg_id) {
                                if (task.task)(self.clone(), cv.clone()) {
                                    continue;
                                }
                            }

                            if cv.is_type(CommunicationType::EraseHostedUserData) {
                                let Some(iota_id) = cv
                                    .get_data(DataType::IotaId)
                                    .as_number()
                                    .and_then(|id| i64::try_from(id).ok())
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
                            if cv.is_type(CommunicationType::ClientChanged) {
                                let Some((receiver, session_id)) = client_changed_target(&cv)
                                else {
                                    continue;
                                };
                                if let Some(client) = self
                                    .rho
                                    .get_client_connection(receiver, session_id)
                                    .await
                                {
                                    client.send_message(&cv).await;
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
        let msg_id = cv
            .require_id()
            .map_err(|error| format!("request is missing correlation id: {error}"))?;
        self.await_connection(timeout_duration).await?;

        let (tx, mut rx) = mpsc::channel(1);

        self.waiting_tasks.insert(
            msg_id,
            WaitingTask {
                task: Box::new(move |_, response_cv| {
                    log_in!(
                        0,
                        PrintType::Omega,
                        "Matched Omega response (request_id={}, response_id={:?}, type={})",
                        msg_id,
                        response_cv.id(),
                        response_cv
                            .get_comm_type_enum()
                            .map(|kind| kind.to_string())
                            .unwrap_or_else(|| response_cv.get_type().to_string())
                    );
                    let inner_tx = tx.clone();
                    tokio::spawn(async move {
                        let _ = inner_tx.send(response_cv).await;
                    });
                    true
                }),
                inserted_at: Instant::now(),
            },
        );

        if let Err(error) = self.try_send_message(cv).await {
            self.waiting_tasks.remove(&msg_id);
            return Err(format!("failed to send request: {error}"));
        }
        log_out!(
            0,
            PrintType::Omega,
            "Sent Omega request (request_id={}, type={})",
            msg_id,
            cv.get_comm_type_enum()
                .map(|kind| kind.to_string())
                .unwrap_or_else(|| cv.get_type().to_string())
        );

        let timeout = timeout_duration.unwrap_or(Duration::from_secs(10));

        match tokio::time::timeout(timeout, rx.recv()).await {
            Ok(Some(response_cv)) => Ok(response_cv),
            Ok(_) => Err("Channel closed".to_string()),
            Err(_) => {
                self.waiting_tasks.remove(&msg_id);
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

    pub async fn await_ready(&self) {
        while !self.is_ready().await {
            sleep(Duration::from_millis(100)).await;
        }
    }

    pub fn cached_authenticated_key(&self, client_id: u64) -> Option<mtp::crypto::PublicKeyBundle> {
        if let Some(key) = self
            .authenticated_key_cache
            .get(&client_id)
            .map(|key| key.clone())
        {
            return Some(key);
        }

        let key = load_public_key_bundle(&authenticated_key_path(client_id)).ok()?;
        self.authenticated_key_cache.insert(client_id, key.clone());
        Some(key)
    }

    pub fn cache_authenticated_key(
        &self,
        client_id: u64,
        public_key: mtp::crypto::PublicKeyBundle,
    ) {
        let path = authenticated_key_path(client_id);
        if let Some(parent) = path.parent() {
            if let Err(error) = std::fs::create_dir_all(parent) {
                log_err!(
                    client_id as i64,
                    PrintType::General,
                    "Create authenticated key cache directory failed: {}",
                    error
                );
                return;
            }
        }
        if let Err(error) = save_public_key_bundle(&public_key, &path) {
            log_err!(
                client_id as i64,
                PrintType::General,
                "Persist authenticated key cache failed: {}",
                error
            );
            return;
        }
        self.authenticated_key_cache.insert(client_id, public_key);
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

    pub async fn iota_connected(&self, iota_id: i64) -> Result<(), String> {
        let request = CommunicationValue::new(CommunicationType::IotaConnected)
            .add_typed_default(DataType::IotaId, DataValue::SignedNumber(iota_id.into()));
        let request_id = request.require_id().map_err(|error| error.to_string())?;
        let result = self.lifecycle_request(&request).await;
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
        mut user_ids: Vec<i64>,
    ) -> Result<(), String> {
        if user_id <= 0 || session_id <= 0 {
            return Err("invalid user or session id".to_string());
        }

        user_ids.sort_unstable();
        user_ids.dedup();

        let key = (user_id, session_id);
        // Store the latest authoritative snapshot before checking readiness.
        // A client can synchronize while the transport is reconnecting.
        self.session_presence.insert(
            key,
            SessionPresenceState {
                subscribed_user_ids: user_ids.clone(),
                pending: true,
            },
        );

        if !self.is_ready().await {
            return Err("Omega is not synchronized".to_string());
        }

        self.deliver_state_subscription(key, user_ids).await
    }

    async fn deliver_state_subscription(
        &self,
        key: (i64, i64),
        user_ids: Vec<i64>,
    ) -> Result<(), String> {
        let (user_id, session_id) = key;

        if !self.peer_capabilities.read().await.state_subscribe_v1 {
            let delivered_ids = user_ids.clone();
            let result = self
                .request_user_states(user_id, session_id, user_ids)
                .await;
            if result.is_ok() {
                self.mark_presence_delivered(key, &delivered_ids).await;
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
            .await?;
        if !response.is_type(CommunicationType::Success) {
            return Err(format!(
                "StateSubscribe rejected with {}",
                response.get_type()
            ));
        }

        let delivered_ids = user_ids.clone();
        self.request_user_states(user_id, session_id, user_ids)
            .await?;
        self.mark_presence_delivered(key, &delivered_ids).await;
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

        for key in active_keys {
            let Some(snapshot) = self.session_presence.get(&key).map(|entry| entry.clone()) else {
                continue;
            };
            if !snapshot.pending {
                continue;
            }
            self.deliver_state_subscription(key, snapshot.subscribed_user_ids)
                .await?;
        }
        Ok(())
    }

    async fn mark_presence_delivered(&self, key: (i64, i64), delivered_ids: &[i64]) {
        if let Some(mut entry) = self.session_presence.get_mut(&key)
            && entry.subscribed_user_ids == delivered_ids
        {
            entry.pending = false;
        }
    }

    async fn request_user_states(
        &self,
        user_id: i64,
        session_id: i64,
        user_ids: Vec<i64>,
    ) -> Result<(), String> {
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
        let response = self
            .await_response(&request, Some(Duration::from_secs(20)))
            .await?;
        let legacy_peer = !self.peer_capabilities.read().await.client_state_push_v1;
        let response =
            if legacy_peer && response.get_data(DataType::SessionId).as_number().is_none() {
                response.add_typed_default(
                    DataType::SessionId,
                    DataValue::SignedNumber(session_id.into()),
                )
            } else {
                response
            };
        if !legacy_peer
            && response.get_data(DataType::SessionId).as_number() != Some(session_id as i128)
        {
            return Err("GetStates response had the wrong session".to_string());
        }

        if let Some(client) = self.rho.get_client_connection(user_id, session_id).await {
            client.send_message(&response).await;
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
}

#[cfg(test)]
mod tests {
    use super::{
        ConnectionOutcome, MAX_RECONNECT_DELAY, PeerCapabilities, RECONNECT_DELAY,
        client_changed_target, iota_user_snapshot, parse_omega_capability_response,
        reconnect_base_after_outcome, reconnect_delay_with_jitter,
    };
    use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};

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
