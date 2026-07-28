use crate::{
    config::Config, data::user::UserStatus, log_cv_in, log_cv_out, log_err, log_in, log_out,
    rho::rho_manager::RhoManager, util::logger::PrintType,
};
use dashmap::DashMap;
use mtp::client::{Client, MTPConnection, Sender};
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use mtp::{
    client::ClientConfig,
    files::load_public_key_bundle,
    host::{Policy, SendMode},
};
use mtp_transport::ConnectionHandle;
use std::{sync::Arc, time::Duration};
use tokio::{
    sync::{Mutex, RwLock, mpsc, watch},
    task::JoinHandle,
    time::{Instant, sleep},
};

use uuid::Uuid;

const RECONNECT_DELAY: Duration = Duration::from_secs(5);
const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(300);
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);
const PING_INTERVAL: Duration = Duration::from_secs(5);
const TASK_CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
const TASK_MAX_AGE: Duration = Duration::from_secs(60);
const MAX_CONCURRENT_REQUESTS: usize = 128;
const CIRCUIT_BREAKER_FAILURE_THRESHOLD: u32 = 3;
const CIRCUIT_BREAKER_COOLDOWN: Duration = Duration::from_secs(30);

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
    Connected { identified: bool },
}

#[allow(unused_variables)]
impl ConnectionState {
    pub fn is_connected(&self) -> bool {
        match self {
            ConnectionState::Connected { identified } => true,
            _ => false,
        }
    }

    #[allow(dead_code)]
    pub fn is_identified(&self) -> bool {
        match self {
            ConnectionState::Connected { identified: true } => true,
            _ => false,
        }
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
    pub connection_id: Uuid,
    shutdown_tx: Arc<Mutex<Option<watch::Sender<bool>>>>,
    // Track if we should reconnect on close
    reconnect_on_close: Arc<RwLock<bool>>,
    request_slots: tokio::sync::Semaphore,
    circuit_breaker: Mutex<CircuitBreaker>,
    keyring: mtp::crypto::Keyring,
    rho: Arc<RhoManager>,
    waiting_tasks: DashMap<u32, WaitingTask>,
}

impl OmegaConnection {
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
            waiting_tasks: DashMap::new(),
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
                Ok(()) => {
                    // Connection closed gracefully, check if we should reconnect
                    if *self.reconnect_on_close.read().await {
                        log_err!(
                            0,
                            PrintType::Omega,
                            "Connection lost, reconnecting in {:?}...",
                            reconnect_delay
                        );
                    } else {
                        log_in!(0, PrintType::Omega, "Connection closed, not reconnecting");
                        break;
                    }
                }
                Err(e) => {
                    log_err!(
                        0,
                        PrintType::Omega,
                        "Connection failed: {}, retrying in {:?}...",
                        e,
                        reconnect_delay
                    );
                }
            }

            tokio::select! {
                _ = sleep(reconnect_delay) => {}
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
            }

            reconnect_delay = std::cmp::min(reconnect_delay * 2, MAX_RECONNECT_DELAY);
        }
    }

    async fn connect_once(self: Arc<Self>) -> Result<(), String> {
        *self.state.write().await = ConnectionState::Connecting;

        let client_config = ClientConfig::new(format!("https://{}:{}", self.host, self.port))
            .with_client_id(self.omikron_id)
            .with_policy(
                Policy::default()
                    .with_send_mode(SendMode::SingleStreamPerMessage)
                    .with_max_message_size(1_000_000_000)
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
            .with_ping_interval(PING_INTERVAL)
            .with_max_missed_pings(0);

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
        *self.state.write().await = ConnectionState::Connected { identified: false };

        // Get handle for close monitoring
        let sender_handle = sender_arc.handle().clone();
        let connection = Arc::new(connection);

        // Start read loop
        let read_self = self.clone();
        let read_handle = tokio::spawn(async move {
            read_self.read_loop(connection, sender_handle).await;
        });

        // Tell omega our current state now that we're actually connected -
        // doing this after teardown (as before) sent into a sender that had
        // already been cleared, silently dropping the sync every time.
        self.clone().sync_client_iota_status().await;

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
            Ok(()) => {
                // Check if we should reconnect
                if *self.reconnect_on_close.read().await {
                    Err("Connection closed, will reconnect".to_string())
                } else {
                    Ok(())
                }
            }
            Err(e) => Err(format!("Read loop error: {}", e)),
        }
    }

    async fn sync_client_iota_status(self: Arc<Self>) {
        let mut connected_iota_ids: Vec<DataValue> = Vec::new();
        let mut connected_user_ids: Vec<DataValue> = Vec::new();

        let iota_ids = self.rho.iota_ids().await;
        let rho_connections = self.rho.connections().await;

        for iota_id in iota_ids {
            connected_iota_ids.push(DataValue::SignedNumber(iota_id.into()));
        }

        for rho in rho_connections {
            for client_conn in rho.get_client_connections().await {
                connected_user_ids.push(DataValue::SignedNumber(
                    client_conn.get_user_id().await.into(),
                ));
            }
        }

        let sync_msg = CommunicationValue::new(CommunicationType::SyncClientIotaStatus)
            .add_typed_default(DataType::IotaIds, DataValue::Array(connected_iota_ids))
            .add_typed_default(DataType::UserIds, DataValue::Array(connected_user_ids))
            .add_typed_default(
                DataType::RhoConnections,
                DataValue::SignedNumber(self.rho.connection_count().await as i128),
            );

        self.send_message(&sync_msg).await;
    }

    // -------------------------------------------------------------------------
    // Read Loop
    // -------------------------------------------------------------------------

    async fn read_loop(
        self: Arc<Self>,
        connection: Arc<MTPConnection>,
        sender_handle: Arc<ConnectionHandle>,
    ) {
        // Monitor both receiver and sender handle for close
        let mut close_rx = sender_handle.subscribe_close();

        loop {
            tokio::select! {
                result = connection.receive() => {
                    match result {
                        Ok(cv) => {
                            log_cv_in!(PrintType::Omega, &cv);

                            let msg_id = cv.get_id();
                            if let Some((_, task)) = self.waiting_tasks.remove(&msg_id) {
                                if (task.task)(self.clone(), cv.clone()) {
                                    continue;
                                }
                            }

                            if cv.is_type(CommunicationType::IotaUserData) {
                                if let DataValue::Array(users) = cv.get_data(DataType::UserIds) {
                                    let mut user_ids = Vec::new();
                                    for value in users {
                                        if let DataValue::SignedNumber(user_id) = value {
                                            if let Ok(user_id) = i64::try_from(*user_id) {
                                                user_ids.push(user_id);
                                            }
                                        }
                                    }
                                    if let Some(iota_id) = cv.get_data(DataType::IotaId).as_number() {
                                        self.rho.replace_users_for_iota(iota_id as i64, user_ids).await;
                                    } else {
                                        let iota_ids = self.rho.iota_ids().await;
                                        for iota_id in iota_ids {
                                            self.rho.replace_users_for_iota(iota_id, user_ids.clone()).await;
                                        }
                                    }
                                }
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
        self.await_connection(timeout_duration).await?;

        let (tx, mut rx) = mpsc::channel(1);
        let msg_id = cv.get_id();

        self.waiting_tasks.insert(
            msg_id,
            WaitingTask {
                task: Box::new(move |_, response_cv| {
                    log_in!(
                        0,
                        PrintType::Omega,
                        "Matched Omega response (request_id={}, response_id={}, type={})",
                        msg_id,
                        response_cv.get_id(),
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

    #[allow(dead_code)]
    pub async fn close_iota(&self, iota_id: i64) {
        let cv = CommunicationValue::new(CommunicationType::IotaDisconnected)
            .add_typed_default(DataType::IotaId, DataValue::SignedNumber(iota_id.into()));
        self.send_message(&cv).await;
    }

    pub async fn client_changed(
        &self,
        _iota_id: i64,
        user_id: i64,
        session_id: i64,
        state: UserStatus,
    ) {
        let cv = CommunicationValue::new(CommunicationType::ClientChanged)
            .add_typed_default(DataType::UserId, DataValue::SignedNumber(user_id.into()))
            .add_typed_default(
                DataType::SessionId,
                DataValue::SignedNumber(session_id.into()),
            )
            .add_typed_default(DataType::UserState, DataValue::Str(state.to_string()));
        self.send_message(&cv).await;
    }

    pub async fn client_disconnected(&self, user_id: i64, session_id: i64) {
        let cv = CommunicationValue::new(CommunicationType::UserDisconnected)
            .add_typed_default(DataType::UserId, DataValue::SignedNumber(user_id.into()))
            .add_typed_default(
                DataType::SessionId,
                DataValue::SignedNumber(session_id.into()),
            );
        self.send_message(&cv).await;
    }

    pub async fn user_states(&self, user_id: i64, user_ids: Vec<i64>) {
        let user_ids = user_ids
            .iter()
            .map(|v| DataValue::SignedNumber((*v).into()))
            .collect();

        let cv = CommunicationValue::new(CommunicationType::GetStates)
            .add_typed_default(DataType::UserIds, DataValue::Array(user_ids));
        let msg_id = cv.get_id();

        let rho_manager = self.rho.clone();
        self.waiting_tasks.insert(
            msg_id,
            WaitingTask {
                task: Box::new(
                    move |_: Arc<OmegaConnection>, response: CommunicationValue| {
                        let rho_manager = rho_manager.clone();
                        tokio::spawn(async move {
                            let rho = rho_manager.get_for_user(user_id).await;
                            if let Some(rho) = rho {
                                for client in rho.get_client_connections_for_user(user_id).await {
                                    client.send_message(&response).await;
                                }
                            }
                        });
                        true
                    },
                ),
                inserted_at: Instant::now(),
            },
        );

        self.send_message(&cv).await;
    }
}
