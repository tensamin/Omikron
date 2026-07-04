use crate::{
    data::user::UserStatus,
    load_keyring, log_cv_in, log_cv_out, log_err, log_in,
    rho::rho_manager::{self, RHO_CONNECTIONS, connection_count},
    util::logger::PrintType,
};
use dashmap::DashMap;
use mtp::client::{Client, Receiver, Sender};
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use mtp::{
    client::ClientConfig,
    files::load_public_key_bundle,
    host::{Policy, SendMode},
};
use mtp_transport::ConnectionHandle;
use once_cell::sync::Lazy;
use std::{collections::HashMap, env, sync::Arc, time::Duration};
use tokio::{
    sync::{Mutex, RwLock, mpsc, watch},
    task::JoinHandle,
    time::{Instant, sleep},
};

use uuid::Uuid;

// ============================================================================
// Configuration
// ============================================================================

const OMEGA_HOST_DEFAULT: &str = "tensamin.net";
const OMEGA_PORT_DEFAULT: u16 = 9187;

fn omega_host_and_port() -> (String, u16) {
    let host = env::var("OMEGA_HOST")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| OMEGA_HOST_DEFAULT.to_string());

    let port = env::var("OMEGA_PORT")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(OMEGA_PORT_DEFAULT);

    (host, port)
}

const RECONNECT_DELAY: Duration = Duration::from_secs(5);
const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(300);
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
const TASK_CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
const TASK_MAX_AGE: Duration = Duration::from_secs(60);

// ============================================================================
// Waiting Task System
// ============================================================================

pub struct WaitingTask {
    pub task: Box<dyn Fn(Arc<OmegaConnection>, CommunicationValue) -> bool + Send + Sync>,
    pub inserted_at: Instant,
}

pub static WAITING_TASKS: Lazy<DashMap<u32, WaitingTask>> = Lazy::new(DashMap::new);

pub fn start_task_cleanup_loop() {
    tokio::spawn(async {
        loop {
            sleep(TASK_CLEANUP_INTERVAL).await;
            WAITING_TASKS.retain(|_, v| v.inserted_at.elapsed() < TASK_MAX_AGE);
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
    last_ping: Arc<Mutex<i64>>,
    heartbeat_handle: Arc<Mutex<Option<JoinHandle<()>>>>,
    message_send_times: Arc<Mutex<HashMap<Uuid, Instant>>>,
    pub connection_id: Uuid,
    shutdown_tx: Arc<Mutex<Option<watch::Sender<bool>>>>,
    // Track if we should reconnect on close
    reconnect_on_close: Arc<RwLock<bool>>,
}

impl OmegaConnection {
    pub fn new() -> Self {
        let (host, port) = omega_host_and_port();
        Self::with_host(&host, port)
    }

    // omikron and omega are both served over publicly trusted (fullchain) certs on
    // the same domain, so the client uses system root trust - no pinning needed.
    pub fn with_host(host: &str, port: u16) -> Self {
        let (shutdown_tx, _) = watch::channel(false);

        OmegaConnection {
            state: Arc::new(RwLock::new(ConnectionState::Disconnected)),
            sender: Arc::new(RwLock::new(None)),
            connection_loop_handle: Arc::new(Mutex::new(None)),
            host: host.to_string(),
            port,
            last_ping: Arc::new(Mutex::new(-1)),
            heartbeat_handle: Arc::new(Mutex::new(None)),
            message_send_times: Arc::new(Mutex::new(HashMap::new())),
            connection_id: Uuid::new_v4(),
            shutdown_tx: Arc::new(Mutex::new(Some(shutdown_tx))),
            reconnect_on_close: Arc::new(RwLock::new(true)),
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

        if let Some(handle) = self.heartbeat_handle.lock().await.take() {
            handle.abort();
        }

        // Close sender if connected
        if let Some(sender) = self.sender.read().await.as_ref() {
            sender.close();
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
            .with_client_id(
                env::var("ID")
                    .unwrap_or("0".to_string())
                    .parse::<u64>()
                    .unwrap_or(0),
            )
            .with_policy(Policy {
                send_mode: SendMode::SingleStreamPerMessage,
                max_message_size: 1_000_000_000,
                close_frame_len: u32::MAX,
                application_close_code: 0,
                open_stream_timeout: Duration::from_millis(2_000),
                write_timeout: Duration::from_millis(2_000),
                accept_stream_timeout: Duration::from_millis(10_000),
                read_timeout: Duration::from_millis(30_000),
                keep_alive_interval: Some(Duration::from_secs(6)),
                max_idle_timeout: Some(Duration::from_secs(30)),
                force_close_delay: Duration::from_millis(300),
                max_transient_recv_errors: 20,
                transient_recv_backoff: Duration::from_millis(100),
                receiver_queue_capacity: 1000,
            });

        let host_public_key = load_public_key_bundle("./omega.mpkb")
            .map_err(|e| format!("Failed to load omega.mpkb: {}", e))?;

        let mut connection =
            Client::auth_connect(client_config, &load_keyring(), &host_public_key)
                .await
                .map_err(|e| format!("Connection failed: {}", e))?;

        log_in!(
            0,
            PrintType::Omega,
            "QUIC connection established to {}",
            format!("https://{}:{}", self.host, self.port)
        );

        // Store sender
        let sender_arc = Arc::new(connection.sender);
        *self.sender.write().await = Some(sender_arc.clone());
        *self.state.write().await = ConnectionState::Connected { identified: false };

        // Get handle for close monitoring
        let sender_handle = sender_arc.handle().clone();

        // Start read loop
        let read_self = self.clone();
        let read_handle = tokio::spawn(async move {
            read_self
                .read_loop(&mut connection.receiver, sender_handle)
                .await;
        });

        // Start heartbeat
        let heartbeat_self = self.clone();
        let heartbeat_handle = tokio::spawn(async move {
            heartbeat_self.heartbeat_loop().await;
        });
        *self.heartbeat_handle.lock().await = Some(heartbeat_handle);

        // Tell omega our current state now that we're actually connected -
        // doing this after teardown (as before) sent into a sender that had
        // already been cleared, silently dropping the sync every time.
        self.clone().sync_client_iota_status().await;

        // Wait for read loop to complete (connection closed)
        let result = read_handle.await;

        // Cleanup
        *self.sender.write().await = None;
        *self.state.write().await = ConnectionState::Disconnected;

        if let Some(handle) = self.heartbeat_handle.lock().await.take() {
            handle.abort();
        }

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

        let rho_connections_reader = RHO_CONNECTIONS.read().await;

        for iota_id in rho_connections_reader.keys() {
            connected_iota_ids.push(DataValue::SignedNumber((*iota_id).into()));
        }

        for rho in rho_connections_reader.values() {
            for client_conn in rho.get_client_connections().await {
                connected_user_ids.push(DataValue::SignedNumber(
                    client_conn.get_user_id().await.into(),
                ));
            }
        }

        drop(rho_connections_reader);

        let sync_msg = CommunicationValue::new(CommunicationType::SyncClientIotaStatus)
            .add_typed_default(DataType::IotaIds, DataValue::Array(connected_iota_ids))
            .add_typed_default(DataType::UserIds, DataValue::Array(connected_user_ids))
            .add_typed_default(
                DataType::RhoConnections,
                DataValue::SignedNumber(connection_count().await as i128),
            );

        self.send_message(&sync_msg).await;
    }

    // -------------------------------------------------------------------------
    // Read Loop & Heartbeat
    // -------------------------------------------------------------------------

    async fn read_loop(
        self: Arc<Self>,
        receiver: &mut Receiver,
        sender_handle: Arc<ConnectionHandle>,
    ) {
        // Monitor both receiver and sender handle for close
        let mut close_rx = sender_handle.subscribe_close();

        loop {
            tokio::select! {
                result = receiver.receive() => {
                    match result {
                        Ok(cv) => {
                            if !cv.is_type(CommunicationType::Pong) && !cv.is_type(CommunicationType::Ping) {
                                log_cv_in!(PrintType::Omega, &cv);
                            }

                            if cv.is_type(CommunicationType::Pong) || cv.is_type(CommunicationType::Ping) {
                                self.handle_pong(&cv).await;
                                continue;
                            }

                            let msg_id = cv.get_id();
                            if let Some((_, task)) = WAITING_TASKS.remove(&msg_id) {
                                if (task.task)(self.clone(), cv.clone()) {
                                    continue;
                                }
                            }

                            if cv.is_type(CommunicationType::IotaUserData) {
                                if let DataValue::Array(users) = cv.get_data(DataType::UserIds) {
                                    let mut user_ids: Vec<u64> = Vec::new();
                                    for value in users {
                                        if let DataValue::SignedNumber(user_id) = value {
                                            user_ids.push(user_id.clone() as u64);
                                        }
                                    }
                                    let connections = crate::rho::rho_manager::RHO_CONNECTIONS.read().await;
                                    if let Some(iota_id) = cv.get_data(DataType::IotaId).as_number() {
                                        if let Some(rho) = connections.get(&(iota_id as i64)) {
                                            rho.get_iota_connection().set_user_ids(user_ids).await;
                                        }
                                    } else {
                                        for rho in connections.values() {
                                            rho.get_iota_connection().set_user_ids(user_ids.clone()).await;
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

    async fn heartbeat_loop(self: Arc<Self>) {
        loop {
            sleep(HEARTBEAT_INTERVAL).await;

            // Check if still connected
            if !self.state.read().await.is_connected() {
                break;
            }

            // Check if sender is closed
            if let Some(sender) = self.sender.read().await.as_ref() {
                if sender.is_closed() {
                    log_err!(0, PrintType::Omega, "Sender closed, stopping heartbeat");
                    break;
                }
            } else {
                break;
            }

            self.send_ping().await;
        }
    }

    async fn send_ping(&self) {
        let ping = CommunicationValue::new(CommunicationType::Ping).add_typed_default(
            DataType::SendTime,
            DataValue::SignedNumber(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i128,
            ),
        );
        self.send_message(&ping).await;
    }

    async fn handle_pong(&self, cv: &CommunicationValue) {
        let timestamp = cv
            .get_data(DataType::SendTime)
            .as_number()
            .unwrap_or_else(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i128
            });

        *self.last_ping.lock().await = timestamp.try_into().unwrap();
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    pub async fn send_message(&self, cv: &CommunicationValue) {
        if !cv.is_type(CommunicationType::Pong) && !cv.is_type(CommunicationType::Ping) {
            log_cv_out!(PrintType::Omega, &cv);
        }

        let sender_guard = self.sender.read().await;
        if let Some(sender) = sender_guard.as_ref() {
            // Check if closed before sending
            if sender.is_closed() {
                log_err!(0, PrintType::Omega, "Cannot send: connection closed");
                drop(sender_guard);
                // Trigger reconnection by closing the connection state
                if let Some(sender) = self.sender.write().await.take() {
                    sender.close();
                }
                return;
            }

            let sender_clone = Arc::clone(sender);
            drop(sender_guard);

            if let Err(e) = sender_clone.send(cv).await {
                log_err!(0, PrintType::Omega, "Send failed: {}", e);
            }
        } else {
            log_err!(0, PrintType::Omega, "Cannot send: not connected");
        }
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
        self.await_connection(timeout_duration).await?;

        let (tx, mut rx) = mpsc::channel(1);
        let msg_id = cv.get_id();

        WAITING_TASKS.insert(
            msg_id,
            WaitingTask {
                task: Box::new(move |_, response_cv| {
                    let inner_tx = tx.clone();
                    tokio::spawn(async move {
                        let _ = inner_tx.send(response_cv).await;
                    });
                    true
                }),
                inserted_at: Instant::now(),
            },
        );

        self.send_message(cv).await;

        let timeout = timeout_duration.unwrap_or(Duration::from_secs(10));

        match tokio::time::timeout(timeout, rx.recv()).await {
            Ok(Some(response_cv)) => Ok(response_cv),
            Ok(_) => Err("Channel closed".to_string()),
            Err(_) => {
                WAITING_TASKS.remove(&msg_id);
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
    pub async fn close_iota(iota_id: i64) {
        let cv = CommunicationValue::new(CommunicationType::IotaDisconnected)
            .add_typed_default(DataType::IotaId, DataValue::SignedNumber(iota_id.into()));
        OMEGA_CONNECTION.send_message(&cv).await;
    }

    pub async fn client_changed(_iota_id: i64, user_id: i64, state: UserStatus) {
        let msg_type = match state {
            UserStatus::iota_offline => CommunicationType::UserDisconnected,
            UserStatus::user_offline => CommunicationType::UserDisconnected,
            UserStatus::user_invisible => CommunicationType::UserDisconnected,
            _ => CommunicationType::UserConnected,
        };

        let cv = CommunicationValue::new(msg_type)
            .add_typed_default(DataType::UserId, DataValue::SignedNumber(user_id.into()))
            .add_typed_default(DataType::UserState, DataValue::Str(state.to_string()));
        OMEGA_CONNECTION.send_message(&cv).await;
    }

    pub async fn user_states(user_id: i64, user_ids: Vec<i64>) {
        let user_ids = user_ids
            .iter()
            .map(|v| DataValue::SignedNumber((*v).into()))
            .collect();

        let cv = CommunicationValue::new(CommunicationType::GetStates)
            .add_typed_default(DataType::UserIds, DataValue::Array(user_ids));
        let msg_id = cv.get_id();

        WAITING_TASKS.insert(
            msg_id,
            WaitingTask {
                task: Box::new(
                    move |_: Arc<OmegaConnection>, response: CommunicationValue| {
                        tokio::spawn(async move {
                            let rho = rho_manager::get_rho_con_for_user(user_id).await;
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

        OMEGA_CONNECTION.send_message(&cv).await;
    }
}

// ============================================================================
// Global Instance
// ============================================================================

static OMEGA_CONNECTION: Lazy<Arc<OmegaConnection>> = Lazy::new(|| {
    let conn = Arc::new(OmegaConnection::new());

    // Start the connection manager immediately
    let conn_clone = conn.clone();
    tokio::spawn(async move {
        conn_clone.start().await;
    });

    start_task_cleanup_loop();

    conn
});

pub fn get_omega_connection() -> Arc<OmegaConnection> {
    OMEGA_CONNECTION.clone()
}
