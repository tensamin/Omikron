use crate::{
    data::user::UserStatus,
    get_private_key, log, log_cv_in, log_cv_out, log_err, log_in,
    rho::rho_manager::{self, RHO_CONNECTIONS, connection_count},
    util::{
        crypto_helper::{decrypt_b64, secret_key_to_base64},
        file_util::load_file_vec,
        logger::PrintType,
    },
};
use dashmap::DashMap;
use epsilon_core::{CommunicationType, CommunicationValue, DataTypes, DataValue, rand_u32};
use epsilon_native::{Receiver, Sender};
use once_cell::sync::Lazy;
use std::{collections::HashMap, env, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    sync::{Mutex, RwLock, mpsc, watch},
    task::JoinHandle,
    time::{Instant, sleep},
};
use uuid::Uuid;

// ============================================================================
// Configuration
// ============================================================================

const OMEGA_HOST_DEFAULT: &str = "omega.tensamin.net";
const OMEGA_PORT_DEFAULT: u16 = 9187;
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

impl ConnectionState {
    pub fn is_connected(&self) -> bool {
        match self {
            ConnectionState::Connected { identified } => true,
            _ => false,
        }
    }

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
pub struct OmegaConnection {
    state: Arc<RwLock<ConnectionState>>,
    sender: Arc<RwLock<Option<Arc<Sender>>>>,
    connection_loop_handle: Arc<Mutex<Option<JoinHandle<()>>>>,
    host: String,
    port: u16,
    server_cert: Vec<u8>,
    last_ping: Arc<Mutex<i64>>,
    heartbeat_handle: Arc<Mutex<Option<JoinHandle<()>>>>,
    message_send_times: Arc<Mutex<HashMap<Uuid, Instant>>>,
    pub connection_id: Uuid,
    shutdown_tx: Arc<Mutex<Option<watch::Sender<bool>>>>,
}

impl OmegaConnection {
    pub fn new() -> Self {
        Self::with_host(OMEGA_HOST_DEFAULT, OMEGA_PORT_DEFAULT)
    }

    pub fn with_host(host: &str, port: u16) -> Self {
        // Load server certificate from default location
        let server_cert =
            load_file_vec("certs", "cert.pem").expect("Failed to load server certificate");

        Self::with_host_and_cert(host, port, server_cert)
    }

    // New constructor that accepts certificate directly
    pub fn with_host_and_cert(host: &str, port: u16, server_cert: Vec<u8>) -> Self {
        let (shutdown_tx, _) = watch::channel(false);

        OmegaConnection {
            state: Arc::new(RwLock::new(ConnectionState::Disconnected)),
            sender: Arc::new(RwLock::new(None)),
            connection_loop_handle: Arc::new(Mutex::new(None)),
            host: host.to_string(),
            port,
            server_cert, // Store certificate for connection
            last_ping: Arc::new(Mutex::new(-1)),
            heartbeat_handle: Arc::new(Mutex::new(None)),
            message_send_times: Arc::new(Mutex::new(HashMap::new())),
            connection_id: Uuid::new_v4(),
            shutdown_tx: Arc::new(Mutex::new(Some(shutdown_tx))),
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

        let self_clone = self.clone();
        let handle = tokio::spawn(async move {
            self_clone.connection_loop().await;
        });

        *self.connection_loop_handle.lock().await = Some(handle);
    }

    pub async fn stop(&self) {
        if let Some(tx) = self.shutdown_tx.lock().await.take() {
            let _ = tx.send(true);
        }

        if let Some(handle) = self.connection_loop_handle.lock().await.take() {
            handle.abort();
        }

        if let Some(handle) = self.heartbeat_handle.lock().await.take() {
            handle.abort();
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

            match self.clone().connect_once().await {
                Ok(()) => {
                    log_err!(
                        0,
                        PrintType::Omega,
                        "Connection lost, reconnecting in {:?}...",
                        reconnect_delay
                    );
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

        let addr_str = format!("https://{}:{}", self.host, self.port);

        let (sender, mut receiver) = epsilon_native::client::connect(&addr_str, None)
            .await
            .map_err(|e| format!("Connection failed: {}", e))?;

        log_in!(
            0,
            PrintType::Omega,
            "QUIC connection established to {}",
            addr_str
        );

        // Store sender
        *self.sender.write().await = Some(Arc::new(sender));
        *self.state.write().await = ConnectionState::Connected { identified: false };

        // Start read loop
        let read_self = self.clone();
        let read_handle = tokio::spawn(async move {
            read_self.read_loop(&mut receiver).await;
        });

        // Send identification
        self.send_identification().await;

        // Start heartbeat
        let heartbeat_self = self.clone();
        let heartbeat_handle = tokio::spawn(async move {
            heartbeat_self.heartbeat_loop().await;
        });
        *self.heartbeat_handle.lock().await = Some(heartbeat_handle);

        // Wait for read loop to complete
        let result = read_handle.await;

        // Cleanup
        *self.sender.write().await = None;
        *self.state.write().await = ConnectionState::Disconnected;

        if let Some(handle) = self.heartbeat_handle.lock().await.take() {
            handle.abort();
        }

        match result {
            Ok(()) => Err("Read loop ended".to_string()),
            Err(e) => Err(format!("Read loop error: {}", e)),
        }
    }

    // -------------------------------------------------------------------------
    // Identification Handshake
    // -------------------------------------------------------------------------

    async fn send_identification(&self) {
        let id = rand_u32();

        let omikron_id = env::var("ID")
            .unwrap_or("0".to_string())
            .parse::<i64>()
            .unwrap_or(0);

        let identify_msg = CommunicationValue::new(CommunicationType::identification)
            .with_id(id)
            .add_data(DataTypes::omikron_id, DataValue::Number(omikron_id));

        WAITING_TASKS.insert(
            id,
            WaitingTask {
                task: Box::new(|selfc, cv| {
                    if cv.is_type(CommunicationType::error_not_found) {
                        log_err!(
                            0,
                            PrintType::Omega,
                            "Identification failed: Omikron ID not found"
                        );
                        return false;
                    }
                    if !cv.is_type(CommunicationType::challenge) {
                        return false;
                    }

                    tokio::spawn(async move {
                        if let Err(e) = selfc.handle_challenge(cv).await {
                            log_err!(0, PrintType::Omega, "Challenge handling failed: {}", e);
                        }
                    });
                    true
                }),
                inserted_at: Instant::now(),
            },
        );

        self.send_message(&identify_msg).await;
    }

    async fn handle_challenge(&self, cv: CommunicationValue) -> Result<(), String> {
        let challenge = cv
            .get_data(DataTypes::challenge)
            .as_str()
            .ok_or("Challenge not found")?;

        let server_pub_key = cv
            .get_data(DataTypes::public_key)
            .as_str()
            .ok_or("Public key not found")?;

        let decrypted_challenge = decrypt_b64(
            &secret_key_to_base64(&get_private_key()),
            server_pub_key,
            challenge,
        )
        .map_err(|e| format!("Decryption failed: {:?}", e))?;

        let response_msg = CommunicationValue::new(CommunicationType::challenge_response)
            .with_id(cv.get_id())
            .add_data(DataTypes::challenge, DataValue::Str(decrypted_challenge));

        let response_id = response_msg.get_id();

        WAITING_TASKS.insert(
            response_id,
            WaitingTask {
                task: Box::new(|selfc, final_cv| {
                    if !final_cv.is_type(CommunicationType::identification_response) {
                        log_err!(0, PrintType::Omega, "Expected identification_response");
                        return false;
                    }

                    let accepted = final_cv
                        .get_data(DataTypes::accepted)
                        .as_bool()
                        .unwrap_or(false);

                    if !accepted {
                        log_err!(0, PrintType::Omega, "Omega did not accept identification");
                        return false;
                    }

                    tokio::spawn(async move {
                        let mut state = selfc.state.write().await;
                        if let ConnectionState::Connected { identified: _ } = *state {
                            *state = ConnectionState::Connected { identified: true };
                        }
                        drop(state);

                        selfc.sync_client_iota_status().await;
                    });

                    log!(0, PrintType::Omega, "Successfully identified with Omega");
                    true
                }),
                inserted_at: Instant::now(),
            },
        );

        self.send_message(&response_msg).await;
        Ok(())
    }

    async fn sync_client_iota_status(self: Arc<Self>) {
        let mut connected_iota_ids: Vec<DataValue> = Vec::new();
        let mut connected_user_ids: Vec<DataValue> = Vec::new();

        let rho_connections_reader = RHO_CONNECTIONS.read().await;

        for iota_id in rho_connections_reader.keys() {
            connected_iota_ids.push(DataValue::Number(*iota_id));
        }

        for rho in rho_connections_reader.values() {
            for client_conn in rho.get_client_connections().await {
                connected_user_ids.push(DataValue::Number(client_conn.get_user_id().await as i64));
            }
        }

        drop(rho_connections_reader);

        let sync_msg = CommunicationValue::new(CommunicationType::sync_client_iota_status)
            .add_data(DataTypes::iota_ids, DataValue::Array(connected_iota_ids))
            .add_data(DataTypes::user_ids, DataValue::Array(connected_user_ids))
            .add_data(
                DataTypes::rho_connections,
                DataValue::Number(connection_count().await as i64),
            );

        self.send_message(&sync_msg).await;
    }

    // -------------------------------------------------------------------------
    // Read Loop & Heartbeat
    // -------------------------------------------------------------------------

    async fn read_loop(self: Arc<Self>, receiver: &mut Receiver) {
        loop {
            match receiver.receive().await {
                Ok(cv) => {
                    log_cv_in!(&cv);

                    if cv.is_type(CommunicationType::pong) || cv.is_type(CommunicationType::ping) {
                        self.handle_pong(&cv).await;
                        continue;
                    }

                    let msg_id = cv.get_id();
                    if let Some((_, task)) = WAITING_TASKS.remove(&msg_id) {
                        if (task.task)(self.clone(), cv) {
                            continue;
                        }
                    }
                }
                Err(e) => {
                    log_err!(0, PrintType::Omega, "Receive error: {}", e);
                    break;
                }
            }
        }
    }

    async fn heartbeat_loop(self: Arc<Self>) {
        loop {
            sleep(HEARTBEAT_INTERVAL).await;

            if !self.state.read().await.is_connected() {
                break;
            }

            self.send_ping().await;
        }
    }

    async fn send_ping(&self) {
        let ping = CommunicationValue::new(CommunicationType::ping).add_data(
            DataTypes::send_time,
            DataValue::Number(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64,
            ),
        );
        self.send_message(&ping).await;
    }

    async fn handle_pong(&self, cv: &CommunicationValue) {
        let timestamp = cv
            .get_data(DataTypes::send_time)
            .as_number()
            .unwrap_or_else(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64
            });

        *self.last_ping.lock().await = timestamp;
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    pub async fn send_message(&self, cv: &CommunicationValue) {
        log_cv_out!(cv);

        let sender_guard = self.sender.read().await;
        if let Some(sender) = sender_guard.as_ref() {
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

    pub async fn is_connected(&self) -> bool {
        self.state.read().await.is_connected()
    }

    pub async fn is_identified(&self) -> bool {
        self.state.read().await.is_identified()
    }

    pub async fn close_iota(iota_id: i64) {
        let cv = CommunicationValue::new(CommunicationType::iota_disconnected)
            .add_data(DataTypes::iota_id, DataValue::Number(iota_id));
        OMEGA_CONNECTION.send_message(&cv).await;
    }

    pub async fn client_changed(_iota_id: i64, user_id: i64, state: UserStatus) {
        let msg_type = match state {
            UserStatus::iota_offline => CommunicationType::user_disconnected,
            UserStatus::user_offline => CommunicationType::user_disconnected,
            _ => CommunicationType::user_connected,
        };

        let cv = CommunicationValue::new(msg_type)
            .add_data(DataTypes::user_id, DataValue::Number(user_id));
        OMEGA_CONNECTION.send_message(&cv).await;
    }

    pub async fn user_states(user_id: i64, user_ids: Vec<i64>) {
        let user_ids = user_ids.iter().map(|v| DataValue::Number(*v)).collect();

        let cv = CommunicationValue::new(CommunicationType::get_states)
            .add_data(DataTypes::user_ids, DataValue::Array(user_ids));
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
