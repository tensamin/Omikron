use async_tungstenite::{
    WebSocketReceiver, WebSocketSender,
    stream::Stream,
    tokio::{TokioAdapter, connect_async},
    tungstenite::protocol::Message,
};
use dashmap::DashMap;
use futures::prelude::*;
use json::{JsonValue, number::Number};
use once_cell::sync::Lazy;
use std::{collections::HashMap, env, sync::Arc, time::Duration};
use tokio::{
    net::TcpStream,
    sync::{Mutex, RwLock, mpsc},
    time::{Instant, sleep},
};
use tokio_native_tls::TlsStream;
use uuid::Uuid;

use crate::log_err;
use crate::{
    data::{
        communication::{CommunicationType, CommunicationValue, DataTypes},
        user::UserStatus,
    },
    get_private_key, log, log_in, log_out,
    rho::rho_manager::{self, RHO_CONNECTIONS, connection_count},
    util::{
        crypto_helper::{decrypt_b64, secret_key_to_base64},
        logger::PrintType,
    },
};

pub struct WaitingTask {
    pub task: Box<dyn Fn(Arc<OmegaConnection>, CommunicationValue) -> bool + Send + Sync>,
    pub inserted_at: Instant,
}

pub static WAITING_TASKS: Lazy<DashMap<Uuid, WaitingTask>> = Lazy::new(DashMap::new);

static OMEGA_CONNECTION: Lazy<Arc<OmegaConnection>> = Lazy::new(|| {
    let conn = Arc::new(OmegaConnection::new());
    let conn_clone = conn.clone();
    tokio::spawn(async move {
        conn_clone.connect_internal(0).await;
    });

    tokio::spawn(async {
        loop {
            sleep(Duration::from_secs(60)).await;
            WAITING_TASKS.retain(|_, v| v.inserted_at.elapsed() < Duration::from_secs(60));
        }
    });

    conn
});

#[allow(dead_code)]
pub fn get_omega_connection() -> Arc<OmegaConnection> {
    OMEGA_CONNECTION.clone()
}

#[derive(Clone)]
pub struct OmegaConnection {
    write: Arc<
        Mutex<
            Option<
                WebSocketSender<
                    Stream<TokioAdapter<TcpStream>, TokioAdapter<TlsStream<TcpStream>>>,
                >,
            >,
        >,
    >,
    read: Arc<
        Mutex<
            Option<
                WebSocketReceiver<
                    Stream<TokioAdapter<TcpStream>, TokioAdapter<TlsStream<TcpStream>>>,
                >,
            >,
        >,
    >,
    pingpong: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    pub last_ping: Arc<Mutex<i64>>,
    pub message_send_times: Arc<Mutex<HashMap<Uuid, Instant>>>,
    state: Arc<RwLock<ConnectionState>>,
}

#[derive(Clone, PartialEq, Eq)]
enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
}

impl OmegaConnection {
    pub fn new() -> Self {
        OmegaConnection {
            read: Arc::new(Mutex::new(None)),
            write: Arc::new(Mutex::new(None)),
            pingpong: Arc::new(Mutex::new(None)),
            last_ping: Arc::new(Mutex::new(-1)),
            message_send_times: Arc::new(Mutex::new(HashMap::new())),
            state: Arc::new(RwLock::new(ConnectionState::Disconnected)),
        }
    }
    async fn connect_internal(self: Arc<OmegaConnection>, mut retry: usize) {
        if self.state.read().await.eq(&ConnectionState::Connected) {
            return;
        }
        if self.state.read().await.eq(&ConnectionState::Connecting) {
            let start = Instant::now();
            let timeout = Duration::from_secs(10);
            while self.state.read().await.eq(&ConnectionState::Connecting)
                && start.elapsed() < timeout
            {
                sleep(Duration::from_millis(100)).await;
            }
            return;
        }

        *self.state.write().await = ConnectionState::Connecting;

        if let Some(handle) = self.pingpong.lock().await.take() {
            handle.abort();
        }

        loop {
            if retry > 500 {
                log_err!(
                    0,
                    PrintType::Omega,
                    "Max retry attempts reached, giving up."
                );
                *self.state.write().await = ConnectionState::Disconnected;
                return;
            }

            let url_str =
                env::var("OMEGA_HOST").unwrap_or("wss://omega.tensamin.net/ws/omikron".to_string());
            match connect_async(&url_str).await {
                Ok((ws_stream, _)) => {
                    log_in!(0, PrintType::Omega, "WebSocket connected to {}", url_str);
                    retry = 0;
                    let (write, read) = ws_stream.split();
                    *self.read.lock().await = Some(read);
                    *self.write.lock().await = Some(write);

                    *self.state.write().await = ConnectionState::Connected;

                    let read_loop_self = self.clone();
                    let read_loop_handle = tokio::spawn(async move {
                        read_loop_self.read_loop().await;
                    });

                    let cloned_self = self.clone();
                    tokio::spawn(async move {
                        let id = Uuid::new_v4();

                        let identify_msg =
                            CommunicationValue::new(CommunicationType::identification)
                                .with_id(id)
                                .add_data(
                                    DataTypes::omikron,
                                    JsonValue::Number(Number::from(
                                        env::var("ID")
                                            .unwrap_or("0".to_string())
                                            .parse::<i64>()
                                            .unwrap_or(0),
                                    )),
                                );
                        WAITING_TASKS.insert(
                            id,
                            WaitingTask {
                                task: Box::new(|selfc, cv| {
                                    if cv.is_type(CommunicationType::error_not_found) {
                                        log_err!(0,
                                            PrintType::Omega,
                                            "Identification failed: Omikron ID not found on Omega.",
                                        );
                                        return false;
                                    }
                                    if !cv.is_type(CommunicationType::challenge) {
                                        return false;
                                    }
                                    tokio::spawn(async move {
                                        let task = async move {
                                            let challenge = cv
                                                .get_data(DataTypes::challenge)
                                                .and_then(|v| v.as_str())
                                                .ok_or_else(|| {
                                                    "Challenge not found or not a string".to_string()
                                                })?;

                                            let server_pub_key = cv
                                                .get_data(DataTypes::public_key)
                                                .and_then(|v| v.as_str())
                                                .ok_or_else(|| {
                                                    "Public key from server not found or not a string"
                                                        .to_string()
                                                })?;

                                            let decrypted_challenge = decrypt_b64(
                                                &secret_key_to_base64(&get_private_key()),
                                                server_pub_key,
                                                challenge,
                                            )
                                            .map_err(|e| {
                                                format!("Failed to decrypt challenge: {:?}", e)
                                            })?;

                                            let response_msg = CommunicationValue::new(
                                                CommunicationType::challenge_response,
                                            )
                                            .with_id(cv.get_id())
                                            .add_data(
                                                DataTypes::challenge,
                                                JsonValue::String(decrypted_challenge),
                                            );

                                            let response_id = response_msg.get_id();
                                            WAITING_TASKS.insert(
                                                response_id,
                                                WaitingTask {
                                                    task: Box::new(|selfc, final_cv| {
                                                        if !final_cv
                                                            .is_type(CommunicationType::identification_response)
                                                        {
                                                            log_err!(0,
                                                                PrintType::Omega,
                                                                "Expected identification_response, got something else.",
                                                            );
                                                            return false;
                                                        }

                                                        if let Some(accepted) = final_cv.get_data(DataTypes::accepted).and_then(|v| v.as_bool()) {
                                                            if !accepted {
                                                                log_err!(0, PrintType::Omega, "Omega did not accept identification.");
                                                                return false;
                                                            }
                                                        } else {
                                                            log_err!(0, PrintType::Omega, "Omega response did not contain 'accepted' field.");
                                                            return false;
                                                        }

                                                        tokio::spawn(async move {
                                                            let mut connected_iota_ids: Vec<JsonValue> = Vec::new();
                                                            let mut connected_user_ids: Vec<JsonValue> = Vec::new();
                                                            let rho_connections_reader = RHO_CONNECTIONS.read().await;

                                                            for iota_id in rho_connections_reader.keys() {
                                                                connected_iota_ids.push(JsonValue::from(*iota_id));
                                                            }

                                                            for rho in rho_connections_reader.values() {
                                                                for client_conn in rho.get_client_connections().await {
                                                                    connected_user_ids.push(JsonValue::from(client_conn.get_user_id().await));
                                                                }
                                                            }

                                                            drop(rho_connections_reader);

                                                            let sync_msg = CommunicationValue::new(CommunicationType::sync_client_iota_status)
                                                                .add_data(DataTypes::iota_ids, JsonValue::Array(connected_iota_ids))
                                                                .add_data(DataTypes::user_ids, JsonValue::Array(connected_user_ids))
                                                                .add_data(DataTypes::rho_connections, JsonValue::from(connection_count().await));

                                                            selfc.send_message(&sync_msg).await;
                                                        });
                                                        log!(0,
                                                            PrintType::Omega,
                                                            "Successfully identified with Omega.",
                                                        );
                                                        true
                                                    }),
                                                    inserted_at: Instant::now(),
                                                }
                                            );

                                            selfc.send_message(&response_msg).await;

                                            Ok::<(), String>(())
                                        };

                                        if let Err(e) = task.await {
                                            log_err!(0, PrintType::Omega, "{}", &e);
                                        }
                                    });

                                    true
                                }),
                                inserted_at: Instant::now(),
                            }
                        );
                        cloned_self.send_message(&identify_msg).await
                    });

                    let ping_pong_self = self.clone();
                    let handle = tokio::spawn(async move {
                        loop {
                            if *ping_pong_self.state.read().await != ConnectionState::Connected {
                                break;
                            }
                            ping_pong_self.send_ping().await;
                            sleep(Duration::from_secs(5)).await;
                        }
                    });

                    *self.pingpong.lock().await = Some(handle);

                    read_loop_handle.await.unwrap_or_else(|e| {
                        log_err!(0, PrintType::Omega, "Read loop task failed: {}", e)
                    });

                    *self.read.lock().await = None;
                    *self.write.lock().await = None;
                    *self.state.write().await = ConnectionState::Disconnected;

                    log_err!(0, PrintType::Omega, "Connection lost. Retrying...");
                    retry += 1;
                    sleep(Duration::from_secs(2)).await;
                }
                Err(e) => {
                    *self.state.write().await = ConnectionState::Disconnected;
                    log_err!(
                        0,
                        PrintType::Omega,
                        "WebSocket connection failed (attempt {}): {}",
                        retry + 1,
                        e,
                    );
                    retry += 1;
                    sleep(Duration::from_secs(2)).await;
                    continue;
                }
            }
        }
    }

    async fn read_loop(self: Arc<Self>) {
        let mut reader = match self.read.lock().await.take() {
            Some(reader) => reader,
            None => return,
        };

        loop {
            let msg = reader.next().await;

            match msg {
                Some(Ok(Message::Text(msg))) => {
                    let cv = CommunicationValue::from_json(&msg);
                    if cv.is_type(CommunicationType::pong) || cv.is_type(CommunicationType::ping) {
                        self.handle_pong(&cv, true).await;
                        continue;
                    }
                    let msg_id = cv.get_id();
                    log_in!(0, PrintType::Omega, "{}", &cv.to_json().to_string());
                    if let Some(task) = WAITING_TASKS.remove(&msg_id) {
                        if (task.1.task)(self.clone(), cv.clone()) {
                            continue;
                        }
                    } else {
                    }
                }
                #[allow(non_snake_case)]
                Some(Ok(Message::Close(_))) | None => break,
                Some(Err(_)) => break,
                _ => {}
            }
        }
    }

    pub async fn send_message(&self, cv: &CommunicationValue) {
        if !cv.is_type(CommunicationType::ping) {
            log_out!(0, PrintType::Omega, "{}", &cv.to_json().to_string());
        }
        let msg = cv.to_json().to_string();

        let mut guard = self.write.lock().await;
        if let Some(ws) = guard.as_mut() {
            let _ = ws.send(Message::Text(msg.into())).await;
        }
    }

    pub async fn close_iota(iota_id: i64) {
        let cv = CommunicationValue::new(CommunicationType::iota_disconnected)
            .add_data(DataTypes::iota_id, JsonValue::from(iota_id));
        OmegaConnection::send_global(cv).await;
    }

    pub async fn client_changed(_iota_id: i64, user_id: i64, state: UserStatus) {
        let msg_type = match state {
            UserStatus::iota_offline => Some(CommunicationType::user_disconnected),
            UserStatus::user_offline => Some(CommunicationType::user_disconnected),
            _ => Some(CommunicationType::user_connected),
        };

        if let Some(t) = msg_type {
            let cv =
                CommunicationValue::new(t).add_data(DataTypes::user_id, JsonValue::from(user_id));
            OmegaConnection::send_global(cv).await;
        }
    }

    pub async fn user_states(user_id: i64, user_ids: Vec<i64>) {
        let user_ids_str = user_ids
            .iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let cv = CommunicationValue::new(CommunicationType::get_states)
            .add_data(DataTypes::user_ids, JsonValue::from(user_ids_str));
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

        OmegaConnection::send_global(cv).await;
    }

    async fn send_global(cv: CommunicationValue) {
        OMEGA_CONNECTION.send_message(&cv).await;
    }

    pub async fn await_connection(&self, timeout_duration: Option<Duration>) -> Result<(), String> {
        if *self.state.read().await == ConnectionState::Connected {
            return Ok(());
        }
        let timeout = timeout_duration.unwrap_or(Duration::from_secs(10));

        let start = Instant::now();
        loop {
            if *self.state.read().await == ConnectionState::Connected {
                return Ok(());
            }

            if start.elapsed() >= timeout {
                return Err(format!(
                    "Connection not established within {} seconds",
                    timeout.as_secs()
                ));
            }

            sleep(Duration::from_millis(100)).await; // short interval polling
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

        let task_tx = tx.clone();
        WAITING_TASKS.insert(
            msg_id,
            WaitingTask {
                task: Box::new(move |_, response_cv| {
                    let inner_tx = task_tx.clone();
                    tokio::spawn(async move {
                        if inner_tx.send(response_cv).await.is_err() {
                            log_err!(
                                0,
                                PrintType::Omega,
                                "Failed to send response back to awaiter",
                            );
                        }
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
            Ok(_) => Err("Failed to receive response, channel was closed.".to_string()),
            Err(_) => {
                WAITING_TASKS.remove(&msg_id);
                Err(format!(
                    "Request timed out after {} seconds.",
                    timeout.as_secs()
                ))
            }
        }
    }
}
