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

use crate::{
    data::{
        communication::{CommunicationType, CommunicationValue, DataTypes},
        user::UserStatus,
    },
    get_private_key, log, log_in, log_out,
    rho::rho_manager::{self, RHO_CONNECTIONS},
    util::crypto_helper::{decrypt_b64, secret_key_to_base64},
    util::logger::PrintType,
};
use crate::{log_err, util::crypto_helper::load_public_key};

pub static WAITING_TASKS: Lazy<
    DashMap<Uuid, Box<dyn Fn(Arc<OmegaConnection>, CommunicationValue) -> bool + Send + Sync>>,
> = Lazy::new(DashMap::new);

static OMEGA_CONNECTION: Lazy<Arc<OmegaConnection>> = Lazy::new(|| {
    let conn = Arc::new(OmegaConnection::new());
    let conn_clone = conn.clone();
    tokio::spawn(async move {
        conn_clone.connect_internal(0).await;
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
        RwLock<
            Option<
                WebSocketSender<
                    Stream<TokioAdapter<TcpStream>, TokioAdapter<TlsStream<TcpStream>>>,
                >,
            >,
        >,
    >,
    read: Arc<
        RwLock<
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
    pub is_connected: Arc<RwLock<bool>>,
}

impl OmegaConnection {
    pub fn new() -> Self {
        OmegaConnection {
            read: Arc::new(RwLock::new(None)),
            write: Arc::new(RwLock::new(None)),
            pingpong: Arc::new(Mutex::new(None)),
            last_ping: Arc::new(Mutex::new(-1)),
            message_send_times: Arc::new(Mutex::new(HashMap::new())),
            is_connected: Arc::new(RwLock::new(false)),
        }
    }
    pub fn connect(self: Arc<OmegaConnection>) {
        let cloned_self = self.clone();
        tokio::spawn(async move {
            cloned_self.connect_internal(0).await;
        });
    }
    async fn connect_internal(self: Arc<OmegaConnection>, mut retry: usize) {
        loop {
            if retry > 5 {
                log_err!(PrintType::Omega, "Max retry attempts reached, giving up.");
                return;
            }

            let url_str =
                env::var("OMEGA_HOST").unwrap_or("wss://omega.tensamin.net/ws/omikron".to_string());
            match connect_async(&url_str).await {
                Ok((ws_stream, _)) => {
                    *self.is_connected.write().await = true;
                    log_in!(PrintType::Omega, "WebSocket connected to {}", url_str);
                    retry = 0;
                    let (write, read) = ws_stream.split();
                    *self.read.write().await = Some(read);
                    *self.write.write().await = Some(write);

                    let cloned_self = self.clone();
                    tokio::spawn(async move {
                        cloned_self.clone().read_loop().await;
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
                            Box::new(|selfc, cv| {
                                if cv.is_type(CommunicationType::error_not_found) {
                                    log_err!(
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

                                        let server_pub_key_obj = load_public_key(server_pub_key).unwrap();

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
                                            Box::new(|selfc, final_cv| {
                                                if !final_cv
                                                    .is_type(CommunicationType::identification_response)
                                                {
                                                    log_err!(
                                                        PrintType::Omega,
                                                        "Expected identification_response, got something else.",
                                                    );
                                                    return false;
                                                }

                                                if let Some(accepted) = final_cv.get_data(DataTypes::accepted).and_then(|v| v.as_bool()) {
                                                    if !accepted {
                                                        log_err!(PrintType::Omega, "Omega did not accept identification.");
                                                        return false;
                                                    }
                                                } else {
                                                    log_err!(PrintType::Omega, "Omega response did not contain 'accepted' field.");
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
                                                        .add_data(DataTypes::user_ids, JsonValue::Array(connected_user_ids));

                                                    selfc.send_message(&sync_msg).await;
                                                });
                                                log!(
                                                    PrintType::Omega,
                                                    "Successfully identified with Omega.",
                                                );
                                                true
                                            }),
                                        );

                                        selfc.send_message(&response_msg).await;

                                        Ok::<(), String>(())
                                    };

                                    if let Err(e) = task.await {
                                        log_err!(PrintType::Omega, "{}", &e);
                                    }
                                });

                                true
                            }),
                        );
                        cloned_self.send_message(&identify_msg).await
                    });

                    let cloned_self = self.clone();
                    let handle = tokio::spawn(async move {
                        loop {
                            if *cloned_self.is_connected.read().await == false {
                                break;
                            }
                            cloned_self.send_ping().await;
                            sleep(Duration::from_secs(1)).await;
                        }
                    });

                    *self.is_connected.write().await = true;
                    *self.pingpong.lock().await = Some(handle);

                    while *self.is_connected.read().await {
                        sleep(Duration::from_secs(2)).await;
                    }
                    *self.read.write().await = None;
                    *self.write.write().await = None;
                    log_err!(PrintType::Omega, "Connection lost. Retrying...");
                    retry += 1;
                    sleep(Duration::from_secs(2)).await;
                }
                Err(e) => {
                    log_err!(
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
        loop {
            let msg = {
                let mut guard = self.read.write().await;
                let ws = match guard.as_mut() {
                    Some(ws) => ws,
                    _ => break,
                };
                ws.next().await
            };

            match msg {
                Some(Ok(Message::Text(msg))) => {
                    let cv = CommunicationValue::from_json(&msg);
                    if cv.is_type(CommunicationType::pong) {
                        self.handle_pong(&cv, true).await;
                        continue;
                    }
                    let msg_id = cv.get_id();
                    log_in!(PrintType::Omega, "{}", &cv.to_json().to_string());
                    // Handle waiting tasks
                    if let Some(task) = WAITING_TASKS.remove(&msg_id) {
                        if (task.1)(self.clone(), cv.clone()) {
                            continue;
                        }
                    } else {
                    }
                }
                #[allow(non_snake_case)]
                Some(Ok(Message::Close(_))) | None => continue,
                Some(Err(_)) => break,
                _ => {}
            }
        }

        *self.is_connected.write().await = false;
        *self.read.write().await = None;
        *self.write.write().await = None;
    }

    pub async fn send_message(&self, cv: &CommunicationValue) {
        let mut guard = self.write.write().await;
        if let Some(ws) = guard.as_mut() {
            if !cv.is_type(CommunicationType::ping) {
                log_out!(PrintType::Omega, "{}", &cv.to_json().to_string());
            }
            let _ = ws
                .send(Message::Text(cv.to_json().to_string().into()))
                .await;
        }
    }

    pub async fn connect_iota(iota_id: i64, _user_ids: Vec<i64>) {
        let cv = CommunicationValue::new(CommunicationType::iota_connected)
            .add_data(DataTypes::iota_id, JsonValue::from(iota_id));
        OmegaConnection::send_global(cv).await;
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
            Box::new(
                move |_: Arc<OmegaConnection>, response: CommunicationValue| {
                    let _ = Box::pin(async move |_: CommunicationValue| {
                        let rho = rho_manager::get_rho_con_for_user(user_id).await;
                        if let Some(rho) = rho {
                            for client in rho.get_client_connections_for_user(user_id).await {
                                client.send_message(&response).await;
                            }
                        }
                        true
                    });
                    true
                },
            ),
        );

        OmegaConnection::send_global(cv).await;
    }

    async fn send_global(cv: CommunicationValue) {
        OMEGA_CONNECTION.send_message(&cv).await;
    }

    pub async fn await_response(
        &self,
        cv: &CommunicationValue,
        timeout_duration: Option<Duration>,
    ) -> Result<CommunicationValue, String> {
        let (tx, mut rx) = mpsc::channel(1);
        let msg_id = cv.get_id();

        let task_tx = tx.clone();
        WAITING_TASKS.insert(
            msg_id,
            Box::new(move |_, response_cv| {
                let inner_tx = task_tx.clone();
                tokio::spawn(async move {
                    if let Err(e) = inner_tx.send(response_cv).await {
                        log_err!(
                            PrintType::Omega,
                            "Failed to send response back to awaiter: {}",
                            e
                        );
                    }
                });
                true
            }),
        );

        self.send_message(cv).await;

        let timeout = timeout_duration.unwrap_or(Duration::from_secs(10));

        match tokio::time::timeout(timeout, rx.recv()).await {
            Ok(Some(response_cv)) => Ok(response_cv),
            Ok(None) => Err("Failed to receive response, channel was closed.".to_string()),
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
