use std::sync::Arc;
use std::time::Duration;

use crate::data::communication::{CommunicationType, CommunicationValue};
use crate::util::print::PrintType;
use crate::util::print::line_err;
use crate::{
    data::{
        communication::DataTypes,
        user::{User, UserStatus},
    },
    rho::rho_manager,
    util::config_util::CONFIG,
};
use async_tungstenite::tungstenite::protocol::Message;
use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use json::JsonValue;
use once_cell::sync::Lazy;
use tokio::io::unix::AsyncFd;
use tokio::sync::Mutex;
use tokio::time::sleep;
use tokio_util::compat::Compat;
use tungstenite::{Utf8Bytes, connect};
use uuid::Uuid;

static WAITING_TASKS: Lazy<DashMap<Uuid, Box<dyn Fn(CommunicationValue) -> bool + Send + Sync>>> =
    Lazy::new(DashMap::new);

pub struct OmegaConnection {
    ws_stream:
        Arc<Mutex<Option<async_tungstenite::WebSocketStream<Compat<tokio::net::TcpStream>>>>>,
}

impl OmegaConnection {
    pub fn new() -> Self {
        OmegaConnection {
            ws_stream: Arc::new(Mutex::new(None)),
        }
    }

    pub async fn connect(&self) {
        self.connect_internal(0).await;
    }
    async fn connect_internal(&self, mut retry: usize) {
        loop {
            if retry > 5 {
                line_err(
                    PrintType::OmegaIn,
                    &"Max retry attempts reached, giving up.",
                );
                return;
            }

            match connect("wss://tensamin.methanium.net/ws/omega") {
                Ok((_, _)) => {
                    retry = 0;
                    let identify_msg = CommunicationValue::new(CommunicationType::identification)
                        .add_data(
                            DataTypes::uuid,
                            JsonValue::String(CONFIG.read().await.omikron_id.to_string()),
                        );
                    self.send_message(&identify_msg).await;

                    let ws_stream_clone = self.ws_stream.clone();
                    tokio::spawn(async move {
                        OmegaConnection::read_loop(ws_stream_clone).await;
                    });
                }
                Err(e) => {
                    line_err(
                        PrintType::OmegaIn,
                        &format!("WebSocket connection failed (attempt {}): {}", retry, e),
                    );
                    retry += 1;
                    sleep(Duration::from_secs(2)).await;
                    continue;
                }
            }
        }
    }

    async fn read_loop(
        ws_stream: Arc<
            Mutex<Option<async_tungstenite::WebSocketStream<Compat<tokio::net::TcpStream>>>>,
        >,
    ) {
        loop {
            let mut lock = ws_stream.lock().await;
            let Some(ws) = lock.as_mut() else {
                break;
            };

            match ws.next().await {
                Some(Ok(Message::Text(msg))) => {
                    let cv = CommunicationValue::from_json(&msg);
                    let msg_id = cv.get_id();

                    // Handle waiting tasks
                    if let Some(task) = WAITING_TASKS.remove(&msg_id) {
                        if (task.1)(cv.clone()) {
                            continue;
                        }
                    }

                    // Handle CLIENT_CHANGED
                    if cv.is_type(CommunicationType::client_changed) {
                        let iota_id = Uuid::parse_str(
                            cv.get_data(DataTypes::iota_id).unwrap().as_str().unwrap(),
                        )
                        .unwrap();
                        let user_id = Uuid::parse_str(
                            cv.get_data(DataTypes::user_id).unwrap().as_str().unwrap(),
                        )
                        .unwrap();
                        let status_str = cv
                            .get_data(DataTypes::user_state)
                            .unwrap()
                            .as_str()
                            .unwrap();
                        let status = UserStatus::from_string(&status_str)
                            .unwrap_or(UserStatus::iota_offline);

                        let user = User::new(iota_id, user_id, status);
                        for rho_con in rho_manager::get_all_connections().await {
                            rho_con.are_they_interested(&user).await;
                        }
                    }
                }
                Some(Ok(Message::Close(_))) | None => {
                    break;
                }
                Some(Err(_)) => {
                    break;
                }
                _ => {}
            }
        }
    }

    pub async fn send_message(&self, cv: &CommunicationValue) {
        let mut guard = self.ws_stream.lock().await;
        if let Some(ws) = guard.as_mut() {
            let _ = ws
                .send(Message::Text(Utf8Bytes::from(cv.to_json().to_string())))
                .await;
        }
    }

    pub async fn connect_iota(iota_id: Uuid, user_ids: Vec<Uuid>) {
        let user_ids_str = user_ids
            .iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let cv = CommunicationValue::new(CommunicationType::iota_connected)
            .add_data(DataTypes::iota_id, JsonValue::from(iota_id.to_string()))
            .add_data(DataTypes::user_ids, JsonValue::from(user_ids_str));
        OmegaConnection::send_global(cv).await;
    }

    pub async fn close_iota(iota_id: Uuid) {
        let cv = CommunicationValue::new(CommunicationType::iota_closed)
            .add_data(DataTypes::iota_id, JsonValue::from(iota_id.to_string()));
        OmegaConnection::send_global(cv).await;
    }

    pub async fn client_changed(iota_id: Uuid, user_id: Uuid, state: UserStatus) {
        let cv = CommunicationValue::new(CommunicationType::client_changed)
            .add_data(DataTypes::iota_id, JsonValue::from(iota_id.to_string()))
            .add_data(DataTypes::user_id, JsonValue::from(user_id.to_string()))
            .add_data(DataTypes::user_state, JsonValue::from(state.to_string()));
        OmegaConnection::send_global(cv).await;
    }

    pub async fn user_states(user_id: Uuid, user_ids: Vec<Uuid>) {
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
            Box::new(move |response: CommunicationValue| {
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
            }),
        );

        OmegaConnection::send_global(cv).await;
    }

    async fn send_global(cv: CommunicationValue) {
        let conn = OmegaConnection::new();
        conn.send_message(&cv).await;
    }
}
