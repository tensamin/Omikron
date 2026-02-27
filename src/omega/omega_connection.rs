use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use dashmap::DashMap;
use once_cell::sync::Lazy;
use tokio::sync::{Mutex, RwLock, mpsc};

use epsilon_core::{CommunicationType, CommunicationValue, DataTypes, DataValue};
use epsilon_native::{Receiver, Sender, connect};

use crate::{data::user::UserStatus, rho::rho_manager};

static WAITING: Lazy<
    DashMap<
        u32,
        (
            Instant,
            Box<dyn Fn(Arc<OmegaConnection>, CommunicationValue) -> bool + Send + Sync>,
        ),
    >,
> = Lazy::new(DashMap::new);

static OMEGA_CONNECTION: Lazy<Arc<OmegaConnection>> = Lazy::new(|| OmegaConnection::new());

pub fn get_omega_connection() -> Arc<OmegaConnection> {
    OMEGA_CONNECTION.clone()
}

#[derive(Clone, PartialEq)]
enum State {
    Disconnected,
    Connecting,
    Connected,
}

pub struct OmegaConnection {
    sender: Arc<Mutex<Option<Sender>>>,
    receiver: Arc<Mutex<Option<Receiver>>>,
    state: Arc<RwLock<State>>,
}

impl OmegaConnection {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            sender: Arc::new(Mutex::new(None)),
            receiver: Arc::new(Mutex::new(None)),
            state: Arc::new(RwLock::new(State::Disconnected)),
        })
    }

    pub async fn connect(self: Arc<Self>, addr: &str) -> Result<(), String> {
        *self.state.write().await = State::Connecting;

        let (sender, receiver) = connect(addr)
            .await
            .map_err(|e| format!("Connect error: {e:?}"))?;

        *self.sender.lock().await = Some(sender);
        *self.receiver.lock().await = Some(receiver);

        *self.state.write().await = State::Connected;

        let read_self = self.clone();
        tokio::spawn(async move {
            read_self.read_loop().await;
        });

        self.identify().await?;

        Ok(())
    }

    async fn identify(&self) -> Result<(), String> {
        let msg = CommunicationValue::new(CommunicationType::identification)
            .add_data(DataTypes::omikron, DataValue::Number(1));

        self.await_response(&msg, Some(Duration::from_secs(10)))
            .await?;

        Ok(())
    }

    async fn read_loop(self: Arc<Self>) {
        loop {
            let result = {
                let mut guard = self.receiver.lock().await;
                match guard.as_mut() {
                    Some(receiver) => receiver.receive().await,
                    None => return,
                }
            };

            let cv = match result {
                Ok(v) => v,
                Err(_) => {
                    *self.state.write().await = State::Disconnected;
                    return;
                }
            };

            let id = cv.get_id();

            if let Some((_, task)) = WAITING.remove(&id) {
                (task.1)(self.clone(), cv);
                continue;
            }

            if cv.is_type(CommunicationType::ping) {
                let pong = CommunicationValue::new(CommunicationType::pong).with_id(id);
                let _ = self.send(&pong).await;
            }
        }
    }

    pub async fn send(&self, cv: &CommunicationValue) -> Result<(), String> {
        let guard = self.sender.lock().await;
        if let Some(sender) = guard.as_ref() {
            sender
                .send(cv)
                .await
                .map_err(|e| format!("Send error: {e:?}"))
        } else {
            Err("Not connected".into())
        }
    }

    pub async fn await_response(
        &self,
        cv: &CommunicationValue,
        timeout: Option<Duration>,
    ) -> Result<CommunicationValue, String> {
        let (tx, mut rx) = mpsc::channel(1);
        let id = cv.get_id();

        WAITING.insert(
            id.into(),
            (
                Instant::now(),
                Box::new(move |_, response| {
                    let _ = tx.try_send(response);
                    true
                }),
            ),
        );

        self.send(cv).await?;

        match tokio::time::timeout(timeout.unwrap_or(Duration::from_secs(10)), rx.recv()).await {
            Ok(Some(v)) => Ok(v),
            _ => {
                WAITING.remove(&id.into());
                Err("Timeout waiting for response".into())
            }
        }
    }
    pub async fn close_iota(iota_id: i64) {
        let cv = CommunicationValue::new(CommunicationType::iota_disconnected)
            .add_data(DataTypes::iota_id, DataValue::Number(iota_id));
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
                CommunicationValue::new(t).add_data(DataTypes::user_id, DataValue::Number(user_id));
            OmegaConnection::send_global(cv).await;
        }
    }
    async fn send_global(cv: CommunicationValue) {
        OMEGA_CONNECTION.send(&cv).await;
    }

    pub async fn user_states(user_id: i64, user_ids: Vec<i64>) {
        let user_ids_str = user_ids
            .iter()
            .map(|id| DataValue::Number(*id))
            .collect::<Vec<_>>();
        let cv = CommunicationValue::new(CommunicationType::get_states)
            .add_data(DataTypes::user_ids, DataValue::Array(user_ids_str));
        let msg_id = cv.get_id();

        WAITING.insert(
            msg_id,
            (
                Instant::now(),
                Box::new(
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
            ),
        );

        OmegaConnection::send_global(cv).await;
    }
}
