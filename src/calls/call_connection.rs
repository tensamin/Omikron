use async_tungstenite::{WebSocketReceiver, WebSocketSender, tungstenite::Message};
use std::{any::Any, sync::Arc};
use tokio::sync::{
    RwLock,
    mpsc::{UnboundedSender, unbounded_channel},
};
use tokio_util::compat::Compat;
use tungstenite::Utf8Bytes;
use uuid::Uuid;

use crate::{
    calls::call_manager,
    data::communication::{CommunicationType, CommunicationValue, DataTypes},
    util::print::{PrintType, line, line_err},
};
use json::JsonValue;

pub struct CallConnection {
    pub sender: Arc<RwLock<WebSocketSender<Compat<tokio::net::TcpStream>>>>,
    pub receiver: Arc<RwLock<WebSocketReceiver<Compat<tokio::net::TcpStream>>>>,
    pub tx: UnboundedSender<Utf8Bytes>,
    pub user_id: Arc<RwLock<Option<Uuid>>>,
    pub call_id: Arc<RwLock<Option<Uuid>>>,
}

impl CallConnection {
    pub async fn new(
        sender: WebSocketSender<Compat<tokio::net::TcpStream>>,
        receiver: WebSocketReceiver<Compat<tokio::net::TcpStream>>,
    ) -> Arc<Self> {
        let (tx, mut rx) = unbounded_channel::<Utf8Bytes>();

        let conn = Arc::new(Self {
            sender: Arc::new(RwLock::new(sender)),
            receiver: Arc::new(RwLock::new(receiver)),
            tx,
            user_id: Arc::new(RwLock::new(None)),
            call_id: Arc::new(RwLock::new(None)),
        });

        // Spawn sender task to forward tx → session
        let sender_clone = Arc::clone(&conn.sender);
        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                let mut sess = sender_clone.write().await;
                let _ = sess.send(Message::Text(msg)).await;
            }
        });

        conn
    }

    /// Handle a single incoming message
    pub async fn handle_message(self: Arc<Self>, msg: Utf8Bytes) {
        let mut cv = CommunicationValue::from_json(&msg);
        if let Some(sender) = *self.user_id.read().await {
            cv = cv.with_sender(sender);
        }

        if cv.is_type(CommunicationType::webrtc_sdp)
            | cv.is_type(CommunicationType::webrtc_ice)
            | cv.is_type(CommunicationType::watch_stream)
        {
            line(
                PrintType::CallIn,
                &format!(
                    "{:?} : {} -> {} ",
                    &cv.type_id(),
                    &cv.get_sender(),
                    &cv.get_data(DataTypes::receiver_id).unwrap()
                ),
            );
        } else if !cv.is_type(CommunicationType::ping) {
            line(PrintType::CallIn, &cv.to_json().to_string());
        }

        match cv.comm_type {
            CommunicationType::identification => self.handle_identification(cv).await,
            CommunicationType::ping => self.handle_ping(cv).await,
            CommunicationType::client_changed => self.handle_client_changed(cv).await,
            CommunicationType::start_stream | CommunicationType::end_stream => {
                self.handle_stream_toggle(cv).await
            }
            CommunicationType::webrtc_sdp
            | CommunicationType::webrtc_ice
            | CommunicationType::watch_stream => self.handle_direct_relay(cv).await,
            _ => {}
        }
    }

    async fn handle_identification(&self, cv: CommunicationValue) {
        let user_str = cv
            .get_data(DataTypes::user_id)
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let call_str = cv
            .get_data(DataTypes::call_id)
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let secret_sha = cv
            .get_data(DataTypes::call_secret_sha)
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let (Ok(uid), Ok(cid)) = (Uuid::parse_str(user_str), Uuid::parse_str(call_str)) else {
            return;
        };

        {
            *self.user_id.write().await = Some(uid);
            *self.call_id.write().await = Some(cid);
        }

        let group = call_manager::get_or_create_group(cid, secret_sha).await;
        if let None = group {
            self.send_message(&CommunicationValue::new(
                CommunicationType::error_invalid_secret,
            ))
            .await;
            return;
        }
        let group = group.unwrap();

        // Build broadcast
        let broadcast = CommunicationValue::new(CommunicationType::client_connected)
            .with_id(cv.get_id().clone())
            .add_data_str(DataTypes::user_id, uid.to_string())
            .add_data_str(DataTypes::call_state, "muted".to_string());
        {
            group
                .lock()
                .await
                .broadcast(&broadcast.to_json().to_string())
                .await;
        }

        {
            group.lock().await.add_member(uid, self.tx.clone());
        }

        // Build response
        let mut response = CommunicationValue::new(CommunicationType::identification_response)
            .with_id(cv.get_id().clone());

        let mut users = JsonValue::new_object();
        {
            for caller in group.lock().await.callers.values() {
                let mut user_info = JsonValue::new_object();
                let _ = user_info.insert("state", JsonValue::from("muted"));
                let _ = user_info.insert("streaming", JsonValue::from(false));
                let _ = users.insert(&caller.user_id.read().await.to_string(), user_info);
            }
        }
        response = response.add_data(DataTypes::about, users);
        self.send_message(&response).await;
    }

    async fn handle_ping(&self, cv: CommunicationValue) {
        let resp = CommunicationValue::new(CommunicationType::pong).with_id(cv.get_id().clone());
        self.send_message(&resp).await;
    }

    async fn handle_client_changed(&self, cv: CommunicationValue) {
        let uid = match *self.user_id.read().await {
            Some(id) => id,
            None => return,
        };

        let cid = match *self.call_id.read().await {
            Some(id) => id,
            None => return,
        };

        if let Some(JsonValue::String(_state_str)) = cv.get_data(DataTypes::call_state) {
            let Some(group_lock) = call_manager::get_group(cid).await else {
                return;
            };
            let mut group = group_lock.lock().await;
            if let Some(_caller) = group.caller_state_mut(&uid) {
                // caller_state_change(caller, &state_str);
            }

            let mut bc = cv.clone();
            bc = bc.add_data(DataTypes::sender_id, JsonValue::String(uid.to_string()));
            group.broadcast(&bc.to_json().to_string()).await;
        }
    }

    async fn handle_stream_toggle(&self, cv: CommunicationValue) {
        let uid = match *self.user_id.read().await {
            Some(id) => id,
            None => return,
        };

        let cid = match *self.call_id.read().await {
            Some(id) => id,
            None => return,
        };

        if let Some(group_lock) = call_manager::get_group(cid).await {
            let group = group_lock.lock().await;
            let _streaming = cv.comm_type == CommunicationType::start_stream;
            let mut bc = cv.clone();
            bc = bc.add_data(DataTypes::sender_id, JsonValue::String(uid.to_string()));
            group.broadcast(&bc.to_json().to_string()).await;
        }
    }

    async fn handle_direct_relay(&self, cv: CommunicationValue) {
        let uid = match *self.user_id.read().await {
            Some(id) => id,
            None => return,
        };
        let cid = match *self.call_id.read().await {
            Some(id) => id,
            None => return,
        };
        if let Some(JsonValue::String(receiver_str)) = cv.get_data(DataTypes::receiver_id) {
            if let Ok(receiver_id) = Uuid::parse_str(&receiver_str) {
                if let Some(group) = call_manager::get_group(cid).await {
                    let mut bc = cv.clone();
                    bc = bc.add_data(DataTypes::sender_id, JsonValue::String(uid.to_string()));
                    group
                        .lock()
                        .await
                        .send_to(&receiver_id, &bc.to_json().to_string())
                        .await;
                    line(
                        PrintType::CallOut,
                        &format!("Forwarded WebRTC message to receiver: {}", receiver_str),
                    );
                } else {
                    line_err(PrintType::CallOut, "Failed to find the group for the call.");
                }
            } else {
                line_err(PrintType::CallOut, "Invalid receiver_id in WebRTC message.");
            }
        } else {
            line_err(PrintType::CallOut, "Missing receiver_id in WebRTC message.");
        }
    }
    pub async fn send_message(&self, cv: &CommunicationValue) {
        if !cv.is_type(CommunicationType::pong) {
            line(PrintType::CallOut, &cv.to_json().to_string());
        }
        let mut session = self.sender.write().await;
        if let Err(e) = session
            .send(Message::Text(Utf8Bytes::from(cv.to_json().to_string())))
            .await
        {
            line_err(
                PrintType::CallOut,
                &format!("Failed to send message to client: {}", e),
            );
        }
    }

    pub async fn close(&self) {
        let (uid, cid) = { (*self.user_id.read().await, *self.call_id.read().await) };
        if let (Some(uid), Some(cid)) = (uid, cid) {
            if let Some(group) = call_manager::get_group(cid).await {
                group
                    .lock()
                    .await
                    .broadcast(
                        &CommunicationValue::new(CommunicationType::client_disconnected)
                            .add_data_str(DataTypes::user_id, uid.to_string())
                            .to_json()
                            .to_string(),
                    )
                    .await;
                group.lock().await.disconnect_member(uid).await;
            }
            call_manager::remove_inactive().await;
        }

        let mut session = self.sender.write().await;
        let _ = session.close(None).await;
    }
    pub async fn handle_close(&self) {
        self.close().await;
    }
}
