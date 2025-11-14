use std::sync::Arc;

use futures::lock::Mutex;
use tokio::sync::{RwLock, mpsc::UnboundedSender};
use tungstenite::Utf8Bytes;
use uuid::Uuid;

pub struct Caller {
    pub user_id: RwLock<Uuid>,
    pub tx: Mutex<Option<UnboundedSender<Utf8Bytes>>>,
    pub user_state: RwLock<CallUserState>,
    pub streaming: RwLock<bool>,
}
#[derive(Clone)]
pub enum CallUserState {
    Active,
    Muted,
    Deafed,
    Disconnected,
}
impl Caller {
    pub fn new(user_id: Uuid, tx: UnboundedSender<Utf8Bytes>) -> Self {
        Self {
            user_id: RwLock::new(user_id),
            tx: Mutex::new(Some(tx)),
            user_state: RwLock::new(CallUserState::Active),
            streaming: RwLock::new(false),
        }
    }

    pub async fn send(&self, msg: impl Into<Utf8Bytes>) {
        if let Some(tx) = &*self.tx.lock().await {
            let _ = tx.send(msg.into());
        }
    }

    pub async fn disconnect(self: &Arc<Self>) {
        *self.user_state.write().await = CallUserState::Disconnected;
        *self.tx.lock().await = None;
    }

    pub async fn is_connected(&self) -> bool {
        if let CallUserState::Disconnected = *self.user_state.read().await {
            false
        } else {
            true
        }
    }
}
