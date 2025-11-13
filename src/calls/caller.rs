use std::sync::Arc;

use futures::lock::Mutex;
use tokio::sync::mpsc::UnboundedSender;
use tungstenite::Utf8Bytes;
use uuid::Uuid;

pub struct Caller {
    pub user_id: Mutex<Uuid>,
    pub tx: Mutex<Option<UnboundedSender<Utf8Bytes>>>,
    pub user_state: Mutex<CallUserState>,
    pub streaming: Mutex<bool>,
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
            user_id: Mutex::new(user_id),
            tx: Mutex::new(Some(tx)),
            user_state: Mutex::new(CallUserState::Active),
            streaming: Mutex::new(false),
        }
    }

    pub fn send(&self, msg: impl Into<Utf8Bytes>) {
        if let Some(tx) = &self.tx.lock().await {
            let _ = tx.send(msg.into());
        }
    }

    pub fn disconnect(self: Arc<Self>) {
        self.user_state = CallUserState::Disconnected;
        self.tx = None;
    }

    pub fn is_connected(&self) -> bool {
        if let CallUserState::Disconnected = self.user_state {
            false
        } else {
            true
        }
    }
}
