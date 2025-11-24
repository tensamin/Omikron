use crate::calls::caller::Caller;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::mpsc::UnboundedSender;
use tungstenite::Utf8Bytes;
use uuid::Uuid;

pub struct CallGroup {
    pub callers: HashMap<Uuid, Arc<Caller>>,
    pub secret_hash: String,
}

impl CallGroup {
    pub fn new(secret_hash: String) -> Self {
        Self {
            callers: HashMap::new(),
            secret_hash: secret_hash,
        }
    }

    pub fn add_member(&mut self, user_id: Uuid, tx: UnboundedSender<Utf8Bytes>) {
        self.callers
            .insert(user_id, Arc::new(Caller::new(user_id, tx)));
    }
    pub fn remove_member(&mut self, user_id: Uuid) {
        self.callers.remove(&user_id);
    }
    pub fn get_member(&self, user_id: &Uuid) -> Option<&Arc<Caller>> {
        self.callers.get(user_id)
    }
    pub async fn disconnect_member(&mut self, user_id: Uuid) {
        if let Some(caller) = self.callers.get(&user_id) {
            caller.disconnect().await;
        }
    }

    pub async fn is_empty(&self) -> bool {
        for caller in self.callers.values() {
            if caller.is_connected().await {
                return false;
            }
        }
        true
    }

    pub async fn send_to(&self, user_id: &Uuid, message: &str) {
        if let Some(caller) = self.callers.get(user_id) {
            caller.send(Utf8Bytes::from(message.to_string())).await;
        }
    }

    pub async fn broadcast(&self, message: &str) {
        for caller in self.callers.values() {
            caller.send(Utf8Bytes::from(message.to_string())).await;
        }
    }

    pub fn caller_state_mut(&mut self, user_id: &Uuid) -> Option<&Arc<Caller>> {
        self.callers.get(user_id)
    }
}
