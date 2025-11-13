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
    pub fn disconnect_member(&mut self, user_id: Uuid) {
        if let Some(caller) = self.callers.get(&user_id) {
            caller.disconnect();
        }
    }

    pub fn remove_member(&mut self, user_id: Uuid) {
        self.callers.remove(&user_id);
    }

    pub fn is_empty(&self) -> bool {
        for caller in self.callers.values() {
            if !caller.is_connected() {
                return false;
            }
        }
        true
    }

    pub fn send_to(&self, user_id: &Uuid, message: &str) {
        if let Some(caller) = self.callers.get(user_id) {
            let _ = caller.send(Utf8Bytes::from(message.to_string()));
        }
    }

    pub fn broadcast(&self, message: &str) {
        for caller in self.callers.values() {
            let _ = caller.send(Utf8Bytes::from(message.to_string()));
        }
    }

    pub fn caller_state_mut(&mut self, user_id: &Uuid) -> Option<&Arc<Caller>> {
        self.callers.get(user_id)
    }
}
