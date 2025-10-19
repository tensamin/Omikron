use crate::calls::caller::Caller;
use std::collections::HashMap;
use tokio::sync::mpsc::UnboundedSender;
use tungstenite::Utf8Bytes;
use uuid::Uuid;

pub struct CallGroup {
    pub call_id: Uuid,
    pub callers: HashMap<Uuid, Caller>,
}

impl CallGroup {
    pub fn new(call_id: Uuid) -> Self {
        Self {
            call_id,
            callers: HashMap::new(),
        }
    }

    pub fn add_member(&mut self, user_id: Uuid, tx: UnboundedSender<Utf8Bytes>) {
        self.callers.insert(user_id, Caller { user_id, tx });
    }

    pub fn remove_member(&mut self, user_id: Uuid) {
        self.callers.remove(&user_id);
    }

    pub fn is_empty(&self) -> bool {
        self.callers.is_empty()
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

    pub fn caller_state_mut(&mut self, user_id: &Uuid) -> Option<&mut Caller> {
        self.callers.get_mut(user_id)
    }
}
