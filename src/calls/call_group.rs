use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use tokio::sync::mpsc::UnboundedSender;

use json::JsonValue;
use tungstenite::Utf8Bytes;
use uuid::Uuid;

use crate::data::communication::{CommunicationType, CommunicationValue, DataTypes};

pub type Tx = UnboundedSender<Utf8Bytes>;

#[derive(Debug)]
pub struct CallGroup {
    pub call_id: Uuid,
    secret: String,
    pub callers: HashMap<Uuid, Caller>,
    pub inform_on_end: HashSet<Uuid>,
    pub started_at: u64,
    pub ended_at: Option<u64>,
}

impl CallGroup {
    pub fn new(call_id: Uuid, secret: String) -> Self {
        CallGroup {
            call_id,
            secret,
            callers: HashMap::new(),
            inform_on_end: HashSet::new(),
            started_at: chrono::Utc::now().timestamp_millis() as u64,
            ended_at: None,
        }
    }

    pub fn add_member(mut self, user_id: Uuid, tx: Tx) {
        // If already present, drop old
        if let Some(old) = self.callers.remove(&user_id) {
            // optionally notify or close old
            // no direct close since we don’t hold session here
        }
        // Notify existing about new client
        let mut cv = CommunicationValue::new(CommunicationType::client_connected);
        cv = cv
            .add_data(DataTypes::user_id, JsonValue::String(user_id.to_string()))
            .add_data(
                DataTypes::call_state,
                JsonValue::String("muted".to_string()),
            );
        // broadcast
        let msg = cv.to_json().to_string();
        for c in self.callers.values() {
            let _ = c.tx.send(Utf8Bytes::from(msg.clone()));
        }
        self.callers.insert(user_id, Caller { user_id, tx });
    }

    pub fn remove_member(&mut self, user_id: &Uuid) {
        if self.callers.remove(user_id).is_some() {
            let cv = CommunicationValue::new(CommunicationType::client_closed)
                .add_data(DataTypes::user_id, JsonValue::String(user_id.to_string()))
                .to_json()
                .to_string();
            for c in self.callers.values() {
                let _ = c.tx.send(Utf8Bytes::from(cv.clone()));
            }
        }
        if self.callers.is_empty() {
            self.ended_at = Some(chrono::Utc::now().timestamp_millis() as u64);
            // Optionally notify inform_on_end
            let end_msg = CommunicationValue::new(CommunicationType::end_call)
                .add_data(
                    DataTypes::call_id,
                    JsonValue::String(self.call_id.to_string()),
                )
                .to_json()
                .to_string();
            for &uid in &self.inform_on_end {
                // here you’d send via your Rho / other channel to user
                // e.g. RhoManager::message_to(uid, end_msg.clone());
            }
        }
    }

    pub fn broadcast(&self, msg: &str) {
        for c in self.callers.values() {
            let _ = c.tx.send(Utf8Bytes::from(msg.clone()));
        }
    }

    pub fn send_to(&self, target: &Uuid, msg: &str) {
        if let Some(c) = self.callers.get(target) {
            let _ = c.tx.send(Utf8Bytes::from(msg.clone()));
        }
    }

    pub fn caller_state_mut(&mut self, uid: &Uuid) -> Option<&mut Caller> {
        self.callers.get_mut(uid)
    }
}
#[derive(Debug)]
pub struct Caller {
    pub user_id: Uuid,
    pub tx: Tx,
}
