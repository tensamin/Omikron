use crate::calls::call_group::CallGroup;
use crate::data::communication::{CommunicationType, CommunicationValue, DataTypes};
use futures::{SinkExt, StreamExt};
use json::JsonValue;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tungstenite::Utf8Bytes;
use uuid::Uuid;
use warp::Filter;

pub type Tx = UnboundedSender<Utf8Bytes>;

#[derive(Debug)]
pub struct CallManagerState {
    pub call_groups: HashMap<Uuid, Arc<CallGroup>>,
}

impl CallManagerState {
    pub fn new() -> Self {
        CallManagerState {
            call_groups: HashMap::new(),
        }
    }

    pub fn get_or_create_group(&mut self, call_id: Uuid, secret: &str) -> Arc<CallGroup> {
        let g = self.call_groups.get_mut(&call_id);
        if let Some(group) = g {
            group.clone()
        } else {
            let cg = Arc::new(CallGroup::new(call_id, secret.to_string()));
            self.call_groups.insert(call_id, cg);
            self.call_groups.get(&call_id).unwrap().clone()
        }
    }

    pub fn remove_inactive(&mut self) {
        self.call_groups.retain(|_k, v| v.callers.len() > 0);
    }
}
