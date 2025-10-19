use crate::calls::call_group::CallGroup;
use futures::lock::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedSender;
use tungstenite::Utf8Bytes;
use uuid::Uuid;

pub type Tx = UnboundedSender<Utf8Bytes>;

pub struct CallManagerState {
    pub call_groups: HashMap<Uuid, Arc<Mutex<CallGroup>>>,
}

impl CallManagerState {
    pub fn new() -> Self {
        CallManagerState {
            call_groups: HashMap::new(),
        }
    }

    pub fn get_or_create_group(&mut self, call_id: Uuid, secret: &str) -> Arc<Mutex<CallGroup>> {
        let g = self.call_groups.get_mut(&call_id);
        if let Some(group) = g {
            group.clone()
        } else {
            let cg = Arc::new(Mutex::new(CallGroup::new(call_id)));
            self.call_groups.insert(call_id, cg);
            self.call_groups.get(&call_id).unwrap().clone()
        }
    }

    pub async fn remove_inactive(&mut self) {
        let mut rem = Vec::new();
        for cg in self.call_groups.keys() {
            let group = self.call_groups.get(cg).unwrap().lock().await;
            if group.callers.is_empty() {
                rem.push(cg.clone());
            }
        }
        for cg in rem {
            self.call_groups.remove(&cg);
        }
    }
}
