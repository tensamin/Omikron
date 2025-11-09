use crate::calls::call_group::CallGroup;
use futures::lock::Mutex;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::sync::mpsc::UnboundedSender;
use tungstenite::Utf8Bytes;
use uuid::Uuid;

pub type Tx = UnboundedSender<Utf8Bytes>;

pub static CALL_GROUPS: Lazy<RwLock<Mutex<HashMap<Uuid, Arc<Mutex<CallGroup>>>>>> =
    Lazy::new(|| RwLock::new(Mutex::new(HashMap::new())));

pub async fn get_group(call_id: Uuid) -> Option<Arc<Mutex<CallGroup>>> {
    CALL_GROUPS
        .read()
        .await
        .lock()
        .await
        .get_mut(&call_id)
        .cloned()
}
pub async fn get_or_create_group(call_id: Uuid, secret: &str) -> Arc<Mutex<CallGroup>> {
    let g = CALL_GROUPS.write().await;
    if let Some(group) = g.lock().await.get_mut(&call_id) {
        group.clone()
    } else {
        let cg = Arc::new(Mutex::new(CallGroup::new(call_id)));
        g.lock().await.insert(call_id, cg.clone());
        cg
    }
}

pub async fn remove_inactive() {
    let mut rem = Vec::new();
    for cg in CALL_GROUPS.read().await.lock().await.keys() {
        if CALL_GROUPS
            .write()
            .await
            .lock()
            .await
            .get(cg)
            .unwrap()
            .lock()
            .await
            .callers
            .is_empty()
        {
            rem.push(cg.clone());
        }
    }
    for cg in rem {
        CALL_GROUPS.write().await.lock().await.remove(&cg);
    }
}
