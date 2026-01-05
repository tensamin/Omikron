use std::sync::Arc;

use tokio::sync::RwLock;
use uuid::Uuid;

use crate::calls::caller::Caller;

pub struct CallGroup {
    pub call_id: Uuid,
    pub members: RwLock<Vec<Arc<Caller>>>,
    pub show: RwLock<bool>,
}

impl CallGroup {
    pub fn new(call_id: Uuid, user: Arc<Caller>) -> Self {
        CallGroup {
            call_id,
            members: RwLock::new(vec![user]),
            show: RwLock::new(true),
        }
    }
}
