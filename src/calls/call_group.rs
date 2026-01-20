use std::sync::Arc;

use tokio::sync::RwLock;
use uuid::Uuid;

use crate::calls::caller::Caller;

pub struct CallGroup {
    pub call_id: Uuid,
    pub members: RwLock<Vec<Arc<Caller>>>,
    pub show: RwLock<bool>,
    pub anonymous_joining: RwLock<bool>,
}

impl CallGroup {
    pub fn new(call_id: Uuid, user: Arc<Caller>) -> Self {
        CallGroup {
            call_id,
            members: RwLock::new(vec![user]),
            show: RwLock::new(true),
            anonymous_joining: RwLock::new(false),
        }
    }

    pub async fn get_caller(&self, user_id: i64) -> Option<Arc<Caller>> {
        self.members
            .read()
            .await
            .iter()
            .find(|caller| caller.user_id == user_id)
            .cloned()
    }

    pub async fn set_anonymous_joining(&self, enable: bool) {
        *self.anonymous_joining.write().await = enable;
    }

    pub async fn remove_caller(&self, user_id: i64) {
        self.members
            .write()
            .await
            .retain(|caller| caller.user_id != user_id);
    }
}
