use std::sync::Arc;

use tokio::sync::RwLock;
use uuid::Uuid;

use crate::calls::caller::Caller;

pub struct CallGroup {
    pub call_id: Uuid,
    pub members: RwLock<Vec<Arc<Caller>>>,
}

impl CallGroup {
    pub fn new(call_id: Uuid, user: Arc<Caller>) -> Self {
        CallGroup {
            call_id,
            members: RwLock::new(vec![user]),
        }
    }

    pub async fn add_member(self: Arc<Self>, member: Uuid, inviter: Uuid) {
        self.members
            .write()
            .await
            .push(Arc::new(Caller::new(member, inviter, self.call_id)));
    }
}
