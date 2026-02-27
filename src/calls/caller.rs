use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::RwLock;
use uuid::Uuid;

use crate::calls::call_util;

pub struct Caller {
    pub user_id: u64,
    pub call_id: Uuid,
    pub has_admin: bool,
    pub timeout: RwLock<i64>,
}

impl Caller {
    pub fn new(user_id: u64, call_id: Uuid, has_admin: bool) -> Self {
        Caller {
            user_id,
            call_id,
            has_admin,
            timeout: RwLock::new(0),
        }
    }
    pub fn set_admin(&mut self, has_admin: bool) {
        self.has_admin = has_admin;
    }
    pub fn has_admin(&self) -> bool {
        self.has_admin
    }
    pub async fn is_timeouted(&self) -> bool {
        *self.timeout.read().await
            > SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64
    }
    pub async fn set_timeout(&self, timeout: i64) {
        *self.timeout.write().await = timeout;
    }
    pub fn create_token(&self) -> String {
        if let Ok(token) = call_util::create_token(self.user_id, self.call_id, self.has_admin()) {
            token
        } else {
            String::new()
        }
    }
}
