use uuid::Uuid;

use crate::calls::call_util;

pub struct Caller {
    pub user_id: i64,
    pub call_id: Uuid,
    pub inviters: Vec<i64>,
}

impl Caller {
    pub fn new(user_id: i64, call_id: Uuid, inviter_id: i64) -> Self {
        Caller {
            user_id,
            call_id,
            inviters: vec![inviter_id],
        }
    }
    pub fn create_token(&self) -> String {
        if let Ok(token) = call_util::create_token(self.user_id, self.call_id) {
            token
        } else {
            String::new()
        }
    }
}
