use uuid::Uuid;

use crate::calls::call_util;

pub struct Caller {
    pub user_id: Uuid,
    pub call_id: Uuid,
    pub inviters: Vec<Uuid>,
}

impl Caller {
    pub fn new(user_id: Uuid, call_id: Uuid, inviter_id: Uuid) -> Self {
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
