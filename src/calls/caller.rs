use uuid::Uuid;

use crate::calls::call_util;

pub struct Caller {
    pub user_id: i64,
    pub call_id: Uuid,
    pub has_admin: bool,
}

impl Caller {
    pub fn new(user_id: i64, call_id: Uuid, has_admin: bool) -> Self {
        Caller {
            user_id,
            call_id,
            has_admin,
        }
    }
    pub fn set_admin(&mut self, has_admin: bool) {
        self.has_admin = has_admin;
    }
    pub fn has_admin(&self) -> bool {
        self.has_admin
    }
    pub fn create_token(&self) -> String {
        if let Ok(token) = call_util::create_token(self.user_id, self.call_id, self.has_admin()) {
            token
        } else {
            String::new()
        }
    }
}
