use std::sync::Arc;

use crate::{app_state::AppState, rho::rho_connection::RhoConnection};

pub struct UserService {
    state: Arc<AppState>,
}

impl UserService {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }

    pub async fn connection_for_user(&self, user_id: i64) -> Option<Arc<RhoConnection>> {
        self.state.rho.get_for_user(user_id).await
    }
}
