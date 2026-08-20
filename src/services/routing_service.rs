use std::sync::Arc;

use mtp::codec::CommunicationValue;

use crate::{app_state::AppState, rho::rho_connection::RhoConnection};

#[allow(dead_code)]
pub struct RoutingService {
    state: Arc<AppState>,
}

#[allow(dead_code)]
impl RoutingService {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }

    pub async fn route_to_user(&self, user_id: i64, message: CommunicationValue) {
        if let Some(connection) = self.state.rho.get_for_user(user_id).await {
            connection.message_to_iota(message).await;
        }
    }

    pub async fn connection_for_user(&self, user_id: i64) -> Option<Arc<RhoConnection>> {
        self.state.rho.get_for_user(user_id).await
    }
}
