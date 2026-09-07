use std::sync::Arc;

use uuid::Uuid;

use crate::{
    app_state::AppState,
    calls::{call_group::CallGroup, call_manager::CallServiceError},
};

#[allow(dead_code)]
pub struct CallService {
    state: Arc<AppState>,
}

#[allow(dead_code)]
impl CallService {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }

    pub async fn get_call(&self, call_id: Uuid) -> Option<Arc<CallGroup>> {
        self.state.call_manager.get_call(call_id).await
    }

    pub async fn token_for_user(
        &self,
        user_id: u64,
        call_id: Uuid,
    ) -> Result<String, CallServiceError> {
        self.state
            .call_manager
            .get_call_token(user_id, call_id)
            .await
    }
}
