use std::sync::Arc;

use uuid::Uuid;

use crate::{
    app_state::AppState,
    calls::{call_group::CallGroup, error::CallError},
};

pub struct CallService {
    state: Arc<AppState>,
}

impl CallService {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }

    pub async fn get_call(&self, call_id: Uuid) -> Option<Arc<CallGroup>> {
        self.state.call_manager.get_call(call_id).await
    }

    pub async fn token_for_user(&self, user_id: u64, call_id: Uuid) -> Result<String, CallError> {
        self.state
            .call_manager
            .get_call_token(user_id, call_id)
            .await
    }
}
