use crate::calls::{
    call_group::{CallGroup, CallRole, CallSecretEnvelope},
    call_util::LiveKitService,
    error::CallError,
};
use dashmap::DashMap;
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;
use uuid::Uuid;
#[derive(Debug, thiserror::Error)]
pub enum CallServiceError {
    #[error("call not found")]
    NotFound,
    #[error("not authorized")]
    NotAuthorized,
    #[error("timed out until {until_ms}")]
    TimedOut { until_ms: i64 },
    #[error("invalid user")]
    InvalidUser,
    #[error("invalid request")]
    InvalidRequest,
    #[error("delivery failed")]
    DeliveryFailed,
    #[error(transparent)]
    LiveKit(#[from] CallError),
}
pub struct CallManager {
    pub(crate) groups: DashMap<Uuid, Arc<CallGroup>>,
    creation_locks: DashMap<Uuid, Arc<Mutex<()>>>,
    pub livekit: Arc<LiveKitService>,
    pub owner_omikron_id: u64,
}
impl Default for CallManager {
    fn default() -> Self {
        Self::new_with_owner(Arc::new(LiveKitService::new(None)), 0)
    }
}
impl CallManager {
    pub fn new(livekit: Arc<LiveKitService>) -> Self {
        Self::new_with_owner(livekit, 0)
    }
    pub fn new_with_owner(livekit: Arc<LiveKitService>, owner: u64) -> Self {
        Self {
            groups: DashMap::new(),
            creation_locks: DashMap::new(),
            livekit,
            owner_omikron_id: owner,
        }
    }
    pub async fn get_call(&self, id: Uuid) -> Option<Arc<CallGroup>> {
        self.groups.get(&id).map(|g| g.clone())
    }
    pub async fn get_call_groups(&self, user: u64) -> Vec<Arc<CallGroup>> {
        let groups = self.groups.iter().map(|g| g.clone()).collect::<Vec<_>>();
        let mut result = Vec::new();
        for g in groups {
            if g.is_related(user).await {
                result.push(g)
            }
        }
        result
    }
    pub fn should_forward_invite(&self, from: u64, to: u64) -> bool {
        from != to
    }
    fn now_ms() -> Result<i64, CallServiceError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CallServiceError::InvalidRequest)
            .and_then(|d| {
                i64::try_from(d.as_millis()).map_err(|_| CallServiceError::InvalidRequest)
            })
    }
    pub async fn get_call_token(&self, user: u64, id: Uuid) -> Result<String, CallServiceError> {
        self.get_or_create_token(user, id, None).await
    }
    pub async fn get_or_create_token(
        &self,
        user: u64,
        id: Uuid,
        creator: Option<CallSecretEnvelope>,
    ) -> Result<String, CallServiceError> {
        if let Some(g) = self.get_call(id).await {
            return self.token_existing(g, user).await;
        }
        let secret = creator.ok_or(CallServiceError::NotFound)?;
        let lock = self
            .creation_locks
            .entry(id)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone();
        let _guard = lock.lock().await;
        if let Some(g) = self.get_call(id).await {
            return self.token_existing(g, user).await;
        }
        self.livekit.create_room(id).await?;
        let g = Arc::new(CallGroup::new_with_service(
            id,
            self.owner_omikron_id,
            user,
            secret,
            self.livekit.clone(),
        ));
        g.update_metadata().await?;
        self.groups.insert(id, g);
        self.livekit
            .create_token(user, id, true)
            .map_err(Into::into)
    }
    async fn token_existing(
        &self,
        g: Arc<CallGroup>,
        user: u64,
    ) -> Result<String, CallServiceError> {
        let member = match g.member(user).await {
            Some(member) => member,
            None => {
                // A failed token request must not turn an invitation into
                // authorization.  LiveKit token creation is pure/local, so
                // perform it before atomically accepting the invite.
                if !g.is_related(user).await {
                    return Err(CallServiceError::NotAuthorized);
                }
                let token = self.livekit.create_token(user, g.call_id, false)?;
                g.accept_invite(user)
                    .await
                    .ok_or(CallServiceError::NotAuthorized)?;
                return Ok(token);
            }
        };
        if let Some(until) = member.timeout_until_ms {
            if until > Self::now_ms()? {
                return Err(CallServiceError::TimedOut { until_ms: until });
            }
        }
        self.livekit
            .create_token(user, g.call_id, member.role == CallRole::Admin)
            .map_err(Into::into)
    }
    pub async fn add_invite(
        &self,
        id: Uuid,
        from: u64,
        to: u64,
        secret: CallSecretEnvelope,
    ) -> Result<(), CallServiceError> {
        let g = self.get_call(id).await.ok_or(CallServiceError::NotFound)?;
        if from == to {
            return Err(CallServiceError::InvalidRequest);
        }
        let caller = g
            .member(from)
            .await
            .ok_or(CallServiceError::NotAuthorized)?;
        if caller
            .timeout_until_ms
            .is_some_and(|until| Self::now_ms().map(|now| until > now).unwrap_or(true))
        {
            return Err(CallServiceError::NotAuthorized);
        }
        g.invite(from, to, secret)
            .await
            .map_err(|_| CallServiceError::InvalidRequest)
    }
    pub async fn rollback_invite(&self, id: Uuid, user: u64) {
        if let Some(g) = self.get_call(id).await {
            g.rollback_invite(user).await
        }
    }
    pub async fn call_data(&self, id: Uuid, user: u64) -> Result<Vec<u64>, CallServiceError> {
        let g = self.get_call(id).await.ok_or(CallServiceError::NotFound)?;
        if !g.is_related(user).await {
            return Err(CallServiceError::NotAuthorized);
        }
        Ok(g.member_ids().await)
    }
    pub async fn timeout_user(
        &self,
        id: Uuid,
        requester: u64,
        target: u64,
        until: i64,
    ) -> Result<(), CallServiceError> {
        if requester == target {
            return Err(CallServiceError::InvalidRequest);
        }
        let g = self.get_call(id).await.ok_or(CallServiceError::NotFound)?;
        if g.member(requester).await.map(|m| m.role == CallRole::Admin) != Some(true) {
            return Err(CallServiceError::NotAuthorized);
        }
        g.timeout(target, until)
            .await
            .map_err(|_| CallServiceError::InvalidUser)?;
        self.livekit.remove_participant(id, target).await?;
        Ok(())
    }
    pub async fn disconnect_user(
        &self,
        id: Uuid,
        requester: u64,
        target: u64,
    ) -> Result<(), CallServiceError> {
        let g = self.get_call(id).await.ok_or(CallServiceError::NotFound)?;
        let source = g
            .member(requester)
            .await
            .ok_or(CallServiceError::NotAuthorized)?;
        if requester != target && source.role != CallRole::Admin {
            return Err(CallServiceError::NotAuthorized);
        }
        if requester == target && source.role == CallRole::Admin && g.member_ids().await.len() == 1
        {
            g.mark_ending().await;
            self.livekit.delete_room(id).await?;
            self.groups.remove(&id);
            return Ok(());
        }
        g.revoke(target)
            .await
            .ok_or(CallServiceError::InvalidUser)?;
        self.livekit.remove_participant(id, target).await?;
        g.update_metadata().await?;
        Ok(())
    }
    pub async fn end_call(&self, id: Uuid, requester: u64) -> Result<(), CallServiceError> {
        let g = self.get_call(id).await.ok_or(CallServiceError::NotFound)?;
        if g.member(requester).await.map(|m| m.role == CallRole::Admin) != Some(true) {
            return Err(CallServiceError::NotAuthorized);
        }
        g.mark_ending().await;
        self.livekit.delete_room(id).await?;
        self.groups.remove(&id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn secret() -> CallSecretEnvelope {
        CallSecretEnvelope {
            secret_id: "s".into(),
            version_number: 1,
            encrypted_secret: vec![1],
            kem_ciphertext: vec![2],
            wrapping_scheme: "test".into(),
        }
    }
    #[tokio::test]
    async fn missing_call_without_creator_secret_is_not_found() {
        assert!(matches!(
            CallManager::default()
                .get_or_create_token(1, Uuid::new_v4(), None)
                .await,
            Err(CallServiceError::NotFound)
        ));
    }
    #[tokio::test]
    async fn invite_is_pending_until_token_request() {
        let manager = CallManager::new_with_owner(
            Arc::new(LiveKitService::new(Some(crate::config::LiveKitConfig {
                hostname: "https://livekit.invalid".into(),
                client_url: "wss://livekit.invalid".into(),
                api_key: "key".into(),
                api_secret: "secret".into(),
            }))),
            1,
        );
        let id = Uuid::new_v4();
        let group = Arc::new(CallGroup::new_with_service(
            id,
            1,
            1,
            secret(),
            manager.livekit.clone(),
        ));
        manager.groups.insert(id, group.clone());
        manager.add_invite(id, 1, 2, secret()).await.unwrap();
        assert!(group.member(2).await.is_none());
        let _ = manager.get_call_token(2, id).await;
        assert!(group.member(2).await.is_some());
    }
    #[tokio::test]
    async fn self_invite_is_rejected() {
        let manager = CallManager::default();
        let id = Uuid::new_v4();
        manager.groups.insert(
            id,
            Arc::new(CallGroup::new_with_service(
                id,
                1,
                1,
                secret(),
                manager.livekit.clone(),
            )),
        );
        assert!(matches!(
            manager.add_invite(id, 1, 1, secret()).await,
            Err(CallServiceError::InvalidRequest)
        ));
    }
}
