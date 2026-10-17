use crate::calls::{
    call_group::{CallGroup, CallRole},
    call_util::LiveKitService,
    error::CallError,
    persistence::CallPersistence,
};
use crate::config::CallLimits;
use crate::log_event;
use crate::util::logger::{LogLevel, PrintType};
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
    #[error("resource limit reached")]
    ResourceLimit,
    #[error("delivery failed")]
    DeliveryFailed,
    #[error(transparent)]
    LiveKit(#[from] CallError),
}
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum InviteRelation {
    Member,
    Pending,
    New,
}
pub struct CallManager {
    pub(crate) groups: DashMap<Uuid, Arc<CallGroup>>,
    admission_locks: DashMap<u64, Arc<Mutex<()>>>,
    pub livekit: Arc<LiveKitService>,
    pub owner_omikron_id: u64,
    limits: CallLimits,
    pub persistence: Option<Arc<CallPersistence>>,
}
impl Default for CallManager {
    fn default() -> Self {
        Self::new_with_owner(Arc::new(LiveKitService::new(None)), 0)
    }
}
impl CallManager {
    pub fn new_with_owner(livekit: Arc<LiveKitService>, owner: u64) -> Self {
        Self::new_with_limits(livekit, owner, CallLimits::default())
    }
    pub fn new_with_limits(livekit: Arc<LiveKitService>, owner: u64, limits: CallLimits) -> Self {
        Self {
            groups: DashMap::new(),
            admission_locks: DashMap::new(),
            livekit,
            owner_omikron_id: owner,
            limits,
            persistence: None,
        }
    }
    pub fn with_persistence(mut self, persistence: Arc<CallPersistence>) -> Self {
        self.persistence = Some(persistence);
        self
    }
    pub async fn restore(&self) -> Result<(), CallServiceError> {
        let Some(db) = &self.persistence else {
            return Ok(());
        };
        let calls = db
            .restore(Self::now_ms()?)
            .map_err(|_| CallServiceError::DeliveryFailed)?;
        for call in calls {
            let Some(_creator) = call.members.first() else {
                continue;
            };
            let mut group = CallGroup::new_with_service(
                call.id,
                self.owner_omikron_id,
                call.owner,
                self.livekit.clone(),
                self.limits.clone(),
            );
            group.created_at_ms = call.created_at_ms;
            {
                let mut state = group.state.write().await;
                state.members = call
                    .members
                    .into_iter()
                    .map(|member| (member.user_id, member))
                    .collect();
                state.pending_invites = call.invites.into_iter().collect();
                state.anonymous_joining = call.anonymous_joining;
                state.short_link = call.short_link;
            }
            self.groups.insert(call.id, Arc::new(group));
        }
        Ok(())
    }
    pub async fn reserve(&self, user: u64) -> Result<Uuid, CallServiceError> {
        let db = self
            .persistence
            .as_ref()
            .ok_or(CallServiceError::DeliveryFailed)?;
        if self.get_call_groups(user).await.len() >= self.limits.max_calls_per_user {
            return Err(CallServiceError::ResourceLimit);
        }
        for _ in 0..10 {
            let id = Uuid::new_v4();
            if self.get_call(id).await.is_none()
                && db
                    .reserve(id, user, Self::now_ms()? + 30_000)
                    .map_err(|_| CallServiceError::DeliveryFailed)?
            {
                return Ok(id);
            }
        }
        Err(CallServiceError::ResourceLimit)
    }
    pub async fn reservation_created_at(
        &self,
        user: u64,
        id: Uuid,
    ) -> Result<i64, CallServiceError> {
        let db = self
            .persistence
            .as_ref()
            .ok_or(CallServiceError::DeliveryFailed)?;
        db.reservation_created_at(id, user, Self::now_ms()?)
            .map_err(|_| CallServiceError::DeliveryFailed)?
            .ok_or(CallServiceError::NotFound)
    }
    pub async fn activate(
        &self,
        user: u64,
        id: Uuid,
        created_at: i64,
    ) -> Result<String, CallServiceError> {
        let db = self
            .persistence
            .as_ref()
            .ok_or(CallServiceError::DeliveryFailed)?;
        if db
            .reservation_owner(id, Self::now_ms()?)
            .map_err(|_| CallServiceError::DeliveryFailed)?
            != Some(user)
        {
            return Err(CallServiceError::NotFound);
        }
        self.livekit.create_room(id).await?;
        let mut group = CallGroup::new_with_service(
            id,
            self.owner_omikron_id,
            user,
            self.livekit.clone(),
            self.limits.clone(),
        );
        group.created_at_ms = created_at;
        let group = Arc::new(group);
        if !db
            .activate(&group, user)
            .map_err(|_| CallServiceError::DeliveryFailed)?
        {
            // A concurrent activation may already own this room. Rejection
            // must not delete a successfully committed call's external state.
            return Err(CallServiceError::NotFound);
        }
        // Persistence and local publication commit without an intervening await.
        // Metadata delivery cannot roll back an already activated call.
        self.groups.insert(id, group.clone());
        if let Err(error) = group.update_metadata().await {
            crate::log_err!(
                0,
                PrintType::Call,
                "Call metadata delivery failed after activation: {}",
                error
            );
        }
        self.get_call_token(user, id).await
    }
    pub async fn get_call(&self, id: Uuid) -> Option<Arc<CallGroup>> {
        self.groups.get(&id).map(|g| g.clone())
    }
    pub async fn get_call_groups(&self, user: u64) -> Vec<Arc<CallGroup>> {
        let groups = self.groups.iter().map(|g| g.clone()).collect::<Vec<_>>();
        let mut result = Vec::new();
        for g in groups {
            if g.created_at_ms + 259_200_000 > Self::timestamp() && g.is_related(user).await {
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
    pub fn timestamp() -> i64 {
        Self::now_ms().unwrap_or_default()
    }
    pub async fn get_call_token(&self, user: u64, id: Uuid) -> Result<String, CallServiceError> {
        let group = self.get_call(id).await.ok_or(CallServiceError::NotFound)?;
        if group.created_at_ms + 259_200_000 <= Self::now_ms()? {
            return Err(CallServiceError::NotFound);
        }
        if !group.is_related(user).await {
            return Err(CallServiceError::NotFound);
        }
        self.token_existing(group, user).await
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
                let token = self.livekit.create_token(user, g.call_id, false)?;
                let mut state = g.state.write().await;
                if state.ending || state.members.len() >= g.limits.max_members_per_call {
                    return Err(CallServiceError::NotFound);
                }
                let Some(invite) = state.pending_invites.get(&user) else {
                    return Err(CallServiceError::NotFound);
                };
                if invite.created_at_ms + g.limits.invite_ttl.as_millis() as i64 <= Self::now_ms()?
                {
                    return Err(CallServiceError::NotFound);
                }
                if let Some(db) = &self.persistence {
                    db.accept(g.call_id, user)
                        .map_err(|_| CallServiceError::DeliveryFailed)?;
                }
                state.pending_invites.remove(&user);
                state.members.insert(
                    user,
                    crate::calls::call_group::CallMember {
                        user_id: user,
                        role: CallRole::Member,
                        timeout_until_ms: None,
                        participating: false,
                    },
                );
                return Ok(token);
            }
        };
        if let Some(until) = member.timeout_until_ms
            && until > Self::now_ms()?
        {
            return Err(CallServiceError::TimedOut { until_ms: until });
        }
        self.livekit
            .create_token(user, g.call_id, member.role == CallRole::Admin)
            .map_err(Into::into)
    }
    pub async fn add_invite(&self, id: Uuid, from: u64, to: u64) -> Result<(), CallServiceError> {
        let (g, relation) = self.check_invite(id, from, to).await?;
        if relation == InviteRelation::Member {
            return Ok(());
        }
        let admission_lock = self
            .admission_locks
            .entry(to)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone();
        let result = {
            let _guard = admission_lock.lock().await;
            if relation == InviteRelation::New
                && self.get_call_groups(to).await.len() >= self.limits.max_calls_per_user
            {
                Err(CallServiceError::ResourceLimit)
            } else {
                g.invite_with_storage(from, to, self.persistence.as_deref())
                    .await?;
                Ok(())
            }
        };
        self.admission_locks.remove_if(&to, |_, current| {
            Arc::ptr_eq(current, &admission_lock) && Arc::strong_count(current) == 2
        });
        if result.is_ok() {
            log_event!(
                0,
                PrintType::Call,
                LogLevel::Info,
                "call.invited",
                "call_id={} from_user_id={} to_user_id={}",
                id,
                from,
                to
            );
        }
        result
    }
    pub async fn check_invite(
        &self,
        id: Uuid,
        from: u64,
        to: u64,
    ) -> Result<(Arc<CallGroup>, InviteRelation), CallServiceError> {
        let g = self.get_call(id).await.ok_or(CallServiceError::NotFound)?;
        if from == to || g.created_at_ms + 259_200_000 <= Self::now_ms()? {
            return Err(CallServiceError::InvalidRequest);
        }
        let state = g.state.read().await;
        let caller = state
            .members
            .get(&from)
            .ok_or(CallServiceError::NotAuthorized)?;
        if state.ending
            || caller
                .timeout_until_ms
                .is_some_and(|until| until > Self::timestamp())
        {
            return Err(CallServiceError::InvalidRequest);
        }
        let relation = if state.members.contains_key(&to) {
            InviteRelation::Member
        } else if state.pending_invites.get(&to).is_some_and(|invite| {
            invite.created_at_ms + self.limits.invite_ttl.as_millis() as i64 > Self::timestamp()
        }) {
            InviteRelation::Pending
        } else {
            InviteRelation::New
        };
        if relation == InviteRelation::New
            && state.pending_invites.len() >= self.limits.max_pending_invites_per_call
        {
            return Err(CallServiceError::ResourceLimit);
        }
        drop(state);
        if relation == InviteRelation::New
            && self.get_call_groups(to).await.len() >= self.limits.max_calls_per_user
        {
            return Err(CallServiceError::ResourceLimit);
        }
        Ok((g, relation))
    }
    pub async fn call_data(
        &self,
        id: Uuid,
        user: u64,
    ) -> Result<(Vec<u64>, i64), CallServiceError> {
        let g = self.get_call(id).await.ok_or(CallServiceError::NotFound)?;
        if g.created_at_ms + 259_200_000 <= Self::now_ms()? {
            return Err(CallServiceError::NotFound);
        }
        if !g.is_related(user).await {
            return Err(CallServiceError::NotFound);
        }
        Ok((g.member_ids().await, g.created_at_ms))
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
        {
            let mut state = g.state.write().await;
            let member = state
                .members
                .get_mut(&target)
                .ok_or(CallServiceError::InvalidUser)?;
            if let Some(db) = &self.persistence {
                db.set_timeout(id, target, until)
                    .map_err(|_| CallServiceError::DeliveryFailed)?;
            }
            member.timeout_until_ms = Some(until);
        }
        match self.livekit.remove_participant(id, target).await {
            Ok(()) | Err(CallError::RoomNotFound { .. }) => {}
            Err(error) => return Err(error.into()),
        }
        log_event!(
            0,
            PrintType::Call,
            LogLevel::Info,
            "call.user_timed_out",
            "call_id={} requester_user_id={} target_user_id={} until_ms={}",
            id,
            requester,
            target,
            until
        );
        Ok(())
    }
    pub async fn set_anonymous_joining(
        &self,
        id: Uuid,
        enabled: bool,
        omega: &crate::omega::omega_connection::OmegaConnection,
    ) -> Result<Option<String>, CallServiceError> {
        let group = self.get_call(id).await.ok_or(CallServiceError::NotFound)?;
        group
            .set_anonymous_joining(enabled, omega, self.persistence.as_deref())
            .await
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
        if requester == target {
            // Explicit leave ends the call only when nobody else is connected.
            let participants = match self.livekit.participant_ids(id).await {
                Ok(participants) => participants,
                Err(CallError::RoomNotFound { .. }) => Vec::new(),
                Err(error) => return Err(error.into()),
            };
            if participants
                .iter()
                .all(|participant| *participant == target)
            {
                self.delete_room(id).await?;
                let mut state = g.state.write().await;
                if let Some(db) = &self.persistence {
                    db.remove(id)
                        .map_err(|_| CallServiceError::DeliveryFailed)?;
                }
                state.ending = true;
                self.groups.remove(&id);
                return Ok(());
            }
            match self.livekit.remove_participant(id, target).await {
                Ok(()) | Err(CallError::RoomNotFound { .. }) => {}
                Err(error) => return Err(error.into()),
            }
            {
                let mut state = g.state.write().await;
                let member = state
                    .members
                    .get_mut(&target)
                    .ok_or(CallServiceError::InvalidUser)?;
                if let Some(db) = &self.persistence {
                    db.set_participating(id, target, false)
                        .map_err(|_| CallServiceError::DeliveryFailed)?;
                }
                member.participating = false;
            }
            if source.role == CallRole::Admin {
                let mut state = g.state.write().await;
                let Some(next_id) = state
                    .members
                    .keys()
                    .copied()
                    .find(|id| *id != target && participants.contains(id))
                    .or_else(|| state.members.keys().copied().find(|id| *id != target))
                else {
                    return Err(CallServiceError::InvalidRequest);
                };
                if let Some(db) = &self.persistence {
                    db.transfer_admin(id, target, next_id)
                        .map_err(|_| CallServiceError::DeliveryFailed)?;
                }
                state
                    .members
                    .get_mut(&target)
                    .ok_or(CallServiceError::InvalidUser)?
                    .role = CallRole::Member;
                state
                    .members
                    .get_mut(&next_id)
                    .ok_or(CallServiceError::InvalidUser)?
                    .role = CallRole::Admin;
            }
            g.update_metadata().await?;
            return Ok(());
        }
        // Kicking revokes future tokens as well as removing the participant.
        match self.livekit.remove_participant(id, target).await {
            Ok(()) | Err(CallError::RoomNotFound { .. }) => {}
            Err(error) => return Err(error.into()),
        }
        {
            let mut state = g.state.write().await;
            if !state.members.contains_key(&target) {
                return Err(CallServiceError::InvalidUser);
            }
            if let Some(db) = &self.persistence {
                db.revoke(id, target)
                    .map_err(|_| CallServiceError::DeliveryFailed)?;
            }
            state.members.remove(&target);
        }
        g.update_metadata().await?;
        Ok(())
    }
    pub async fn reconcile_participants(
        &self,
        id: Uuid,
        participants: &[u64],
    ) -> Result<(), CallServiceError> {
        let group = self.get_call(id).await.ok_or(CallServiceError::NotFound)?;
        let mut state = group.state.write().await;
        if state
            .members
            .values()
            .all(|member| member.participating == participants.contains(&member.user_id))
        {
            return Ok(());
        }
        if let Some(db) = &self.persistence {
            db.reconcile_participants(id, participants)
                .map_err(|_| CallServiceError::DeliveryFailed)?;
        }
        for member in state.members.values_mut() {
            member.participating = participants.contains(&member.user_id);
        }
        Ok(())
    }
    async fn delete_room(&self, id: Uuid) -> Result<(), CallServiceError> {
        match self.livekit.delete_room(id).await {
            Ok(()) | Err(CallError::RoomNotFound { .. }) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
    pub async fn end_call(&self, id: Uuid, requester: u64) -> Result<(), CallServiceError> {
        let g = self.get_call(id).await.ok_or(CallServiceError::NotFound)?;
        if g.member(requester).await.map(|m| m.role == CallRole::Admin) != Some(true) {
            return Err(CallServiceError::NotAuthorized);
        }
        self.delete_room(id).await?;
        let mut state = g.state.write().await;
        if let Some(db) = &self.persistence {
            db.remove(id)
                .map_err(|_| CallServiceError::DeliveryFailed)?;
        }
        state.ending = true;
        self.groups.remove(&id);
        log_event!(
            0,
            PrintType::Call,
            LogLevel::Info,
            "call.ended",
            "call_id={} requester_user_id={}",
            id,
            requester
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn missing_call_is_not_found_even_with_a_token_request() {
        assert!(matches!(
            CallManager::default()
                .get_call_token(1, Uuid::new_v4())
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
            manager.livekit.clone(),
            CallLimits::default(),
        ));
        manager.groups.insert(id, group.clone());
        manager.add_invite(id, 1, 2).await.unwrap();
        assert!(group.member(2).await.is_none());
        let _ = manager.get_call_token(2, id).await;
        assert!(group.member(2).await.is_some());
    }
    #[tokio::test]
    async fn concurrent_invites_share_user_quota() {
        let limits = CallLimits {
            max_calls_per_user: 1,
            ..CallLimits::default()
        };
        let manager = Arc::new(CallManager::new_with_limits(
            Arc::new(LiveKitService::new(None)),
            1,
            limits.clone(),
        ));
        let mut ids = Vec::new();
        for owner in [1, 2] {
            let id = Uuid::new_v4();
            manager.groups.insert(
                id,
                Arc::new(CallGroup::new_with_service(
                    id,
                    1,
                    owner,
                    manager.livekit.clone(),
                    limits.clone(),
                )),
            );
            ids.push((id, owner));
        }
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let mut tasks = Vec::new();
        for (id, owner) in ids {
            let manager = manager.clone();
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                manager.add_invite(id, owner, 42).await
            }));
        }
        let first = tasks.remove(0).await.unwrap();
        let second = tasks.remove(0).await.unwrap();
        assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
        assert!(manager.admission_locks.is_empty());
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
                manager.livekit.clone(),
                CallLimits::default(),
            )),
        );
        assert!(matches!(
            manager.add_invite(id, 1, 1).await,
            Err(CallServiceError::InvalidRequest)
        ));
    }
    #[tokio::test]
    async fn reinviting_a_member_or_lapsed_participant_succeeds() {
        let manager = Arc::new(CallManager::new_with_owner(
            Arc::new(LiveKitService::new(Some(crate::config::LiveKitConfig {
                hostname: "https://livekit.invalid".into(),
                client_url: "wss://livekit.invalid".into(),
                api_key: "key".into(),
                api_secret: "secret".into(),
            }))),
            1,
        ));
        let id = Uuid::new_v4();
        let group = Arc::new(CallGroup::new_with_service(
            id,
            1,
            1,
            manager.livekit.clone(),
            CallLimits::default(),
        ));
        manager.groups.insert(id, group.clone());
        // First invite creates a pending invite.
        manager.add_invite(id, 1, 2).await.unwrap();
        // A repeat invite while pending stays idempotent.
        manager.add_invite(id, 1, 2).await.unwrap();
        assert!(group.member(2).await.is_none());
        // The invitee joins and becomes a member.
        let _ = manager.get_call_token(2, id).await;
        assert!(group.member(2).await.is_some());
        // Re-inviting a connected member succeeds (it is a nudge, not an error).
        manager.add_invite(id, 1, 2).await.unwrap();
        assert!(group.member(2).await.is_some());
        // The member leaves; membership is retained so they can rejoin.
        group.revoke(2).await;
        assert!(group.member(2).await.is_none());
        // And a re-invite after leaving also succeeds, restoring the invite.
        manager.add_invite(id, 1, 2).await.unwrap();
        assert!(group.member(2).await.is_none());
        assert!(group.is_related(2).await);
    }
}
