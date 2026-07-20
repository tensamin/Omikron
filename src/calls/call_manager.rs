use dashmap::DashMap;
use std::sync::Arc;
use uuid::Uuid;

use crate::calls::{
    call_group::{CallGroup, CallSecretEnvelope},
    call_util::LiveKitService,
    caller::Caller,
    error::CallError,
};

pub struct CallManager {
    pub(crate) groups: DashMap<Uuid, Arc<CallGroup>>,
    pub livekit: Arc<LiveKitService>,
}

impl Default for CallManager {
    fn default() -> Self {
        Self {
            groups: DashMap::new(),
            livekit: Arc::new(LiveKitService::new(None)),
        }
    }
}

impl CallManager {
    pub fn new(livekit: Arc<LiveKitService>) -> Self {
        Self {
            groups: DashMap::new(),
            livekit,
        }
    }

    #[allow(dead_code)]
    pub async fn get_call_invites(&self, user_id: u64) -> Vec<Arc<Caller>> {
        let mut callers = Vec::new();
        let call_groups = self
            .groups
            .iter()
            .map(|entry| entry.value().clone())
            .collect::<Vec<_>>();
        for cg in call_groups {
            let members = cg.members.read().await;
            for member in members.iter() {
                if member.user_id == user_id {
                    callers.push(member.clone());
                }
            }
        }
        callers
    }

    pub async fn get_call(&self, call_id: Uuid) -> Option<Arc<CallGroup>> {
        if let Some(b) = self.groups.get(&call_id) {
            Some(b.clone())
        } else {
            None
        }
    }

    pub async fn get_call_groups(&self, user_id: u64) -> Vec<Arc<CallGroup>> {
        let mut call_groups = Vec::new();
        let tracked_groups = self
            .groups
            .iter()
            .map(|entry| entry.value().clone())
            .collect::<Vec<_>>();
        for cg in tracked_groups {
            let is_member = {
                let members = cg.members.read().await;
                members.iter().any(|m| m.user_id == user_id)
            };

            if is_member {
                call_groups.push(cg.clone());
            }
        }
        call_groups
    }

    pub async fn get_call_token(&self, user_id: u64, call_id: Uuid) -> Result<String, CallError> {
        if let Some(cg) = self.groups.get(&call_id) {
            let mut members = cg.members.write().await;

            if let Some(member) = members.iter().find(|m| m.user_id == user_id) {
                return self.livekit.create_token(
                    member.user_id,
                    member.call_id,
                    member.has_admin(),
                );
            }

            let new_caller = Arc::new(Caller::new(user_id, call_id, false));
            let token = self.livekit.create_token(
                new_caller.user_id,
                new_caller.call_id,
                new_caller.has_admin(),
            )?;

            members.push(new_caller);

            return Ok(token);
        }

        let caller = Arc::new(Caller::new(user_id, call_id, true));
        let call_group = Arc::new(CallGroup::new_with_service(
            call_id,
            caller.clone(),
            self.livekit.clone(),
        ));

        self.livekit.create_room(call_id).await?;
        self.groups.insert(call_id, call_group.clone());
        call_group.update_admins().await;

        self.livekit
            .create_token(caller.user_id, caller.call_id, caller.has_admin())
    }

    pub async fn add_invite(
        &self,
        call_id: Uuid,
        inviter_id: u64,
        invitee_id: u64,
        secret: CallSecretEnvelope,
    ) -> bool {
        if let Some(cg) = self.groups.get(&call_id) {
            let mut members = cg.members.write().await;

            let is_inviter_member = members.iter().any(|m| m.user_id == inviter_id);

            if is_inviter_member {
                if !members.iter().any(|m| m.user_id == invitee_id) {
                    members.push(Arc::new(Caller::new(invitee_id, call_id, false)));
                }

                let mut secrets = cg.secrets.write().await;
                secrets.insert(invitee_id, secret);

                return true;
            }
        }
        false
    }

    pub fn should_forward_invite(&self, inviter_id: u64, invitee_id: u64) -> bool {
        inviter_id != invitee_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(label: &str) -> CallSecretEnvelope {
        CallSecretEnvelope {
            secret_id: format!("call:test:{label}"),
            version_number: 1,
            encrypted_secret: format!("encrypted:{label}").into_bytes(),
            kem_ciphertext: format!("kem:{label}").into_bytes(),
            wrapping_scheme: "mtp-call-secret-kem-chacha20poly1305-hkdf-sha256-v1".to_string(),
        }
    }

    #[tokio::test]
    async fn add_invite_stores_receiver_envelope_only_under_receiver_id() {
        let call_id = Uuid::new_v4();
        let sender_id = 11;
        let receiver_id = 22;
        let group = Arc::new(CallGroup::new(
            call_id,
            Arc::new(Caller::new(sender_id, call_id, true)),
        ));
        let manager = CallManager::default();
        manager.groups.insert(call_id, group.clone());

        let receiver_secret = envelope("receiver");

        assert!(
            manager
                .add_invite(call_id, sender_id, receiver_id, receiver_secret.clone(),)
                .await
        );

        assert_eq!(
            group.get_secret_for_user(receiver_id).await,
            Some(receiver_secret.clone())
        );
        assert_eq!(group.get_secret_for_user(sender_id).await, None);
    }

    #[tokio::test]
    async fn self_invite_stores_secret_without_duplicating_member() {
        let call_id = Uuid::new_v4();
        let sender_id = 33;
        let group = Arc::new(CallGroup::new(
            call_id,
            Arc::new(Caller::new(sender_id, call_id, true)),
        ));
        let manager = CallManager::default();
        manager.groups.insert(call_id, group.clone());

        let secret = envelope("self");

        assert!(
            manager
                .add_invite(call_id, sender_id, sender_id, secret.clone())
                .await
        );

        assert_eq!(group.get_secret_for_user(sender_id).await, Some(secret));
        assert_eq!(
            group
                .members
                .read()
                .await
                .iter()
                .filter(|member| member.user_id == sender_id)
                .count(),
            1
        );
    }

    #[test]
    fn self_invites_are_not_forwarded() {
        let manager = CallManager::default();
        assert!(!manager.should_forward_invite(44, 44));
        assert!(manager.should_forward_invite(44, 55));
    }
}
