#[cfg(test)]
use crate::calls::call_manager::CallServiceError;
use crate::{
    calls::{call_util::LiveKitService, error::CallError},
    config::CallLimits,
    util::data_type_id,
};
use mtp::codec::{CommunicationValue, DataType, DataValue, TypeMap};
use serde::{Deserialize, Serialize};
#[cfg(test)]
use std::time::Duration;
use std::{collections::BTreeMap, sync::Arc};
use tokio::sync::RwLock;
use uuid::Uuid;

pub struct CallGroup {
    pub call_id: Uuid,
    pub owner_omikron_id: u64,
    pub created_at_ms: i64,
    pub state: RwLock<CallGroupState>,
    pub(crate) limits: CallLimits,
}
pub struct CallGroupState {
    pub members: BTreeMap<u64, CallMember>,
    pub pending_invites: BTreeMap<u64, PendingCallInvite>,
    pub anonymous_joining: bool,
}
#[derive(Clone)]
pub struct CallMember {
    pub user_id: u64,
    pub role: CallRole,
    pub timeout_until_ms: Option<i64>,
    pub participating: bool,
}
#[derive(Clone)]
pub struct PendingCallInvite {
    pub inviter_id: u64,
    pub created_at_ms: i64,
}
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum CallRole {
    Admin,
    Member,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CallSecretEnvelope {
    pub secret_id: String,
    pub version_number: i64,
    pub encrypted_secret: Vec<u8>,
    pub kem_ciphertext: Vec<u8>,
    pub wrapping_scheme: String,
}
impl CallSecretEnvelope {
    pub fn from_data_value(v: &DataValue) -> Option<Self> {
        let t = TypeMap::latest();
        let secret_id = v
            .get_field(data_type_id(DataType::SecretId, &t))?
            .as_str()?;
        let encrypted_secret = v
            .get_field(data_type_id(DataType::EncryptedSecret, &t))?
            .as_bytes()?;
        let kem_ciphertext = v
            .get_field(data_type_id(DataType::KemCiphertext, &t))?
            .as_bytes()?;
        let wrapping_scheme = v
            .get_field(data_type_id(DataType::WrappingScheme, &t))?
            .as_str()?;
        if secret_id.is_empty()
            || secret_id.len() > 256
            || encrypted_secret.len() > 44 + 24 + 16
            || kem_ciphertext.len() > mtp::crypto::HybridKem::ciphertext_len()
            || wrapping_scheme.len() > "mtp-call-secret-kem-chacha20poly1305-hkdf-sha256-v1".len()
        {
            return None;
        }
        Some(Self {
            secret_id: secret_id.to_string(),
            version_number: v
                .get_field(data_type_id(DataType::VersionNumber, &t))?
                .as_number()
                .and_then(|n| i64::try_from(n).ok())?,
            encrypted_secret,
            kem_ciphertext,
            wrapping_scheme: wrapping_scheme.to_string(),
        })
    }
    pub fn to_data_value(&self) -> DataValue {
        let t = TypeMap::latest();
        let mut m = BTreeMap::new();
        m.insert(
            data_type_id(DataType::SecretId, &t),
            DataValue::Str(self.secret_id.clone()),
        );
        m.insert(
            data_type_id(DataType::VersionNumber, &t),
            DataValue::SignedNumber(self.version_number.into()),
        );
        m.insert(
            data_type_id(DataType::EncryptedSecret, &t),
            DataValue::Bytes(self.encrypted_secret.clone()),
        );
        m.insert(
            data_type_id(DataType::KemCiphertext, &t),
            DataValue::Bytes(self.kem_ciphertext.clone()),
        );
        m.insert(
            data_type_id(DataType::WrappingScheme, &t),
            DataValue::Str(self.wrapping_scheme.clone()),
        );
        DataValue::container_from_map(&m)
    }
}
fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or_default()
}
pub fn call_invite_secret_from_cv(cv: &CommunicationValue) -> Option<CallSecretEnvelope> {
    CallSecretEnvelope::from_data_value(cv.get_data(DataType::CallSecret)?)
}
impl CallGroup {
    pub fn new_with_service(
        id: Uuid,
        owner: u64,
        creator: u64,
        _livekit: Arc<LiveKitService>,
        limits: CallLimits,
    ) -> Self {
        let mut members = BTreeMap::new();
        members.insert(
            creator,
            CallMember {
                user_id: creator,
                role: CallRole::Admin,
                timeout_until_ms: None,
                participating: false,
            },
        );
        Self {
            call_id: id,
            owner_omikron_id: owner,
            created_at_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_millis() as i64)
                .unwrap_or_default(),
            state: RwLock::new(CallGroupState {
                members,
                pending_invites: BTreeMap::new(),
                anonymous_joining: false,
            }),
            limits,
        }
    }
    pub async fn member(&self, id: u64) -> Option<CallMember> {
        self.state.read().await.members.get(&id).cloned()
    }
    pub async fn is_related(&self, id: u64) -> bool {
        let s = self.state.read().await;
        s.members.contains_key(&id)
            || s.pending_invites.get(&id).is_some_and(|invite| {
                invite.created_at_ms + self.limits.invite_ttl.as_millis() as i64 > now_ms()
            })
    }
    pub async fn member_ids(&self) -> Vec<u64> {
        self.state.read().await.members.keys().copied().collect()
    }
    #[cfg(test)]
    pub async fn invite(&self, from: u64, to: u64) -> Result<(), CallServiceError> {
        let mut state = self.state.write().await;
        let now = now_ms();
        state.pending_invites.retain(|_, invite| {
            invite.created_at_ms + self.limits.invite_ttl.as_millis() as i64 > now
        });
        if !state
            .members
            .get(&from)
            .is_some_and(|member| member.timeout_until_ms.is_none_or(|until| until <= now))
            || from == to
            || state.members.contains_key(&to)
        {
            return Err(CallServiceError::InvalidRequest);
        }
        if !state.pending_invites.contains_key(&to)
            && state.pending_invites.len() >= self.limits.max_pending_invites_per_call
        {
            return Err(CallServiceError::ResourceLimit);
        }
        state.pending_invites.insert(
            to,
            PendingCallInvite {
                inviter_id: from,
                created_at_ms: now,
            },
        );
        Ok(())
    }
    #[cfg(test)]
    pub async fn accept_invite(&self, id: u64) -> Result<CallMember, CallServiceError> {
        let mut s = self.state.write().await;
        s.pending_invites.retain(|_, invite| {
            invite.created_at_ms + self.limits.invite_ttl.as_millis() as i64 > now_ms()
        });
        if s.members.len() >= self.limits.max_members_per_call {
            return Err(CallServiceError::ResourceLimit);
        }
        s.pending_invites
            .remove(&id)
            .ok_or(CallServiceError::NotAuthorized)?;
        let m = CallMember {
            user_id: id,
            role: CallRole::Member,
            timeout_until_ms: None,
            participating: false,
        };
        s.members.insert(id, m.clone());
        Ok(m)
    }
    pub async fn is_anonymous(&self) -> bool {
        self.state.read().await.anonymous_joining
    }
    pub async fn create_anonymous_token(&self, _user: u64) -> Result<Option<String>, CallError> {
        // Legacy random numeric guest IDs are not authenticated call principals.
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn expired_invite_cannot_join_or_expose_secret() {
        let limits = CallLimits {
            max_members_per_call: 2,
            max_pending_invites_per_call: 1,
            max_calls_per_user: 1,
            invite_ttl: Duration::from_secs(60),
            ..CallLimits::default()
        };
        let group = CallGroup::new_with_service(
            Uuid::new_v4(),
            1,
            1,
            Arc::new(LiveKitService::new(None)),
            limits,
        );
        group.invite(1, 2).await.unwrap();
        assert!(matches!(
            group.invite(1, 3).await,
            Err(CallServiceError::ResourceLimit)
        ));
        group
            .state
            .write()
            .await
            .pending_invites
            .get_mut(&2)
            .unwrap()
            .created_at_ms = now_ms() - 60_001;
        assert!(!group.is_related(2).await);
        assert!(matches!(
            group.accept_invite(2).await,
            Err(CallServiceError::NotAuthorized)
        ));
        group.invite(1, 3).await.unwrap();
    }

    #[test]
    fn parses_creator_secret_with_unsigned_version_number() {
        let type_map = TypeMap::latest();
        let mut fields = BTreeMap::new();
        fields.insert(
            data_type_id(DataType::SecretId, &type_map),
            DataValue::Str("call:test:main".into()),
        );
        fields.insert(
            data_type_id(DataType::VersionNumber, &type_map),
            DataValue::UnsignedNumber(1),
        );
        fields.insert(
            data_type_id(DataType::EncryptedSecret, &type_map),
            DataValue::Bytes(vec![1]),
        );
        fields.insert(
            data_type_id(DataType::KemCiphertext, &type_map),
            DataValue::Bytes(vec![2]),
        );
        fields.insert(
            data_type_id(DataType::WrappingScheme, &type_map),
            DataValue::Str("test".into()),
        );

        let parsed = CallSecretEnvelope::from_data_value(&DataValue::container_from_map(&fields));

        assert_eq!(parsed.map(|secret| secret.version_number), Some(1));
    }
}
