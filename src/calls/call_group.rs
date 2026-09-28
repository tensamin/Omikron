use crate::{
    calls::call_manager::CallServiceError,
    calls::{call_util::LiveKitService, caller::Caller, error::CallError},
    config::CallLimits,
    omega::omega_connection::OmegaConnection,
    rho::connection::OptionalDataValueCompat,
    util::data_type_id,
};
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue, TypeMap};
use serde::Serialize;
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use tokio::sync::RwLock;
use uuid::Uuid;

pub struct CallGroup {
    pub call_id: Uuid,
    pub owner_omikron_id: u64,
    pub created_at_ms: i64,
    pub state: RwLock<CallGroupState>,
    pub(crate) livekit: Arc<LiveKitService>,
    pub(crate) limits: CallLimits,
}
pub struct CallGroupState {
    pub members: BTreeMap<u64, CallMember>,
    pub pending_invites: BTreeMap<u64, PendingCallInvite>,
    pub anonymous_joining: bool,
    pub short_link: Option<String>,
    pub ending: bool,
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
#[derive(Clone, Debug, Eq, PartialEq)]
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
#[derive(Serialize)]
struct CallRoomMetadata {
    owner_omikron_id: u64,
    admins: Vec<u64>,
    anonymous_joining: bool,
}
impl CallGroup {
    pub fn new_with_service(
        id: Uuid,
        owner: u64,
        creator: u64,
        livekit: Arc<LiveKitService>,
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
                short_link: None,
                ending: false,
            }),
            livekit,
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
    pub async fn get_caller(&self, id: u64) -> Option<Caller> {
        let m = self.member(id).await?;
        let caller = Caller::new(id, self.call_id, m.role == CallRole::Admin);
        if let Some(until) = m.timeout_until_ms {
            caller.set_timeout(until).await;
        }
        Some(caller)
    }
    pub async fn remove_caller(&self, id: u64) {
        self.revoke(id).await;
        if let Err(error) = self.livekit.remove_participant(self.call_id, id).await {
            crate::log_event!(
                0,
                crate::util::logger::PrintType::Call,
                crate::util::logger::LogLevel::Warn,
                "call.participant_remove_failed",
                "call_id={} user_id={} error={}",
                self.call_id,
                id,
                error
            );
        }
    }
    pub async fn get_short_link(&self) -> Option<String> {
        self.state.read().await.short_link.clone()
    }
    pub async fn invite(&self, from: u64, to: u64) -> Result<(), CallServiceError> {
        self.invite_with_storage(from, to, None).await
    }
    pub async fn invite_with_storage(
        &self,
        from: u64,
        to: u64,
        persistence: Option<&crate::calls::persistence::CallPersistence>,
    ) -> Result<(), CallServiceError> {
        let mut state = self.state.write().await;
        let now = now_ms();
        state.pending_invites.retain(|_, invite| {
            invite.created_at_ms + self.limits.invite_ttl.as_millis() as i64 > now
        });
        if state.ending
            || !state
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
        if let Some(db) = persistence {
            db.store_invite(self.call_id, to, from, now)
                .map_err(|_| CallServiceError::DeliveryFailed)?;
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
    pub async fn accept_invite(&self, id: u64) -> Result<CallMember, CallServiceError> {
        let mut s = self.state.write().await;
        s.pending_invites.retain(|_, invite| {
            invite.created_at_ms + self.limits.invite_ttl.as_millis() as i64 > now_ms()
        });
        if s.ending {
            return Err(CallServiceError::InvalidRequest);
        }
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
    pub async fn revoke(&self, id: u64) -> Option<CallMember> {
        self.state.write().await.members.remove(&id)
    }
    pub async fn is_anonymous(&self) -> bool {
        self.state.read().await.anonymous_joining
    }
    pub async fn update_metadata(&self) -> Result<(), CallError> {
        let s = self.state.read().await;
        let metadata = CallRoomMetadata {
            owner_omikron_id: self.owner_omikron_id,
            admins: s
                .members
                .values()
                .filter(|m| m.role == CallRole::Admin)
                .map(|m| m.user_id)
                .collect(),
            anonymous_joining: s.anonymous_joining,
        };
        let value =
            serde_json::to_string(&metadata).map_err(|e| CallError::MetadataUpdateFailed {
                call_id: self.call_id,
                detail: e.to_string(),
            })?;
        self.livekit.set_room_metadata(self.call_id, value).await
    }
    pub async fn set_anonymous_joining(
        &self,
        enable: bool,
        omega: &OmegaConnection,
    ) -> Result<Option<String>, CallError> {
        let previous = {
            let mut state = self.state.write().await;
            let previous = state.anonymous_joining;
            state.anonymous_joining = enable;
            previous
        };
        if let Err(error) = self.update_metadata().await {
            self.state.write().await.anonymous_joining = previous;
            return Err(error);
        }
        if !enable {
            return Ok(None);
        }
        if let Some(link) = self.state.read().await.short_link.clone() {
            return Ok(Some(link));
        }
        let link = format!(
            "https://app.tensamin.net/call/anonymous?call_id={}&omikron_id={}",
            self.call_id, self.owner_omikron_id
        );
        if let Ok(r) = omega
            .await_response(
                &CommunicationValue::new(CommunicationType::ShortenLink)
                    .add_typed_default(DataType::Link, DataValue::Str(link)),
                Some(Duration::from_secs(20)),
            )
            .await
        {
            if let Some(link) = r.get_data(DataType::Link).as_str() {
                let link = link.to_string();
                self.state.write().await.short_link = Some(link.clone());
                return Ok(Some(link));
            }
        }
        Ok(None)
    }
    pub async fn create_anonymous_token(&self, user: u64) -> Result<Option<String>, CallError> {
        if self.is_anonymous().await {
            self.livekit
                .create_token(user, self.call_id, false)
                .map(Some)
        } else {
            Ok(None)
        }
    }
    pub async fn mark_ending(&self) {
        self.state.write().await.ending = true;
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
            invite_ttl: Duration::from_millis(1),
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
        tokio::time::sleep(Duration::from_millis(5)).await;
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
