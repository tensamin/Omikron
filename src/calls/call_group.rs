use crate::{
    calls::{call_util::LiveKitService, caller::Caller, error::CallError},
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
    pub state: RwLock<CallGroupState>,
    livekit: Arc<LiveKitService>,
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
    pub secret: Option<CallSecretEnvelope>,
}
#[derive(Clone)]
pub struct PendingCallInvite {
    pub inviter_id: u64,
    pub secret: CallSecretEnvelope,
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
        Some(Self {
            secret_id: v
                .get_field(data_type_id(DataType::SecretId, &t))?
                .as_str()?
                .to_string(),
            version_number: v
                .get_field(data_type_id(DataType::VersionNumber, &t))?
                .as_number()
                .and_then(|n| i64::try_from(n).ok())?,
            encrypted_secret: v
                .get_field(data_type_id(DataType::EncryptedSecret, &t))?
                .as_bytes()?,
            kem_ciphertext: v
                .get_field(data_type_id(DataType::KemCiphertext, &t))?
                .as_bytes()?,
            wrapping_scheme: v
                .get_field(data_type_id(DataType::WrappingScheme, &t))?
                .as_str()?
                .to_string(),
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
        secret: CallSecretEnvelope,
        livekit: Arc<LiveKitService>,
    ) -> Self {
        let mut members = BTreeMap::new();
        members.insert(
            creator,
            CallMember {
                user_id: creator,
                role: CallRole::Admin,
                timeout_until_ms: None,
                secret: Some(secret),
            },
        );
        Self {
            call_id: id,
            owner_omikron_id: owner,
            state: RwLock::new(CallGroupState {
                members,
                pending_invites: BTreeMap::new(),
                anonymous_joining: false,
                short_link: None,
                ending: false,
            }),
            livekit,
        }
    }
    pub async fn member(&self, id: u64) -> Option<CallMember> {
        self.state.read().await.members.get(&id).cloned()
    }
    pub async fn is_related(&self, id: u64) -> bool {
        let s = self.state.read().await;
        s.members.contains_key(&id) || s.pending_invites.contains_key(&id)
    }
    pub async fn member_ids(&self) -> Vec<u64> {
        self.state.read().await.members.keys().copied().collect()
    }
    pub async fn get_secret_for_user(&self, id: u64) -> Option<CallSecretEnvelope> {
        let s = self.state.read().await;
        s.members
            .get(&id)
            .and_then(|m| m.secret.clone())
            .or_else(|| s.pending_invites.get(&id).map(|i| i.secret.clone()))
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
            log::warn!("unable to remove call participant: {error}");
        }
    }
    pub async fn get_short_link(&self) -> Option<String> {
        self.state.read().await.short_link.clone()
    }
    pub async fn invite(&self, from: u64, to: u64, secret: CallSecretEnvelope) -> Result<(), ()> {
        let mut s = self.state.write().await;
        if s.ending || !s.members.contains_key(&from) || from == to {
            return Err(());
        }
        s.pending_invites.insert(
            to,
            PendingCallInvite {
                inviter_id: from,
                secret,
            },
        );
        Ok(())
    }
    pub async fn rollback_invite(&self, id: u64) {
        self.state.write().await.pending_invites.remove(&id);
    }
    pub async fn accept_invite(&self, id: u64) -> Option<CallMember> {
        let mut s = self.state.write().await;
        let i = s.pending_invites.remove(&id)?;
        let m = CallMember {
            user_id: id,
            role: CallRole::Member,
            timeout_until_ms: None,
            secret: Some(i.secret),
        };
        s.members.insert(id, m.clone());
        Some(m)
    }
    pub async fn revoke(&self, id: u64) -> Option<CallMember> {
        self.state.write().await.members.remove(&id)
    }
    pub async fn timeout(&self, id: u64, until: i64) -> Result<(), ()> {
        let mut s = self.state.write().await;
        s.members.get_mut(&id).ok_or(())?.timeout_until_ms = Some(until);
        Ok(())
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
        {
            self.state.write().await.anonymous_joining = enable;
        }
        self.update_metadata().await?;
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
