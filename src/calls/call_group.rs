use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataTypeId, DataValue, TypeMap};
use serde_json::Map;

use std::{collections::BTreeMap, sync::Arc, time::Duration};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::{
    calls::{call_util::LiveKitService, caller::Caller, error::CallError},
    omega::omega_connection::OmegaConnection,
    rho::connection::OptionalDataValueCompat,
    util::data_type_id,
};

pub struct CallGroup {
    pub call_id: Uuid,
    pub members: RwLock<Vec<Arc<Caller>>>,
    #[allow(dead_code)]
    pub show: RwLock<bool>,
    pub anonymous_joining: RwLock<bool>,
    pub short_link: RwLock<Option<String>>,
    pub secrets: RwLock<BTreeMap<u64, CallSecretEnvelope>>,
    livekit: Arc<LiveKitService>,
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
    pub fn from_data_value(value: &DataValue) -> Option<Self> {
        let tm = TypeMap::latest();
        let secret_id = value
            .get_field(data_type_id(DataType::SecretId, &tm))?
            .as_str()?
            .to_string();
        let version_number = value
            .get_field(data_type_id(DataType::VersionNumber, &tm))?
            .as_signed_number()
            .and_then(|n| i64::try_from(n).ok())
            .or_else(|| {
                value
                    .get_field(data_type_id(DataType::VersionNumber, &tm))?
                    .as_number()
                    .and_then(|n| i64::try_from(n).ok())
            })?;
        let encrypted_secret = value
            .get_field(data_type_id(DataType::EncryptedSecret, &tm))?
            .as_bytes()?;
        let kem_ciphertext = value
            .get_field(data_type_id(DataType::KemCiphertext, &tm))?
            .as_bytes()?;
        let wrapping_scheme = value
            .get_field(data_type_id(DataType::WrappingScheme, &tm))?
            .as_str()?
            .to_string();

        Some(Self {
            secret_id,
            version_number,
            encrypted_secret,
            kem_ciphertext,
            wrapping_scheme,
        })
    }

    pub fn to_data_value(&self) -> DataValue {
        let tm = TypeMap::latest();
        let mut map: BTreeMap<DataTypeId, DataValue> = BTreeMap::new();
        map.insert(
            data_type_id(DataType::SecretId, &tm),
            DataValue::Str(self.secret_id.clone()),
        );
        map.insert(
            data_type_id(DataType::VersionNumber, &tm),
            DataValue::SignedNumber(self.version_number.into()),
        );
        map.insert(
            data_type_id(DataType::EncryptedSecret, &tm),
            DataValue::Bytes(self.encrypted_secret.clone()),
        );
        map.insert(
            data_type_id(DataType::KemCiphertext, &tm),
            DataValue::Bytes(self.kem_ciphertext.clone()),
        );
        map.insert(
            data_type_id(DataType::WrappingScheme, &tm),
            DataValue::Str(self.wrapping_scheme.clone()),
        );
        DataValue::container_from_map(&map)
    }
}

pub fn call_invite_secret_from_cv(cv: &CommunicationValue) -> Option<CallSecretEnvelope> {
    CallSecretEnvelope::from_data_value(cv.get_data(DataType::CallSecret)?)
}

impl CallGroup {
    #[allow(dead_code)]
    pub fn new(call_id: Uuid, user: Arc<Caller>) -> Self {
        Self::new_with_service(call_id, user, Arc::new(LiveKitService::new(None)))
    }

    pub fn new_with_service(
        call_id: Uuid,
        user: Arc<Caller>,
        livekit: Arc<LiveKitService>,
    ) -> Self {
        CallGroup {
            call_id,
            members: RwLock::new(vec![user]),
            show: RwLock::new(true),
            anonymous_joining: RwLock::new(false),
            short_link: RwLock::new(None),
            secrets: RwLock::new(BTreeMap::new()),
            livekit,
        }
    }

    pub async fn get_caller(&self, user_id: u64) -> Option<Arc<Caller>> {
        self.members
            .read()
            .await
            .iter()
            .find(|caller| caller.user_id == user_id)
            .cloned()
    }

    pub async fn get_secret_for_user(&self, user_id: u64) -> Option<CallSecretEnvelope> {
        self.secrets.read().await.get(&user_id).cloned()
    }

    pub async fn is_anonymous(&self) -> bool {
        *self.anonymous_joining.read().await
    }

    pub async fn update_admins(&self) {
        let call_metadata = match self.livekit.get_room_metadata(self.call_id).await {
            Ok(metadata) => metadata,
            Err(_) => "{}".to_string(),
        };
        let call_metadata: serde_json::Value = match serde_json::from_str(&call_metadata) {
            Ok(json) => json,
            Err(_) => serde_json::Value::Object(Map::new()),
        };
        let mut call_metadata = match call_metadata.as_object() {
            Some(metadata) => metadata.clone(),
            None => Map::new(),
        };

        let admin_ids = self
            .members
            .read()
            .await
            .iter()
            .filter(|member| member.has_admin)
            .map(|admin| admin.user_id)
            .collect::<Vec<_>>();

        call_metadata.insert("admins".to_string(), serde_json::json!(admin_ids));

        if let Err(error) = self
            .livekit
            .set_room_metadata(
                self.call_id,
                serde_json::Value::Object(call_metadata).to_string(),
            )
            .await
        {
            log::warn!(
                "Unable to update administrators for call {}: {}",
                self.call_id,
                error
            );
        }
    }

    pub async fn set_anonymous_joining(
        &self,
        enable: bool,
        omega: &OmegaConnection,
        omikron_id: u64,
    ) {
        *self.anonymous_joining.write().await = enable;

        let call_metadata = match self.livekit.get_room_metadata(self.call_id).await {
            Ok(metadata) => metadata,
            Err(_) => "{}".to_string(),
        };
        let call_metadata: serde_json::Value = match serde_json::from_str(&call_metadata) {
            Ok(json) => json,
            Err(_) => serde_json::Value::Object(Map::new()),
        };
        let mut call_metadata = match call_metadata.as_object() {
            Some(metadata) => metadata.clone(),
            None => Map::new(),
        };

        call_metadata.insert("anonymous_joining".to_string(), serde_json::json!(enable));

        if let Err(error) = self
            .livekit
            .set_room_metadata(
                self.call_id,
                serde_json::Value::Object(call_metadata).to_string(),
            )
            .await
        {
            log::warn!(
                "Unable to update anonymous access for call {}: {}",
                self.call_id,
                error
            );
        }

        if self.short_link.read().await.is_none() {
            let long_link = format!(
                "https://app.tensamin.net/call/anonymous?call_id={}&omikron_id={}",
                self.call_id, omikron_id,
            );
            let response_cv = omega
                .await_response(
                    &CommunicationValue::new(CommunicationType::ShortenLink)
                        .add_typed_default(DataType::Link, DataValue::Str(long_link)),
                    Some(Duration::from_secs(20)),
                )
                .await;
            if let Ok(response) = response_cv {
                if let Some(link) = response.get_data(DataType::Link).as_str() {
                    *self.short_link.write().await = Some(link.to_string());
                    log::info!("Shortened link for call {}", self.call_id);
                }
            }
        }
    }

    pub async fn create_anonymous_token(&self, user_id: u64) -> Result<Option<String>, CallError> {
        if self.is_anonymous().await {
            return self
                .livekit
                .create_token(user_id, self.call_id, false)
                .map(Some);
        }
        Ok(None)
    }

    pub async fn remove_caller(&self, user_id: u64) {
        if let Err(error) = self.livekit.remove_participant(self.call_id, user_id).await {
            log::warn!(
                "Unable to remove user {} from call {}: {}",
                user_id,
                self.call_id,
                error
            );
        }
        self.members
            .write()
            .await
            .retain(|caller| caller.user_id != user_id);
    }

    pub async fn get_short_link(self: Arc<Self>) -> Option<String> {
        self.short_link.read().await.clone()
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

    #[test]
    fn call_secret_plain_string_is_rejected() {
        assert!(
            CallSecretEnvelope::from_data_value(&DataValue::Str("old-secret".to_string()))
                .is_none()
        );
    }

    #[test]
    fn call_secret_missing_required_field_is_rejected() {
        let tm = TypeMap::latest();
        let mut map: BTreeMap<DataTypeId, DataValue> = BTreeMap::new();
        map.insert(
            data_type_id(DataType::SecretId, &tm),
            DataValue::Str("call:test:main".to_string()),
        );
        map.insert(
            data_type_id(DataType::VersionNumber, &tm),
            DataValue::SignedNumber(1),
        );
        map.insert(
            data_type_id(DataType::EncryptedSecret, &tm),
            DataValue::Bytes(vec![1, 2, 3]),
        );
        map.insert(
            data_type_id(DataType::WrappingScheme, &tm),
            DataValue::Str("mtp-call-secret-kem-chacha20poly1305-hkdf-sha256-v1".to_string()),
        );

        assert!(
            CallSecretEnvelope::from_data_value(&DataValue::container_from_map(&map)).is_none()
        );
    }

    #[test]
    fn call_secret_envelope_round_trips_opaque_bytes() {
        let secret = envelope("receiver");

        assert_eq!(
            CallSecretEnvelope::from_data_value(&secret.to_data_value()),
            Some(secret)
        );
    }

    #[test]
    fn call_invite_missing_call_secret_is_rejected() {
        let cv = CommunicationValue::new(CommunicationType::CallInvite);

        assert!(call_invite_secret_from_cv(&cv).is_none());
    }

    #[test]
    fn call_invite_parses_call_secret_envelope() {
        let secret = envelope("receiver");
        let cv = CommunicationValue::new(CommunicationType::CallInvite)
            .add_typed_default(DataType::CallSecret, secret.clone().to_data_value());

        assert_eq!(call_invite_secret_from_cv(&cv), Some(secret));
    }

    #[test]
    fn receiver_call_invite_contains_receiver_envelope_unchanged() {
        let receiver_secret = envelope("receiver");
        let cv = CommunicationValue::new(CommunicationType::CallInvite).add_typed_default(
            DataType::CallSecret,
            receiver_secret.clone().to_data_value(),
        );

        let Some(call_secret) = cv.get_data(DataType::CallSecret) else {
            panic!("call invite did not contain a call secret");
        };
        assert_eq!(
            CallSecretEnvelope::from_data_value(call_secret),
            Some(receiver_secret)
        );
    }

    #[tokio::test]
    async fn call_group_returns_only_current_users_secret() {
        let call_id = Uuid::new_v4();
        let group = CallGroup::new(call_id, Arc::new(Caller::new(1, call_id, true)));
        let own_secret = envelope("own");
        let receiver_secret = envelope("receiver");

        {
            let mut secrets = group.secrets.write().await;
            secrets.insert(1, own_secret.clone());
            secrets.insert(2, receiver_secret.clone());
        }

        assert_eq!(group.get_secret_for_user(1).await, Some(own_secret));
        assert_eq!(group.get_secret_for_user(2).await, Some(receiver_secret));
        assert_eq!(group.get_secret_for_user(3).await, None);
    }
}
