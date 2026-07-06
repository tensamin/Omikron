use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataTypeId, DataValue, TypeMap};
use serde_json::Map;

use std::{collections::BTreeMap, env, sync::Arc, time::Duration};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::{
    calls::{call_util, caller::Caller},
    omega::omega_connection::get_omega_connection,
};

pub struct CallGroup {
    pub call_id: Uuid,
    pub members: RwLock<Vec<Arc<Caller>>>,
    pub show: RwLock<bool>,
    pub anonymous_joining: RwLock<bool>,
    pub short_link: RwLock<Option<String>>,
    pub secrets: RwLock<BTreeMap<u64, CallSecretEnvelope>>,
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
            .get_field(DataType::SecretId.to_id(&tm))?
            .as_str()?
            .to_string();
        let version_number = value
            .get_field(DataType::VersionNumber.to_id(&tm))?
            .as_signed_number()
            .and_then(|n| i64::try_from(n).ok())
            .or_else(|| {
                value
                    .get_field(DataType::VersionNumber.to_id(&tm))?
                    .as_number()
                    .and_then(|n| i64::try_from(n).ok())
            })?;
        let encrypted_secret = value
            .get_field(DataType::EncryptedSecret.to_id(&tm))?
            .as_bytes()?;
        let kem_ciphertext = value
            .get_field(DataType::KemCiphertext.to_id(&tm))?
            .as_bytes()?;
        let wrapping_scheme = value
            .get_field(DataType::WrappingScheme.to_id(&tm))?
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
            DataType::SecretId.to_id(&tm),
            DataValue::Str(self.secret_id.clone()),
        );
        map.insert(
            DataType::VersionNumber.to_id(&tm),
            DataValue::SignedNumber(self.version_number.into()),
        );
        map.insert(
            DataType::EncryptedSecret.to_id(&tm),
            DataValue::Bytes(self.encrypted_secret.clone()),
        );
        map.insert(
            DataType::KemCiphertext.to_id(&tm),
            DataValue::Bytes(self.kem_ciphertext.clone()),
        );
        map.insert(
            DataType::WrappingScheme.to_id(&tm),
            DataValue::Str(self.wrapping_scheme.clone()),
        );
        DataValue::container_from_map(&map)
    }
}

pub fn call_invite_secret_from_cv(cv: &CommunicationValue) -> Option<CallSecretEnvelope> {
    CallSecretEnvelope::from_data_value(cv.get_data(DataType::CallSecret))
}

impl CallGroup {
    pub fn new(call_id: Uuid, user: Arc<Caller>) -> Self {
        CallGroup {
            call_id,
            members: RwLock::new(vec![user]),
            show: RwLock::new(true),
            anonymous_joining: RwLock::new(false),
            short_link: RwLock::new(None),
            secrets: RwLock::new(BTreeMap::new()),
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
        let call_metadata = match call_util::get_room_metadata(self.call_id).await {
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

        let _ = call_util::set_room_metadata(
            self.call_id,
            serde_json::Value::Object(call_metadata).to_string(),
        )
        .await;
    }

    pub async fn set_anonymous_joining(&self, enable: bool) {
        *self.anonymous_joining.write().await = enable;

        let call_metadata = match call_util::get_room_metadata(self.call_id).await {
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

        let _ = call_util::set_room_metadata(
            self.call_id,
            serde_json::Value::Object(call_metadata).to_string(),
        )
        .await;

        if self.short_link.read().await.is_none() {
            let long_link = format!(
                "https://app.tensamin.net/call/anonymous?call_id={}&omikron_id={}",
                self.call_id,
                env::var("ID")
                    .unwrap_or("0".to_string())
                    .parse::<i64>()
                    .unwrap_or(0),
            );
            let response_cv = get_omega_connection()
                .await_response(
                    &CommunicationValue::new(CommunicationType::ShortenLink)
                        .add_typed_default(DataType::Link, DataValue::Str(long_link)),
                    Some(Duration::from_secs(20)),
                )
                .await;
            if let Ok(response) = response_cv {
                *self.short_link.write().await = Some(
                    response
                        .get_data(DataType::Link)
                        .as_str()
                        .unwrap()
                        .to_string(),
                );
                log::info!(
                    "Shortened link for call {} is {}",
                    self.call_id,
                    self.short_link.read().await.as_ref().unwrap()
                );
            }
        }
    }

    pub async fn create_anonymous_token(&self, user_id: u64) -> Option<String> {
        if self.is_anonymous().await {
            if let Ok(token) = call_util::create_token(user_id, self.call_id, false) {
                return Some(token);
            }
        }
        None
    }

    pub async fn remove_caller(&self, user_id: u64) {
        let _ = call_util::remove_participant(self.call_id, user_id).await;
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
            DataType::SecretId.to_id(&tm),
            DataValue::Str("call:test:main".to_string()),
        );
        map.insert(
            DataType::VersionNumber.to_id(&tm),
            DataValue::SignedNumber(1),
        );
        map.insert(
            DataType::EncryptedSecret.to_id(&tm),
            DataValue::Bytes(vec![1, 2, 3]),
        );
        map.insert(
            DataType::WrappingScheme.to_id(&tm),
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

        assert_eq!(
            CallSecretEnvelope::from_data_value(cv.get_data(DataType::CallSecret)),
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
