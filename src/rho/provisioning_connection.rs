use std::{sync::Arc, time::Duration};

use mtp::{
    codec::{CommunicationType, CommunicationValue, DataType, DataValue},
    crypto::PublicKeyBundle,
};
use uuid::Uuid;

use super::connection::{GeneralConnection, MtpReceiver, MtpSender};
use crate::provisioning::session::{
    ProvisioningMethod, ProvisioningParticipant, ProvisioningRole, ProvisioningSession,
    ResolvedAccount,
};

const MAX_KEY_LENGTH: usize = 16 * 1024;
const MAX_USERNAME_LENGTH: usize = 15;

pub struct ProvisioningConnection {
    general: Arc<GeneralConnection>,
    sender: Arc<MtpSender>,
    receiver: Arc<MtpReceiver>,
}

impl ProvisioningConnection {
    fn valid_fields(request: &CommunicationValue) -> bool {
        let allowed: &[DataType] = match request.get_comm_type_enum() {
            Some(CommunicationType::ProvisioningCreate) => &[
                DataType::ProvisioningMethod,
                DataType::ProvisioningRole,
                DataType::PublicKey,
                DataType::Username,
                DataType::UserId,
            ],
            Some(CommunicationType::ProvisioningJoin) => &[
                DataType::Uuid,
                DataType::ProvisioningRole,
                DataType::PublicKey,
            ],
            Some(CommunicationType::ProvisioningBindAccount) => {
                &[DataType::Uuid, DataType::Username, DataType::UserId]
            }
            Some(
                CommunicationType::PasswordProvisioningStart
                | CommunicationType::PasswordProvisioningFinish,
            ) => &[DataType::Uuid, DataType::OpaqueMessage],
            Some(
                CommunicationType::ProvisioningCancel
                | CommunicationType::ProvisioningComplete
                | CommunicationType::QrProvisioningConfirm,
            ) => &[DataType::Uuid],
            Some(CommunicationType::ProvisioningCredential) => return true,
            _ => return false,
        };
        let mut seen = Vec::new();
        request.iter_typed_data().all(|(kind, _)| {
            kind.is_some_and(|kind| {
                allowed.contains(&kind) && !seen.contains(&kind) && {
                    seen.push(kind);
                    true
                }
            })
        })
    }

    pub fn from_general(general: Arc<GeneralConnection>) -> Arc<Self> {
        Arc::new(Self {
            sender: general.sender.clone(),
            receiver: general.receiver.clone(),
            general,
        })
    }

    pub async fn start(self: Arc<Self>) {
        while let Ok(request) = self.receiver.receive().await {
            let Some(id) = request.id() else {
                let _ = self
                    .sender
                    .send(
                        &CommunicationValue::new(CommunicationType::ErrorInvalidData).without_id(),
                    )
                    .await;
                continue;
            };
            let error_kind = if matches!(
                request.get_comm_type_enum(),
                Some(
                    CommunicationType::PasswordProvisioningStart
                        | CommunicationType::PasswordProvisioningFinish
                )
            ) {
                CommunicationType::ErrorNotAuthenticated
            } else {
                CommunicationType::ErrorInvalidData
            };
            if !Self::valid_fields(&request) {
                let _ = self
                    .sender
                    .send(&CommunicationValue::new(error_kind).with_id(id))
                    .await;
                continue;
            }
            let result = match request.get_comm_type_enum() {
                Some(CommunicationType::ProvisioningCreate) => self.create(&request).await,
                Some(CommunicationType::ProvisioningJoin) => self.join(&request).await,
                Some(CommunicationType::ProvisioningBindAccount) => self.bind(&request).await,
                Some(CommunicationType::QrProvisioningConfirm) => self.confirm(&request).await,
                Some(CommunicationType::ProvisioningCredential) => {
                    self.relay_credential(&request).await
                }
                Some(CommunicationType::ProvisioningComplete) => self.complete(&request).await,
                Some(CommunicationType::ProvisioningCancel) => self.cancel(&request).await,
                Some(CommunicationType::PasswordProvisioningStart) => {
                    self.password_start(&request).await
                }
                Some(CommunicationType::PasswordProvisioningFinish) => {
                    self.password_finish(&request).await
                }
                _ => Err("operation not allowed on provisioning connection"),
            };
            if result.is_err() {
                let error = CommunicationValue::new(error_kind).with_id(id);
                let _ = self.sender.send(&error).await;
            } else if matches!(
                request.get_comm_type_enum(),
                Some(
                    CommunicationType::ProvisioningComplete | CommunicationType::ProvisioningCancel
                )
            ) {
                break;
            }
        }
        let _ = self.sender.close();
        self.general
            .state
            .provisioning
            .remove_participant(self.general.id());
    }

    fn session_id(request: &CommunicationValue) -> Result<Uuid, &'static str> {
        request
            .get_data(DataType::Uuid)
            .and_then(DataValue::as_str)
            .and_then(|value| Uuid::parse_str(value).ok())
            .ok_or("invalid session ID")
    }

    fn participant(
        &self,
        request: &CommunicationValue,
        role: ProvisioningRole,
    ) -> Result<ProvisioningParticipant, &'static str> {
        let encoded = request
            .get_data(DataType::PublicKey)
            .and_then(DataValue::as_str)
            .ok_or("missing key")?;
        if encoded.len() > MAX_KEY_LENGTH {
            return Err("key too large");
        }
        let key = PublicKeyBundle::from_base64(encoded).map_err(|_| "invalid key")?;
        Ok(ProvisioningParticipant {
            id: self.general.id(),
            role,
            temporary_public_key: key,
            sender: Arc::downgrade(&self.sender),
        })
    }

    fn role(request: &CommunicationValue) -> Result<ProvisioningRole, &'static str> {
        match request
            .get_data(DataType::ProvisioningRole)
            .and_then(DataValue::as_str)
        {
            Some("contact") => Ok(ProvisioningRole::Contact),
            Some("owner") => Ok(ProvisioningRole::Owner),
            _ => Err("invalid role"),
        }
    }

    async fn create(&self, request: &CommunicationValue) -> Result<(), &'static str> {
        let method = match request
            .get_data(DataType::ProvisioningMethod)
            .and_then(DataValue::as_str)
        {
            Some("password") => ProvisioningMethod::Password,
            Some("qr-contact-created") => ProvisioningMethod::QrContactCreated,
            Some("qr-owner-created") => ProvisioningMethod::QrOwnerCreated,
            _ => return Err("invalid method"),
        };
        let role = Self::role(request)?;
        if request.get_data(DataType::Username).is_some()
            && request.get_data(DataType::UserId).is_some()
        {
            return Err("ambiguous account hint");
        }
        if method != ProvisioningMethod::Password
            && (request.get_data(DataType::Username).is_some()
                || request.get_data(DataType::UserId).is_some())
        {
            return Err("QR creation does not accept an account hint");
        }
        if (method == ProvisioningMethod::QrContactCreated && role != ProvisioningRole::Contact)
            || (method == ProvisioningMethod::QrOwnerCreated && role != ProvisioningRole::Owner)
            || (method == ProvisioningMethod::Password && role != ProvisioningRole::Contact)
        {
            return Err("invalid creator role");
        }
        let participant = self.participant(request, role)?;
        let account = if method == ProvisioningMethod::Password {
            let account = self.resolve_account(request).await?;
            self.general
                .state
                .rho
                .get_by_iota(account.iota_id)
                .await
                .ok_or("Iota unavailable")?;
            Some(account)
        } else {
            None
        };
        let id = self
            .general
            .state
            .provisioning
            .create(method, participant)
            .map_err(|_| "cannot create session")?;
        if let Some(account) = account {
            self.general
                .state
                .provisioning
                .bind(id, self.general.id(), account)?;
        }
        let reply = CommunicationValue::new(CommunicationType::ProvisioningCreated)
            .with_id(request.id().ok_or("missing request ID")?)
            .add_typed_default(DataType::Uuid, DataValue::Str(id.to_string()))
            .add_typed_default(
                DataType::ProvisioningParticipantId,
                DataValue::UnsignedNumber(self.general.id().into()),
            )
            .add_typed_default(
                DataType::ProvisioningMethod,
                DataValue::Str(method.as_str().into()),
            )
            .add_typed_default(
                DataType::ProvisioningRole,
                DataValue::Str(role.as_str().into()),
            );
        self.sender.send(&reply).await.map_err(|_| "send failed")
    }

    async fn join(&self, request: &CommunicationValue) -> Result<(), &'static str> {
        let id = Self::session_id(request)?;
        let role = Self::role(request)?;
        let participant = self.participant(request, role)?;
        let session = self
            .general
            .state
            .provisioning
            .join(id, participant.clone())?;
        let peer = match role {
            ProvisioningRole::Contact => session.owner.as_ref(),
            ProvisioningRole::Owner => session.contact.as_ref(),
        }
        .ok_or("peer missing")?;
        let peer_event = |other: &ProvisioningParticipant,
                          frame_id: Option<u32>|
         -> Result<CommunicationValue, &'static str> {
            let mut event = CommunicationValue::new(CommunicationType::ProvisioningPeerJoined);
            if let Some(frame_id) = frame_id {
                event = event.with_id(frame_id);
            }
            Ok(event
                .add_typed_default(DataType::Uuid, DataValue::Str(id.to_string()))
                .add_typed_default(
                    DataType::ProvisioningParticipantId,
                    DataValue::UnsignedNumber(other.id.into()),
                )
                .add_typed_default(
                    DataType::ProvisioningRole,
                    DataValue::Str(other.role.as_str().into()),
                )
                .add_typed_default(
                    DataType::PublicKey,
                    DataValue::Str(
                        other
                            .temporary_public_key
                            .try_to_base64()
                            .map_err(|_| "key encoding failed")?,
                    ),
                ))
        };
        let frame_id = request.id().ok_or("missing request ID")?;
        self.sender
            .send(&peer_event(peer, Some(frame_id))?)
            .await
            .map_err(|_| "send failed")?;
        let peer_sender = peer.sender.upgrade().ok_or("peer disconnected")?;
        peer_sender
            .send(&peer_event(&participant, None)?)
            .await
            .map_err(|_| "send failed")
    }

    async fn resolve_account(
        &self,
        request: &CommunicationValue,
    ) -> Result<ResolvedAccount, &'static str> {
        let mut lookup = CommunicationValue::new(CommunicationType::GetUserData)
            .with_sender(self.general.state.omega.omikron_id());
        if let Some(user_id) = request
            .get_data(DataType::UserId)
            .and_then(DataValue::as_signed_number)
        {
            let id = i64::try_from(user_id)
                .ok()
                .filter(|id| *id > 0)
                .ok_or("invalid user ID")?;
            lookup = lookup.add_typed_default(DataType::UserId, DataValue::SignedNumber(id.into()));
        } else {
            let username = request
                .get_data(DataType::Username)
                .and_then(DataValue::as_str)
                .ok_or("missing account hint")?;
            if username.is_empty() || username.len() > MAX_USERNAME_LENGTH {
                return Err("invalid username");
            }
            lookup = lookup.add_typed_default(DataType::Username, DataValue::Str(username.into()));
        }
        let response = self
            .general
            .state
            .omega
            .clone()
            .await_response(&lookup, Some(Duration::from_secs(20)))
            .await
            .map_err(|_| "account lookup failed")?;
        if !response.is_type(CommunicationType::GetUserData) {
            return Err("account not found");
        }
        let positive = |field| {
            response
                .get_data(field)
                .and_then(DataValue::as_signed_number)
                .and_then(|value| i64::try_from(value).ok())
                .filter(|value| *value > 0)
                .ok_or("invalid account")
        };
        let string = |field| {
            response
                .get_data(field)
                .and_then(DataValue::as_str)
                .map(str::to_owned)
                .ok_or("invalid account")
        };
        let encoded = string(DataType::PublicKey)?;
        Ok(ResolvedAccount {
            user_id: positive(DataType::UserId)?,
            username: string(DataType::Username)?,
            principal: string(DataType::Principal)?,
            iota_id: positive(DataType::IotaId)?,
            public_key: PublicKeyBundle::from_base64(&encoded)
                .map_err(|_| "invalid account key")?,
        })
    }

    async fn bind(&self, request: &CommunicationValue) -> Result<(), &'static str> {
        if request.get_data(DataType::Username).is_some()
            && request.get_data(DataType::UserId).is_some()
        {
            return Err("ambiguous account hint");
        }
        let id = Self::session_id(request)?;
        let session = self
            .general
            .state
            .provisioning
            .snapshot(id, self.general.id())?;
        session.require_actor(self.general.id(), ProvisioningRole::Owner)?;
        let account = self.resolve_account(request).await?;
        let session =
            self.general
                .state
                .provisioning
                .bind(id, self.general.id(), account.clone())?;
        let reply = CommunicationValue::new(CommunicationType::ProvisioningAccountBound)
            .with_id(request.id().ok_or("missing request ID")?)
            .add_typed_default(DataType::Uuid, DataValue::Str(id.to_string()))
            .add_typed_default(
                DataType::UserId,
                DataValue::SignedNumber(account.user_id.into()),
            )
            .add_typed_default(DataType::Username, DataValue::Str(account.username))
            .add_typed_default(
                DataType::IotaId,
                DataValue::SignedNumber(account.iota_id.into()),
            )
            .add_typed_default(DataType::Principal, DataValue::Str(account.principal))
            .add_typed_default(
                DataType::PublicKey,
                DataValue::Str(
                    account
                        .public_key
                        .try_to_base64()
                        .map_err(|_| "key encoding failed")?,
                ),
            );
        self.sender.send(&reply).await.map_err(|_| "send failed")?;
        if let Some(contact) = session.contact.and_then(|contact| contact.sender.upgrade()) {
            contact
                .send(&reply.clone().with_id(rand::random::<u32>().max(1)))
                .await
                .map_err(|_| "send failed")?;
        }
        Ok(())
    }

    async fn confirm(&self, request: &CommunicationValue) -> Result<(), &'static str> {
        self.general
            .state
            .provisioning
            .confirm(Self::session_id(request)?, self.general.id())?;
        self.send_success(request).await
    }

    async fn relay_credential(&self, request: &CommunicationValue) -> Result<(), &'static str> {
        let session = self
            .general
            .state
            .provisioning
            .for_participant(self.general.id())?;
        let recipient = request.receiver().ok_or("missing recipient")?;
        // Only protected frames have an encrypted payload; clear credentials must never be routed.
        if request.payload().as_encrypted().is_none() {
            return Err("credential is not protected");
        }
        let session = self.general.state.provisioning.authorize_delivery(
            session.id,
            self.general.id(),
            recipient,
        )?;
        let contact = session
            .contact
            .ok_or("contact missing")?
            .sender
            .upgrade()
            .ok_or("contact disconnected")?;
        contact.send(request).await.map_err(|_| "send failed")?;
        self.general
            .state
            .provisioning
            .delivered(session.id, self.general.id())
    }

    async fn complete(&self, request: &CommunicationValue) -> Result<(), &'static str> {
        let id = Self::session_id(request)?;
        let owner = self
            .general
            .state
            .provisioning
            .complete(id, self.general.id())?;
        if let Some(owner) = owner.and_then(|owner| owner.sender.upgrade()) {
            let _ = owner
                .send(
                    &CommunicationValue::new(CommunicationType::ProvisioningComplete)
                        .add_typed_default(DataType::Uuid, DataValue::Str(id.to_string())),
                )
                .await;
        }
        self.send_success(request).await
    }

    async fn cancel(&self, request: &CommunicationValue) -> Result<(), &'static str> {
        self.general
            .state
            .provisioning
            .snapshot(Self::session_id(request)?, self.general.id())?;
        self.general
            .state
            .provisioning
            .remove_participant(self.general.id());
        self.send_success(request).await
    }

    async fn send_success(&self, request: &CommunicationValue) -> Result<(), &'static str> {
        self.sender
            .send(
                &CommunicationValue::new(CommunicationType::Success)
                    .with_id(request.id().ok_or("missing request ID")?),
            )
            .await
            .map_err(|_| "send failed")
    }

    async fn password_start(&self, request: &CommunicationValue) -> Result<(), &'static str> {
        let id = Self::session_id(request)?;
        let ke1 = request
            .get_data(DataType::OpaqueMessage)
            .and_then(DataValue::as_bytes)
            .ok_or("missing KE1")?;
        if ke1.is_empty() || ke1.len() > 16 * 1024 {
            return Err("invalid KE1");
        }
        let session = self
            .general
            .state
            .provisioning
            .password_start(id, self.general.id())?;
        let response = self.password_forward(request, &session, ke1).await?;
        if !response.is_type(CommunicationType::PasswordProvisioningResponse)
            || response
                .get_data(DataType::Uuid)
                .and_then(DataValue::as_str)
                != Some(id.to_string().as_str())
            || response
                .get_data(DataType::OpaqueMessage)
                .and_then(DataValue::as_bytes)
                .is_none()
        {
            return Err("invalid Iota KE2");
        }
        self.sender.send(&response).await.map_err(|_| "send failed")
    }

    async fn password_finish(&self, request: &CommunicationValue) -> Result<(), &'static str> {
        let id = Self::session_id(request)?;
        let ke3 = request
            .get_data(DataType::OpaqueMessage)
            .and_then(DataValue::as_bytes)
            .ok_or("missing KE3")?;
        if ke3.is_empty() || ke3.len() > 16 * 1024 {
            return Err("invalid KE3");
        }
        let session = self
            .general
            .state
            .provisioning
            .password_finish(id, self.general.id())?;
        let response = self.password_forward(request, &session, ke3).await?;
        if !response.is_type(CommunicationType::ProvisioningCredential)
            || response.receiver() != Some(self.general.id())
            || response.payload().as_encrypted().is_none()
        {
            return Err("Iota did not authorize the credential");
        }
        self.sender
            .send(&response)
            .await
            .map_err(|_| "send failed")?;
        self.general
            .state
            .provisioning
            .password_delivered(id, self.general.id())
    }

    async fn password_forward(
        &self,
        request: &CommunicationValue,
        session: &ProvisioningSession,
        opaque: Vec<u8>,
    ) -> Result<CommunicationValue, &'static str> {
        let account = session.account.as_ref().ok_or("account not bound")?;
        let contact = session.contact.as_ref().ok_or("contact not present")?;
        let rho = self
            .general
            .state
            .rho
            .get_by_iota(account.iota_id)
            .await
            .ok_or("Iota unavailable")?;
        let message =
            CommunicationValue::new(request.get_comm_type_enum().ok_or("invalid operation")?)
                .with_id(request.id().ok_or("missing request ID")?)
                .add_typed_default(DataType::Uuid, DataValue::Str(session.id.to_string()))
                .add_typed_default(
                    DataType::ProvisioningParticipantId,
                    DataValue::UnsignedNumber(contact.id.into()),
                )
                .add_typed_default(
                    DataType::UserId,
                    DataValue::SignedNumber(account.user_id.into()),
                )
                .add_typed_default(
                    DataType::IotaId,
                    DataValue::SignedNumber(account.iota_id.into()),
                )
                .add_typed_default(
                    DataType::PublicKey,
                    DataValue::Str(
                        contact
                            .temporary_public_key
                            .try_to_base64()
                            .map_err(|_| "invalid key")?,
                    ),
                )
                .add_typed_default(DataType::OpaqueMessage, DataValue::Bytes(opaque));
        rho.get_iota_connection()
            .clone()
            .await_response_rekeyed(&message, Some(Duration::from_secs(30)))
            .await
            .map_err(|_| "Iota request failed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provisioning_frames_reject_bootstrap_and_repeated_account_fields() {
        let create = CommunicationValue::new(CommunicationType::ProvisioningCreate)
            .add_typed_default(
                DataType::ProvisioningMethod,
                DataValue::Str("qr-contact-created".into()),
            )
            .add_typed_default(DataType::ProvisioningRole, DataValue::Str("contact".into()))
            .add_typed_default(DataType::PublicKey, DataValue::Str("key".into()));
        assert!(ProvisioningConnection::valid_fields(&create));
        assert!(!ProvisioningConnection::valid_fields(
            &create.add_typed_default(
                DataType::Payload,
                DataValue::Bytes(b"bootstrap secret".to_vec())
            )
        ));
        let ke1 = CommunicationValue::new(CommunicationType::PasswordProvisioningStart)
            .add_typed_default(DataType::Uuid, DataValue::Str(Uuid::new_v4().to_string()))
            .add_typed_default(DataType::OpaqueMessage, DataValue::Bytes(vec![1]));
        assert!(ProvisioningConnection::valid_fields(&ke1));
        assert!(!ProvisioningConnection::valid_fields(
            &ke1.add_typed_default(DataType::UserId, DataValue::SignedNumber(7))
        ));
        assert!(!ProvisioningConnection::valid_fields(
            &CommunicationValue::new(CommunicationType::SettingsSave)
        ));
    }
}
