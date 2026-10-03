use std::{future::Future, sync::Arc, time::Duration};

use mtp::{
    codec::{CommunicationType, CommunicationValue, DataType, DataValue},
    crypto::PublicKeyBundle,
};
use uuid::Uuid;

use super::connection::{GeneralConnection, MtpReceiver, MtpSender};
use crate::provisioning::ProvisioningManager;
use crate::provisioning::session::{
    ProvisioningFailure, ProvisioningMethod, ProvisioningParticipant, ProvisioningRole,
    ProvisioningSession, ResolvedAccount,
};

const MAX_KEY_LENGTH: usize = 16 * 1024;
const MAX_USERNAME_LENGTH: usize = 15;

#[derive(Debug)]
enum ProvisioningOperationError {
    Replyable(&'static str),
    // The requester response path was attempted. Never send another frame with its request ID.
    NoFurtherReply(&'static str),
}

impl From<&'static str> for ProvisioningOperationError {
    fn from(value: &'static str) -> Self {
        Self::Replyable(value)
    }
}

impl From<crate::provisioning::error::ProvisioningError> for ProvisioningOperationError {
    fn from(error: crate::provisioning::error::ProvisioningError) -> Self {
        Self::Replyable(error.into())
    }
}

#[derive(Debug, PartialEq, Eq)]
enum DeliveryFailure {
    Peer,
    Requester,
}

async fn deliver_peer_then_reply<P, R, PF, RF>(
    event: CommunicationValue,
    reply: CommunicationValue,
    send_peer: P,
    send_requester: R,
) -> Result<(), DeliveryFailure>
where
    P: FnOnce(CommunicationValue) -> PF,
    R: FnOnce(CommunicationValue) -> RF,
    PF: Future<Output = bool>,
    RF: Future<Output = bool>,
{
    if !send_peer(event).await {
        return Err(DeliveryFailure::Peer);
    }
    if !send_requester(reply).await {
        return Err(DeliveryFailure::Requester);
    }
    Ok(())
}

fn peer_joined_message(
    id: Uuid,
    participant: &ProvisioningParticipant,
    frame_id: Option<u32>,
) -> Result<CommunicationValue, &'static str> {
    let encoded_key = participant
        .temporary_public_key
        .try_to_base64()
        .map_err(|_| "key encoding failed")?;
    let mut message = CommunicationValue::new(CommunicationType::ProvisioningPeerJoined);
    if let Some(frame_id) = frame_id {
        message = message.with_id(frame_id);
    }
    Ok(message
        .add_typed_default(DataType::Uuid, DataValue::Str(id.to_string()))
        .add_typed_default(
            DataType::ProvisioningParticipantId,
            DataValue::UnsignedNumber(participant.id.into()),
        )
        .add_typed_default(
            DataType::ProvisioningRole,
            DataValue::Str(participant.role.as_str().into()),
        )
        .add_typed_default(DataType::PublicKey, DataValue::Str(encoded_key)))
}

fn account_bound_message(
    id: Uuid,
    account: &ResolvedAccount,
    encoded_public_key: &str,
    frame_id: Option<u32>,
) -> CommunicationValue {
    let mut message = CommunicationValue::new(CommunicationType::ProvisioningAccountBound);
    if let Some(frame_id) = frame_id {
        message = message.with_id(frame_id);
    }
    message
        .add_typed_default(DataType::Uuid, DataValue::Str(id.to_string()))
        .add_typed_default(
            DataType::UserId,
            DataValue::SignedNumber(account.user_id.into()),
        )
        .add_typed_default(DataType::Username, DataValue::Str(account.username.clone()))
        .add_typed_default(
            DataType::IotaId,
            DataValue::SignedNumber(account.iota_id.into()),
        )
        .add_typed_default(
            DataType::Principal,
            DataValue::Str(account.principal.clone()),
        )
        .add_typed_default(
            DataType::PublicKey,
            DataValue::Str(encoded_public_key.to_owned()),
        )
}

pub struct ProvisioningConnection {
    general: Arc<GeneralConnection>,
    sender: Arc<MtpSender>,
    receiver: Arc<MtpReceiver>,
}

impl ProvisioningConnection {
    async fn terminate_forward(&self, id: Uuid, reason: ProvisioningFailure) {
        let Ok(terminated) =
            self.general
                .state
                .provisioning
                .fail_forward(id, self.general.id(), reason)
        else {
            return;
        };
        crate::log_err!(
            self.general.id() as i64,
            crate::util::logger::PrintType::Client,
            "Provisioning {} ({:?}) terminated after {:?}",
            terminated.id,
            terminated.method,
            terminated.reason
        );
        let peer = if terminated
            .contact
            .as_ref()
            .map(|participant| participant.id)
            == Some(self.general.id())
        {
            terminated.owner
        } else {
            terminated.contact
        };
        if let Some(sender) = peer.and_then(|participant| participant.sender.upgrade()) {
            let _ = sender
                .send(
                    &CommunicationValue::new(CommunicationType::ProvisioningCancel)
                        .with_id(rand::random::<u32>().max(1))
                        .add_typed_default(DataType::Uuid, DataValue::Str(id.to_string())),
                )
                .await;
        }
    }

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
            let result: Result<(), ProvisioningOperationError> = match request.get_comm_type_enum()
            {
                Some(CommunicationType::ProvisioningCreate) => {
                    self.create(&request).await.map_err(Into::into)
                }
                Some(CommunicationType::ProvisioningJoin) => self.join(&request).await,
                Some(CommunicationType::ProvisioningBindAccount) => self.bind(&request).await,
                Some(CommunicationType::QrProvisioningConfirm) => {
                    self.confirm(&request).await.map_err(Into::into)
                }
                Some(CommunicationType::ProvisioningCredential) => {
                    self.relay_credential(&request).await.map_err(Into::into)
                }
                Some(CommunicationType::ProvisioningComplete) => {
                    self.complete(&request).await.map_err(Into::into)
                }
                Some(CommunicationType::ProvisioningCancel) => {
                    self.cancel(&request).await.map_err(Into::into)
                }
                Some(CommunicationType::PasswordProvisioningStart) => {
                    self.password_start(&request).await.map_err(Into::into)
                }
                Some(CommunicationType::PasswordProvisioningFinish) => {
                    self.password_finish(&request).await.map_err(Into::into)
                }
                _ => Err(ProvisioningOperationError::Replyable(
                    "operation not allowed on provisioning connection",
                )),
            };
            match result {
                Ok(())
                    if matches!(
                        request.get_comm_type_enum(),
                        Some(
                            CommunicationType::ProvisioningComplete
                                | CommunicationType::ProvisioningCancel
                        )
                    ) =>
                {
                    break;
                }
                Ok(()) => {}
                Err(ProvisioningOperationError::Replyable(message)) => {
                    crate::log_err!(
                        self.general.id() as i64,
                        crate::util::logger::PrintType::Client,
                        "Provisioning request failed: {}",
                        message
                    );
                    let error = CommunicationValue::new(error_kind).with_id(id);
                    let _ = self.sender.send(&error).await;
                }
                Err(ProvisioningOperationError::NoFurtherReply(message)) => {
                    crate::log_err!(
                        self.general.id() as i64,
                        crate::util::logger::PrintType::Client,
                        "Provisioning request terminated after requester response path: {}",
                        message
                    );
                }
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
        if self.sender.send(&reply).await.is_err() {
            self.terminate_forward(id, ProvisioningFailure::DeliveryFailed)
                .await;
            return Err("send failed");
        }
        Ok(())
    }

    // A request may have at most one response with its frame ID. Notify the peer
    // before replying, and never retry the requester response path after attempting it.
    async fn join(&self, request: &CommunicationValue) -> Result<(), ProvisioningOperationError> {
        let id = Self::session_id(request)?;
        let role = Self::role(request)?;
        let participant = self.participant(request, role)?;
        let frame_id = request.id().ok_or("missing request ID")?;
        let session = self
            .general
            .state
            .provisioning
            .join(id, participant.clone())?;
        let peer = match role {
            ProvisioningRole::Contact => session.owner,
            ProvisioningRole::Owner => session.contact,
        }
        .ok_or("peer missing")?;
        let peer_sender = match peer.sender.upgrade() {
            Some(sender) => sender,
            None => {
                self.terminate_forward(id, ProvisioningFailure::PeerDisconnected)
                    .await;
                return Err("peer disconnected".into());
            }
        };
        let event_to_peer = match peer_joined_message(id, &participant, None) {
            Ok(message) => message,
            Err(error) => {
                self.terminate_forward(id, ProvisioningFailure::DeliveryFailed)
                    .await;
                return Err(error.into());
            }
        };
        let reply_to_joiner = match peer_joined_message(id, &peer, Some(frame_id)) {
            Ok(message) => message.add_typed_default(
                DataType::ClientId,
                DataValue::UnsignedNumber(participant.id.into()),
            ),
            Err(error) => {
                self.terminate_forward(id, ProvisioningFailure::DeliveryFailed)
                    .await;
                return Err(error.into());
            }
        };
        let delivery = deliver_peer_then_reply(
            event_to_peer,
            reply_to_joiner,
            |message| async move { peer_sender.send(&message).await.is_ok() },
            |message| async move { self.sender.send(&message).await.is_ok() },
        )
        .await;
        if let Err(failure) = delivery {
            self.terminate_forward(id, ProvisioningFailure::DeliveryFailed)
                .await;
            return Err(match failure {
                DeliveryFailure::Peer => "peer notification failed".into(),
                DeliveryFailure::Requester => {
                    ProvisioningOperationError::NoFurtherReply("join response delivery failed")
                }
            });
        }
        Ok(())
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

    // A request may have at most one response with its frame ID. Notify the peer
    // before replying, and never retry the requester response path after attempting it.
    async fn bind(&self, request: &CommunicationValue) -> Result<(), ProvisioningOperationError> {
        if request.get_data(DataType::Username).is_some()
            && request.get_data(DataType::UserId).is_some()
        {
            return Err("ambiguous account hint".into());
        }
        let id = Self::session_id(request)?;
        let frame_id = request.id().ok_or("missing request ID")?;
        let session = self
            .general
            .state
            .provisioning
            .snapshot(id, self.general.id())?;
        session.require_actor(self.general.id(), ProvisioningRole::Owner)?;
        let account = self.resolve_account(request).await?;
        let encoded_public_key = account
            .public_key
            .try_to_base64()
            .map_err(|_| ProvisioningOperationError::Replyable("key encoding failed"))?;
        let session =
            self.general
                .state
                .provisioning
                .bind(id, self.general.id(), account.clone())?;
        let contact = match session.contact.and_then(|contact| contact.sender.upgrade()) {
            Some(contact) => contact,
            None => {
                self.terminate_forward(id, ProvisioningFailure::PeerDisconnected)
                    .await;
                return Err("contact disconnected".into());
            }
        };
        let event_to_contact = account_bound_message(id, &account, &encoded_public_key, None);
        let reply_to_owner =
            account_bound_message(id, &account, &encoded_public_key, Some(frame_id));
        let delivery = deliver_peer_then_reply(
            event_to_contact,
            reply_to_owner,
            |message| async move { contact.send(&message).await.is_ok() },
            |message| async move { self.sender.send(&message).await.is_ok() },
        )
        .await;
        if let Err(failure) = delivery {
            self.terminate_forward(id, ProvisioningFailure::DeliveryFailed)
                .await;
            return Err(match failure {
                DeliveryFailure::Peer => "contact notification failed".into(),
                DeliveryFailure::Requester => ProvisioningOperationError::NoFurtherReply(
                    "account binding response delivery failed",
                ),
            });
        }
        Ok(())
    }

    async fn confirm(&self, request: &CommunicationValue) -> Result<(), &'static str> {
        let id = Self::session_id(request)?;
        self.general
            .state
            .provisioning
            .confirm(id, self.general.id())?;
        if let Err(error) = self.send_success(request).await {
            self.terminate_forward(id, ProvisioningFailure::DeliveryFailed)
                .await;
            return Err(error);
        }
        Ok(())
    }

    async fn relay_credential(&self, request: &CommunicationValue) -> Result<(), &'static str> {
        let session =
            authorize_qr_credential(&self.general.state.provisioning, self.general.id(), request)?;
        let Some(contact) = session.contact.and_then(|contact| contact.sender.upgrade()) else {
            self.terminate_forward(session.id, ProvisioningFailure::PeerDisconnected)
                .await;
            return Err("contact disconnected");
        };
        self.general
            .state
            .provisioning
            .delivered(session.id, self.general.id())
            .map_err(|_| "session expired")?;
        if contact.send(request).await.is_err() {
            self.terminate_forward(session.id, ProvisioningFailure::DeliveryFailed)
                .await;
            return Err("credential delivery failed");
        }
        Ok(())
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
        let response = match self.password_forward(request, &session, ke1).await {
            Ok(response) => response,
            Err(error) => {
                self.terminate_forward(id, ProvisioningFailure::UpstreamUnavailable)
                    .await;
                return Err(error);
            }
        };
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
            self.terminate_forward(id, ProvisioningFailure::InvalidUpstreamResponse)
                .await;
            return Err("invalid Iota KE2");
        }
        if self.sender.send(&response).await.is_err() {
            self.terminate_forward(id, ProvisioningFailure::DeliveryFailed)
                .await;
            return Err("send failed");
        }
        Ok(())
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
        let response = match self.password_forward(request, &session, ke3).await {
            Ok(response) => response,
            Err(error) => {
                self.terminate_forward(id, ProvisioningFailure::UpstreamRejected)
                    .await;
                return Err(error);
            }
        };
        if !response.is_type(CommunicationType::ProvisioningCredential)
            || response.receiver() != Some(self.general.id())
            || response.payload().as_encrypted().is_none()
        {
            self.terminate_forward(id, ProvisioningFailure::InvalidUpstreamResponse)
                .await;
            return Err("Iota did not authorize the credential");
        }
        self.general
            .state
            .provisioning
            .password_delivered(id, self.general.id())
            .map_err(|_| "session expired")?;
        if self.sender.send(&response).await.is_err() {
            self.terminate_forward(id, ProvisioningFailure::DeliveryFailed)
                .await;
            return Err("send failed");
        }
        Ok(())
    }

    async fn password_forward(
        &self,
        request: &CommunicationValue,
        session: &ProvisioningSession,
        opaque: Vec<u8>,
    ) -> Result<CommunicationValue, &'static str> {
        let account = session.account.as_ref().ok_or("account not bound")?;
        let rho = self
            .general
            .state
            .rho
            .get_by_iota(account.iota_id)
            .await
            .ok_or("Iota unavailable")?;
        let message = build_password_iota_request(request, session, opaque)?;
        rho.get_iota_connection()
            .clone()
            .await_response(&message, Some(Duration::from_secs(30)))
            .await
            .map_err(|_| "Iota request failed")
    }
}

fn authorize_qr_credential(
    manager: &ProvisioningManager,
    participant_id: u64,
    request: &CommunicationValue,
) -> Result<ProvisioningSession, &'static str> {
    let session = manager.for_participant(participant_id)?;
    let recipient = request.receiver().ok_or("missing recipient")?;
    // The relay never opens the Owner-to-Contact encrypted credential.
    if request.payload().as_encrypted().is_none() {
        return Err("credential is not protected");
    }
    manager
        .authorize_delivery(session.id, participant_id, recipient)
        .map_err(Into::into)
}

fn build_password_iota_request(
    request: &CommunicationValue,
    session: &ProvisioningSession,
    opaque: Vec<u8>,
) -> Result<CommunicationValue, &'static str> {
    let account = session.account.as_ref().ok_or("account not bound")?;
    let contact = session.contact.as_ref().ok_or("contact not present")?;
    Ok(
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
            .add_typed_default(DataType::OpaqueMessage, DataValue::Bytes(opaque)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provisioning::session::{
        ProvisioningMethod, ProvisioningParticipant, ProvisioningRole, ProvisioningState,
        ResolvedAccount,
    };
    use crate::rho::connection::OptionalDataValueCompat;
    use mtp::crypto::Keyring;
    use mtp::{codec::ProtectedMessageBuilder, crypto::DualSigner};
    use std::{sync::Weak, time::Instant};

    #[tokio::test]
    async fn join_and_bind_send_peer_first_and_attempt_only_one_requester_response() {
        for (kind, request_id) in [
            (CommunicationType::ProvisioningPeerJoined, 42),
            (CommunicationType::ProvisioningAccountBound, 73),
        ] {
            for failure in [
                None,
                Some(DeliveryFailure::Peer),
                Some(DeliveryFailure::Requester),
            ] {
                let attempts = Arc::new(std::sync::Mutex::new(Vec::new()));
                let event = CommunicationValue::new(kind);
                let event_id = event.id();
                let response = CommunicationValue::new(kind).with_id(request_id);
                let peer_attempts = attempts.clone();
                let requester_attempts = attempts.clone();
                let fail_peer = failure == Some(DeliveryFailure::Peer);
                let fail_requester = failure == Some(DeliveryFailure::Requester);
                let result = deliver_peer_then_reply(
                    event,
                    response,
                    move |message| async move {
                        peer_attempts.lock().unwrap().push(("peer", message.id()));
                        !fail_peer
                    },
                    move |message| async move {
                        requester_attempts
                            .lock()
                            .unwrap()
                            .push(("requester", message.id()));
                        !fail_requester
                    },
                )
                .await;
                assert_eq!(result.err(), failure);
                let attempts = attempts.lock().unwrap();
                assert_eq!(attempts[0], ("peer", event_id));
                assert_eq!(attempts.len(), if fail_peer { 1 } else { 2 });
                if !fail_peer {
                    assert_eq!(attempts[1], ("requester", Some(request_id)));
                }
            }
        }
    }

    #[test]
    fn join_and_bind_replies_use_request_ids() {
        let id = Uuid::new_v4();
        let participant = ProvisioningParticipant {
            id: 2,
            role: ProvisioningRole::Contact,
            temporary_public_key: Keyring::generate().public_key_bundle(),
            sender: Weak::new(),
        };
        let event = peer_joined_message(id, &participant, None).unwrap();
        let response = peer_joined_message(id, &participant, Some(42)).unwrap();
        assert!(event.id().is_some());
        assert_eq!(response.id(), Some(42));
        assert!(event.is_type(CommunicationType::ProvisioningPeerJoined));

        let account = ResolvedAccount {
            user_id: 7,
            username: "alice".into(),
            iota_id: 11,
            principal: "principal".into(),
            public_key: Keyring::generate().public_key_bundle(),
        };
        let encoded = account.public_key.try_to_base64().unwrap();
        let event = account_bound_message(id, &account, &encoded, None);
        let response = account_bound_message(id, &account, &encoded, Some(73));
        assert!(event.id().is_some());
        assert_eq!(response.id(), Some(73));
        assert!(event.is_type(CommunicationType::ProvisioningAccountBound));
    }

    #[test]
    fn terminated_join_or_bind_releases_both_participant_mappings() {
        for bound in [false, true] {
            let manager = ProvisioningManager::new(Duration::from_secs(60), 2);
            let participant = |id, role| ProvisioningParticipant {
                id,
                role,
                temporary_public_key: Keyring::generate().public_key_bundle(),
                sender: Weak::new(),
            };
            let id = manager
                .create(
                    ProvisioningMethod::QrOwnerCreated,
                    participant(1, ProvisioningRole::Owner),
                )
                .unwrap();
            manager
                .join(id, participant(2, ProvisioningRole::Contact))
                .unwrap();
            if bound {
                manager
                    .bind(
                        id,
                        1,
                        ResolvedAccount {
                            user_id: 7,
                            username: "alice".into(),
                            iota_id: 11,
                            principal: "principal".into(),
                            public_key: Keyring::generate().public_key_bundle(),
                        },
                    )
                    .unwrap();
            }
            manager
                .fail_forward(id, 2, ProvisioningFailure::DeliveryFailed)
                .unwrap();
            assert!(manager.for_participant(1).is_err());
            assert!(manager.for_participant(2).is_err());
            assert!(manager.snapshot(id, 1).is_err());
            assert!(
                manager
                    .create(
                        ProvisioningMethod::QrOwnerCreated,
                        participant(1, ProvisioningRole::Owner)
                    )
                    .is_ok()
            );
        }
    }

    #[test]
    fn forged_client_metadata_does_not_override_session() {
        let contact_key = Keyring::generate().public_key_bundle();
        let session = ProvisioningSession {
            id: Uuid::new_v4(),
            method: ProvisioningMethod::Password,
            contact: Some(ProvisioningParticipant {
                id: 300,
                role: ProvisioningRole::Contact,
                temporary_public_key: contact_key.clone(),
                sender: Weak::new(),
            }),
            owner: None,
            account: Some(ResolvedAccount {
                user_id: 100,
                username: "user".into(),
                principal: "principal".into(),
                iota_id: 200,
                public_key: Keyring::generate().public_key_bundle(),
            }),
            state: ProvisioningState::AccountBound,
            owner_confirmed: false,
            created_at: Instant::now(),
        };
        let request = CommunicationValue::new(CommunicationType::PasswordProvisioningStart)
            .with_id(42)
            .add_typed_default(DataType::UserId, DataValue::SignedNumber(999))
            .add_typed_default(DataType::IotaId, DataValue::SignedNumber(999))
            .add_typed_default(
                DataType::ProvisioningParticipantId,
                DataValue::UnsignedNumber(999),
            )
            .add_typed_default(
                DataType::PublicKey,
                DataValue::Str(
                    Keyring::generate()
                        .public_key_bundle()
                        .try_to_base64()
                        .unwrap(),
                ),
            );
        let forwarded = build_password_iota_request(&request, &session, vec![1, 2]).unwrap();
        assert_eq!(forwarded.get_data(DataType::UserId).as_number(), Some(100));
        assert_eq!(forwarded.get_data(DataType::IotaId).as_number(), Some(200));
        assert_eq!(
            forwarded
                .get_data(DataType::ProvisioningParticipantId)
                .as_number(),
            Some(300)
        );
        assert_eq!(
            forwarded.get_data(DataType::PublicKey).as_str(),
            Some(contact_key.try_to_base64().unwrap().as_str())
        );
    }

    #[test]
    fn qr_credential_relay_requires_protection_recipient_and_owner_confirmation() {
        let owner = Keyring::generate();
        let contact = Keyring::generate();
        let signer = DualSigner::new(
            &owner.sig_cl_secret_key,
            &owner.sig_pq_secret_key,
            &owner.sig_pq_public_key,
        )
        .unwrap();
        for method in [
            ProvisioningMethod::QrContactCreated,
            ProvisioningMethod::QrOwnerCreated,
        ] {
            let manager = ProvisioningManager::new(Duration::from_secs(60), 2);
            let participant = |id, role, key: &Keyring| ProvisioningParticipant {
                id,
                role,
                temporary_public_key: key.public_key_bundle(),
                sender: Weak::new(),
            };
            let id = match method {
                ProvisioningMethod::QrContactCreated => {
                    let id = manager
                        .create(method, participant(2, ProvisioningRole::Contact, &contact))
                        .unwrap();
                    manager
                        .join(id, participant(1, ProvisioningRole::Owner, &owner))
                        .unwrap();
                    id
                }
                ProvisioningMethod::QrOwnerCreated => {
                    let id = manager
                        .create(method, participant(1, ProvisioningRole::Owner, &owner))
                        .unwrap();
                    manager
                        .join(id, participant(2, ProvisioningRole::Contact, &contact))
                        .unwrap();
                    id
                }
                ProvisioningMethod::Password => unreachable!(),
            };
            manager
                .bind(
                    id,
                    1,
                    ResolvedAccount {
                        user_id: 100,
                        username: "owner".into(),
                        principal: "omega-key:example#100".into(),
                        iota_id: 200,
                        public_key: owner.public_key_bundle(),
                    },
                )
                .unwrap();

            let clear = CommunicationValue::new(CommunicationType::ProvisioningCredential)
                .with_id(42)
                .with_receiver(2);
            assert!(authorize_qr_credential(&manager, 1, &clear).is_err());

            let protected = ProtectedMessageBuilder::new(
                CommunicationType::ProvisioningCredential,
                DataValue::Bytes(vec![1, 2, 3]),
                1,
                2,
                &signer,
                crate::app_protection::purpose(
                    crate::app_protection::PROVISIONING_CREDENTIAL_SIGNATURE,
                ),
                crate::app_protection::purpose(
                    crate::app_protection::PROVISIONING_CREDENTIAL_ENCRYPTION,
                ),
            )
            .message_id(u128::from(id.as_u128() as u64))
            .created_at(1)
            .recipients(vec![contact.public_key_bundle()])
            .frame_id(42)
            .build()
            .unwrap();
            let original_payload = protected.payload().clone();
            assert!(protected.payload().as_encrypted().is_some());
            assert!(
                authorize_qr_credential(&manager, 1, &protected.clone().with_receiver(3)).is_err()
            );
            if method == ProvisioningMethod::QrOwnerCreated {
                assert!(authorize_qr_credential(&manager, 1, &protected).is_err());
                manager.confirm(id, 1).unwrap();
            }
            authorize_qr_credential(&manager, 1, &protected).unwrap();
            assert_eq!(protected.payload(), &original_payload);
            manager.delivered(id, 1).unwrap();
        }
    }

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
