mod password;
mod qr;
#[cfg(test)]
use password::build_password_iota_request;
pub(crate) use password::handle_authenticated_login;
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

async fn bounded_send(sender: &MtpSender, value: &CommunicationValue) -> Result<(), &'static str> {
    tokio::time::timeout(Duration::from_secs(10), sender.send(value))
        .await
        .map_err(|_| "provisioning delivery timed out")?
        .map_err(|_| "provisioning delivery failed")
}

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
            let notification = CommunicationValue::new(CommunicationType::ProvisioningCancel)
                .with_id(rand::random::<u32>().max(1))
                .add_typed_default(DataType::Uuid, DataValue::Str(id.to_string()));
            let _ = tokio::time::timeout(
                self.general.state.config.message_drain,
                sender.send(&notification),
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
                DataType::Uuid,
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
        let tasks = super::tasks::MessageTasks::new(
            self.general.shutdown.subscribe(),
            self.general.state.config.message_drain,
        );
        while let Some(Ok(request)) = tasks
            .while_connected(&self.receiver, self.receiver.receive())
            .await
        {
            let Some(id) = request.id() else {
                let _ = bounded_send(
                    &self.sender,
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
                let _ = bounded_send(
                    &self.sender,
                    &CommunicationValue::new(error_kind).with_id(id),
                )
                .await;
                continue;
            }
            // Binding and upstream credential operations are not disposable.
            // Local session termination runs after observing their results.
            let result = async {
                let result: Result<(), ProvisioningOperationError> = match request
                    .get_comm_type_enum()
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
                result
            }
            .await;
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
                    let _ = bounded_send(&self.sender, &error).await;
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
        self.sender.close();
        if let Ok(session) = self
            .general
            .state
            .provisioning
            .for_participant(self.general.id())
        {
            let _ = tokio::time::timeout(
                self.general.state.config.cleanup_timeout,
                self.terminate_forward(session.id, ProvisioningFailure::PeerDisconnected),
            )
            .await;
        }
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

    async fn send_success(&self, request: &CommunicationValue) -> Result<(), &'static str> {
        bounded_send(
            &self.sender,
            &CommunicationValue::new(CommunicationType::Success)
                .with_id(request.id().ok_or("missing request ID")?),
        )
        .await
        .map_err(|_| "send failed")
    }
}

pub(crate) fn authorize_qr_credential(
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

#[cfg(test)]
mod tests;
