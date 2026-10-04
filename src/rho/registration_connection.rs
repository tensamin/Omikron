use crate::{
    log_cv_in, log_cv_out, log_err,
    rho::connection::{
        GeneralConnection, MtpReceiver, MtpSender, OptionalDataValueCompat, RequiredMtpFields,
    },
    util::logger::PrintType,
};
use mtp::{
    codec::{CommunicationType, CommunicationValue, DataType, DataValue, ProtectionPolicy},
    crypto::PublicKeyBundle,
};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

struct PendingRegistration {
    invitation_id: i64,
    iota_id: i64,
    user_id: i64,
    public_key: PublicKeyBundle,
    challenge: Option<u64>,
}

struct RegistrationUpgrade {
    user_id: i64,
    request_id: u32,
}

fn is_registration_operation(value: &CommunicationValue) -> bool {
    matches!(
        value.get_comm_type_enum(),
        Some(
            CommunicationType::RedeemUserInvitation
                | CommunicationType::GetUserInvitationStatus
                | CommunicationType::RegisteringClientAuthenticate
        )
    )
}

pub struct RegistrationConnection {
    general: Arc<GeneralConnection>,
    sender: Arc<MtpSender>,
    receiver: Arc<MtpReceiver>,
    pending: Mutex<Option<PendingRegistration>>,
    last_redemption_attempt: Mutex<Option<Instant>>,
}

impl RegistrationConnection {
    pub fn from_general(general: Arc<GeneralConnection>) -> Arc<Self> {
        Arc::new(Self {
            sender: general.sender.clone(),
            receiver: general.receiver.clone(),
            general,
            pending: Mutex::new(None),
            last_redemption_attempt: Mutex::new(None),
        })
    }

    pub async fn start(self: Arc<Self>) {
        while let Ok(value) = self.receiver.receive().await {
            if let Some(upgrade) = self.clone().handle_message(value).await {
                let Some(client) = self
                    .general
                    .clone()
                    .attach_registered_client(upgrade.user_id as u64)
                    .await
                else {
                    self.send_error(upgrade.request_id, "activation_route_unavailable")
                        .await;
                    continue;
                };
                self.pending.lock().await.take();
                self.send(
                    CommunicationValue::new(CommunicationType::Success)
                        .with_id(upgrade.request_id)
                        .add_typed_default(
                            DataType::UserId,
                            DataValue::SignedNumber(upgrade.user_id.into()),
                        ),
                )
                .await;
                client.start();
                return;
            }
        }
    }

    async fn handle_message(
        self: Arc<Self>,
        value: CommunicationValue,
    ) -> Option<RegistrationUpgrade> {
        let request_id = match value.require_id() {
            Ok(request_id) => request_id,
            Err(_) => {
                self.send(
                    CommunicationValue::new(CommunicationType::ErrorInvalidData).without_id(),
                )
                .await;
                return None;
            }
        };
        log_cv_in!(PrintType::Client, &value);
        if !is_registration_operation(&value) {
            self.send_error(
                request_id,
                "registration connections only accept invitation redemption",
            )
            .await;
            return None;
        }
        match value.get_comm_type_enum() {
            Some(CommunicationType::RedeemUserInvitation) => self.redeem(value).await,
            Some(CommunicationType::GetUserInvitationStatus) => self.status(value).await,
            Some(CommunicationType::RegisteringClientAuthenticate) => self.activate(value).await,
            _ => {
                self.send_error(request_id, "unknown registration operation")
                    .await
            }
        }
    }

    async fn redeem(self: &Arc<Self>, value: CommunicationValue) -> Option<RegistrationUpgrade> {
        let mut last_attempt = self.last_redemption_attempt.lock().await;
        if let Some(previous) = *last_attempt {
            let elapsed = previous.elapsed();
            if elapsed < Duration::from_secs(1) {
                tokio::time::sleep(Duration::from_secs(1) - elapsed).await;
            }
        }
        *last_attempt = Some(Instant::now());
        drop(last_attempt);
        let request_id = value.id().unwrap_or_default();
        let invitation_id = signed_i64(&value, DataType::InvitationId);
        let iota_id = signed_i64(&value, DataType::IotaId);
        let public_key = value
            .get_data(DataType::PublicKey)
            .as_str()
            .and_then(|encoded| PublicKeyBundle::from_base64(encoded).ok());
        let Some((invitation_id, iota_id, public_key)) = invitation_id
            .zip(iota_id)
            .zip(public_key)
            .map(|((invitation, iota), key)| (invitation, iota, key))
        else {
            self.send_error(request_id, "invalid invitation target or public key")
                .await;
            return None;
        };
        let response = self
            .general
            .state
            .omega
            .await_response(&value, Some(Duration::from_secs(20)))
            .await;
        match response {
            Ok(response) if response.is_type(CommunicationType::RedeemUserInvitation) => {
                let Some(user_id) = signed_i64(&response, DataType::UserId) else {
                    self.send_error(request_id, "Omega omitted the provisioned user ID")
                        .await;
                    return None;
                };
                *self.pending.lock().await = Some(PendingRegistration {
                    invitation_id,
                    iota_id,
                    user_id,
                    public_key,
                    challenge: None,
                });
                self.send(response).await;
            }
            Ok(response) => self.send(response).await,
            Err(error) => {
                log_err!(
                    0,
                    PrintType::Omega,
                    "Invitation redemption failed: {}",
                    error
                );
                self.send_error(request_id, "Omega invitation redemption failed")
                    .await;
            }
        }
        None
    }

    async fn status(self: &Arc<Self>, value: CommunicationValue) -> Option<RegistrationUpgrade> {
        let request_id = value.id().unwrap_or_default();
        let target = {
            let pending = self.pending.lock().await;
            pending
                .as_ref()
                .map(|pending| (pending.invitation_id, pending.iota_id))
        };
        let Some((invitation_id, iota_id)) = target else {
            self.send_error(request_id, "redemption has not started")
                .await;
            return None;
        };
        if signed_i64(&value, DataType::InvitationId) != Some(invitation_id)
            || signed_i64(&value, DataType::IotaId) != Some(iota_id)
        {
            self.send_error(request_id, "invitation status target mismatch")
                .await;
            return None;
        }
        match self
            .general
            .state
            .omega
            .await_response(&value, Some(Duration::from_secs(20)))
            .await
        {
            Ok(response)
                if response.get_data(DataType::InvitationState).as_str() == Some("redeemed") =>
            {
                let mut pending_guard = self.pending.lock().await;
                let pending = pending_guard.as_mut()?;
                let challenge = rand::random::<u64>().max(1);
                pending.challenge = Some(challenge);
                let response = response.add_typed_default(
                    DataType::ServerNonce,
                    DataValue::SignedNumber(challenge.into()),
                );
                drop(pending_guard);
                self.send(response).await;
            }
            Ok(response) => self.send(response).await,
            Err(error) => {
                log_err!(0, PrintType::Omega, "Invitation status failed: {}", error);
                self.send_error(request_id, "Omega invitation status failed")
                    .await;
            }
        }
        None
    }

    async fn activate(self: &Arc<Self>, value: CommunicationValue) -> Option<RegistrationUpgrade> {
        let request_id = value.id().unwrap_or_default();
        let signed = value
            .get_data(DataType::Signed)
            .as_bytes()
            .and_then(|bytes| DataValue::from_bytes(&bytes));
        let nonce = value
            .get_data(DataType::ServerNonce)
            .as_signed_number()
            .and_then(|value| u64::try_from(value).ok());
        let pending = self.pending.lock().await;
        let Some(registration) = pending.as_ref() else {
            drop(pending);
            self.send_error(request_id, "redemption has not started")
                .await;
            return None;
        };
        let Some((nonce, signed)) = nonce.zip(signed) else {
            drop(pending);
            self.send_error(request_id, "missing activation challenge response")
                .await;
            return None;
        };
        if registration.challenge != Some(nonce)
            || signed_i64(&value, DataType::UserId) != Some(registration.user_id)
        {
            drop(pending);
            self.send_error(request_id, "activation challenge mismatch")
                .await;
            return None;
        }
        let payload = activation_payload(
            registration.user_id,
            registration.iota_id,
            registration.invitation_id,
            nonce,
        );
        if signed
            .verify_with_policy(
                registration.user_id as u64,
                &registration.public_key,
                crate::app_protection::purpose(crate::app_protection::REGISTRATION_ACTIVATION),
                ProtectionPolicy::dual(),
            )
            .is_err()
            || signed.as_signed().map(|value| value.value.as_ref())
                != Some(&DataValue::Bytes(payload))
        {
            drop(pending);
            self.send_error(request_id, "activation signature is invalid")
                .await;
            return None;
        }
        Some(RegistrationUpgrade {
            user_id: registration.user_id,
            request_id,
        })
    }

    async fn send(&self, value: CommunicationValue) {
        log_cv_out!(PrintType::Client, &value);
        let _ = self.sender.send(&value).await;
    }

    async fn send_error(&self, request_id: u32, message: &str) -> Option<RegistrationUpgrade> {
        self.send(
            CommunicationValue::new(CommunicationType::ErrorNotAuthenticated)
                .with_id(request_id)
                .add_typed_default(DataType::ErrorType, DataValue::Str(message.into())),
        )
        .await;
        None
    }
}

fn signed_i64(value: &CommunicationValue, data_type: DataType) -> Option<i64> {
    value
        .get_data(data_type)
        .as_signed_number()
        .and_then(|value| i64::try_from(value).ok())
}

fn activation_payload(user_id: i64, iota_id: i64, invitation_id: i64, nonce: u64) -> Vec<u8> {
    let mut payload = b"tensamin:invitation-activate:v1\0".to_vec();
    payload.extend_from_slice(&user_id.to_be_bytes());
    payload.extend_from_slice(&iota_id.to_be_bytes());
    payload.extend_from_slice(&invitation_id.to_be_bytes());
    payload.extend_from_slice(&nonce.to_be_bytes());
    payload
}

#[cfg(test)]
mod tests {
    use super::{activation_payload, is_registration_operation};
    use mtp::codec::{CommunicationType, CommunicationValue};

    #[test]
    fn activation_payload_binds_account_and_invitation() {
        assert_ne!(
            activation_payload(1, 2, 3, 4),
            activation_payload(1, 2, 5, 4)
        );
        assert_ne!(
            activation_payload(1, 2, 3, 4),
            activation_payload(1, 2, 3, 5)
        );
    }

    #[test]
    fn registering_clients_cannot_manage_invitations() {
        for operation in [
            CommunicationType::CreateUserInvitation,
            CommunicationType::ListUserInvitations,
            CommunicationType::RevokeUserInvitation,
        ] {
            assert!(!is_registration_operation(&CommunicationValue::new(
                operation
            )));
        }
    }
}
