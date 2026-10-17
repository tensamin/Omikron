use crate::{
    log_cv_in, log_cv_out, log_err,
    rho::connection::{
        GeneralConnection, MtpReceiver, MtpSender, OmikronIdentity, OptionalDataValueExt,
        RequiredCommunicationFields,
    },
    util::logger::PrintType,
};
use mtp::{
    codec::{CommunicationType, CommunicationValue, DataType, DataValue, ProtectionPolicy},
    crypto::PublicKeyBundle,
};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tau::data_i64 as signed_i64;
use tokio::sync::Mutex;

struct PendingRegistration {
    invitation_id: i64,
    iota_id: i64,
    user_id: i64,
    public_key: PublicKeyBundle,
    challenge: Option<u64>,
    journal_operation: Option<String>,
}

struct RegistrationUpgrade {
    user_id: i64,
    iota_id: i64,
    request_id: u32,
    verified: tau::VerifiedApplicationAuthentication<OmikronIdentity>,
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
    #[cfg(test)]
    before_success: Mutex<
        Option<(
            tokio::sync::oneshot::Sender<()>,
            tokio::sync::oneshot::Receiver<()>,
        )>,
    >,
}

impl RegistrationConnection {
    pub fn from_general(general: Arc<GeneralConnection>) -> Arc<Self> {
        Arc::new(Self {
            sender: general.sender.clone(),
            receiver: general.receiver.clone(),
            general,
            pending: Mutex::new(None),
            last_redemption_attempt: Mutex::new(None),
            #[cfg(test)]
            before_success: Mutex::new(None),
        })
    }

    pub async fn start(self: Arc<Self>) {
        let tasks = super::tasks::MessageTasks::new(
            self.general.shutdown.subscribe(),
            self.general.state.config.message_drain,
        );
        while let Some(Ok(value)) = tasks
            .while_connected(&self.receiver, self.receiver.receive())
            .await
        {
            // Omega may already have committed redemption. Observe its bounded
            // result before discarding connection-local challenge state.
            let upgrade = self.clone().handle_message(value).await;
            if let Some(upgrade) = upgrade {
                let Some(prepared) = tasks
                    .while_connected(
                        &self.receiver,
                        self.general.prepare_registered_client(
                            upgrade.user_id as u64,
                            upgrade.iota_id as u64,
                        ),
                    )
                    .await
                else {
                    break;
                };
                let Some((client, rho, generation)) = prepared else {
                    self.send_error(upgrade.request_id, "activation_route_unavailable")
                        .await;
                    continue;
                };
                // All awaits finish before the logical commit. The current route and
                // session entry remain locked only during synchronous publication.
                let mutation = self.general.state.rho.mutation_guard().await;
                let mut route = self.general.rho_connection.write().await;
                let mut session = self.general.tau_session.write().await;
                let mut pending = self.pending.lock().await;
                if self.receiver.close_reason().is_some() || *self.general.shutdown.borrow() {
                    return;
                }
                let result = self.general.state.rho.attach_registered_client(
                    &mutation,
                    &rho,
                    generation,
                    client.clone(),
                    || session.authenticate_application(upgrade.verified),
                );
                if result.is_err() {
                    drop(session);
                    drop(route);
                    drop(pending);
                    drop(mutation);
                    self.send_error(
                        upgrade.request_id,
                        "activation_session_or_attachment_rejected",
                    )
                    .await;
                    continue;
                }
                let iota_id = rho.iota_id();
                *route = Some(rho);
                self.general
                    .set_active_handler(crate::rho::connection::ConnectionKind::Client);
                if let Some(id) = pending
                    .as_ref()
                    .and_then(|pending| pending.journal_operation.as_deref())
                    && let Err(error) = self.general.state.omega.finish_redemption_publication(id)
                {
                    log_err!(
                        upgrade.user_id,
                        PrintType::Client,
                        "Activation publication recovery marker failed: {}",
                        error
                    );
                }
                drop(session);
                drop(route);
                pending.take();
                drop(pending);
                drop(mutation);
                #[cfg(test)]
                {
                    let barrier = self.before_success.lock().await.take();
                    if let Some((reached, resume)) = barrier {
                        let _ = reached.send(());
                        let _ = resume.await;
                    }
                }
                let response = CommunicationValue::new(CommunicationType::Success)
                    .with_id(upgrade.request_id)
                    .add_typed_default(
                        DataType::UserId,
                        DataValue::SignedNumber(upgrade.user_id.into()),
                    );
                if !matches!(
                    tokio::time::timeout(
                        self.general.state.config.message_drain,
                        self.sender.send(&response)
                    )
                    .await,
                    Ok(Ok(()))
                ) {
                    client.close().await;
                    client.clone().handle_close().await;
                    self.pending.lock().await.take();
                    self.general.tau_session.write().await.close();
                    return;
                }
                client.notify_connected(iota_id);
                client.run().await;
                return;
            }
        }
        self.pending.lock().await.take();
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
        let invitation_id = signed_i64(&value, DataType::InvitationId).filter(|id| *id > 0);
        let iota_id = signed_i64(&value, DataType::IotaId).filter(|id| *id > 0);
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
                let Some(user_id) = signed_i64(&response, DataType::UserId).filter(|id| *id > 0)
                else {
                    self.send_error(request_id, "Omega omitted the provisioned user ID")
                        .await;
                    return None;
                };
                let mut pending = self.pending.lock().await;
                let journal_operation = match self
                    .general
                    .state
                    .omega
                    .redemption_publication(&value, "pending")
                {
                    Ok(id) => id,
                    Err(error) => {
                        drop(pending);
                        log_err!(
                            user_id,
                            PrintType::Omega,
                            "Redemption publication marker failed: {}",
                            error
                        );
                        self.send_error(request_id, "redemption publication requires recovery")
                            .await;
                        return None;
                    }
                };
                *pending = Some(PendingRegistration {
                    invitation_id,
                    iota_id,
                    user_id,
                    public_key,
                    challenge: None,
                    journal_operation,
                });
                drop(pending);
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
        let pending = self.pending.lock().await;
        let Some(registration) = pending.as_ref() else {
            drop(pending);
            return self
                .send_error(request_id, "redemption has not started")
                .await;
        };
        let user_id = registration.user_id;
        let iota_id = registration.iota_id;
        let session = self.general.tau_session.read().await;
        let verified = session
            .verify_application(&value, |_context, request| async move {
                verify_activation(registration, request)
            })
            .await;
        drop(session);
        drop(pending);
        match verified {
            Ok(verified) => Some(RegistrationUpgrade {
                user_id,
                iota_id,
                request_id,
                verified,
            }),
            Err(error) => self.send_error(request_id, error).await,
        }
    }

    async fn send(&self, value: CommunicationValue) {
        log_cv_out!(PrintType::Client, &value);
        if self.receiver.close_reason().is_none() && !*self.general.shutdown.borrow() {
            let _ = tokio::time::timeout(
                self.general.state.config.message_drain,
                self.sender.send(&value),
            )
            .await;
        }
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

/// Invalid proofs and unavailable routes retain the challenge for a retry on this
/// connection. Only committed activation consumes it; the client handler cannot
/// execute registration operations again.
fn verify_activation(
    registration: &PendingRegistration,
    value: &CommunicationValue,
) -> Result<OmikronIdentity, &'static str> {
    let signed = value
        .get_data(DataType::Signed)
        .as_bytes()
        .and_then(|bytes| DataValue::from_bytes(&bytes));
    let nonce = value
        .get_data(DataType::ServerNonce)
        .as_signed_number()
        .and_then(|value| u64::try_from(value).ok());
    let Some((nonce, signed)) = nonce.zip(signed) else {
        return Err("missing activation challenge response");
    };
    if registration.challenge != Some(nonce)
        || signed_i64(value, DataType::UserId) != Some(registration.user_id)
    {
        return Err("activation challenge mismatch");
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
        || signed.as_signed().map(|value| value.value.as_ref()) != Some(&DataValue::Bytes(payload))
    {
        return Err("activation signature is invalid");
    }
    Ok(OmikronIdentity::Client(registration.user_id as u64))
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
    #[tokio::test]
    async fn lost_redemption_reply_reconciles_on_reconnect_without_redeeming_again() {
        use crate::rho::{
            connection::{GeneralConnection, admission_engine},
            test_support,
        };
        use mtp::codec::{DataType, DataValue};
        use mtp::crypto::Keyring;
        use std::time::Duration;
        for matching_key in [true, false] {
            let state = test_support::state();
            let mut omega = state.omega.test_requests();
            let keys = Keyring::generate();
            let public_key = keys.public_key_bundle().try_to_base64().unwrap();
            let request = CommunicationValue::new(CommunicationType::RedeemUserInvitation)
                .with_id(41)
                .add_typed_default(DataType::InvitationId, DataValue::SignedNumber(3))
                .add_typed_default(DataType::IotaId, DataValue::SignedNumber(2))
                .add_typed_default(DataType::PublicKey, DataValue::Str(public_key.clone()));
            let (host, peer, transport) = test_support::guest("registering-client").await;
            let general =
                GeneralConnection::admit(transport, state.clone(), &admission_engine()).unwrap();
            let registration = super::RegistrationConnection::from_general(general);
            let first = tokio::spawn({
                let request = request.clone();
                async move { registration.handle_message(request).await }
            });
            let (sent, reply) = omega.recv().await.unwrap();
            assert!(sent.is_type(CommunicationType::RedeemUserInvitation));
            reply
                .send(Err("response lost after authoritative commit".into()))
                .unwrap();
            first.await.unwrap();
            peer.sender.close().await;
            host.shutdown().await;

            let (host, peer, transport) = test_support::guest("registering-client").await;
            let general =
                GeneralConnection::admit(transport, state.clone(), &admission_engine()).unwrap();
            let registration = super::RegistrationConnection::from_general(general);
            let second = tokio::spawn({
                let registration = registration.clone();
                let request = request.clone().with_id(42);
                async move { registration.handle_message(request).await }
            });
            let (status, reply) = omega.recv().await.unwrap();
            assert!(status.is_type(CommunicationType::GetUserInvitationStatus));
            reply
                .send(Ok(status
                    .add_typed_default(DataType::UserId, DataValue::SignedNumber(7))
                    .add_typed_default(
                        DataType::InvitationState,
                        DataValue::Str("redeemed".into()),
                    )))
                .unwrap();
            let (account, reply) = omega.recv().await.unwrap();
            assert!(account.is_type(CommunicationType::GetUserData));
            let registered_key = if matching_key {
                public_key
            } else {
                Keyring::generate()
                    .public_key_bundle()
                    .try_to_base64()
                    .unwrap()
            };
            reply
                .send(Ok(account.add_typed_default(
                    DataType::PublicKey,
                    DataValue::Str(registered_key),
                )))
                .unwrap();
            second.await.unwrap();
            let response = tokio::time::timeout(Duration::from_secs(2), peer.receive())
                .await
                .unwrap()
                .unwrap();
            let pending = registration.pending.lock().await;
            if matching_key {
                assert!(response.is_type(CommunicationType::RedeemUserInvitation));
                let pending = pending.as_ref().unwrap();
                assert_eq!(pending.user_id, 7);
                assert!(pending.journal_operation.is_some());
            } else {
                assert!(response.is_type(CommunicationType::ErrorNotAuthenticated));
                assert!(pending.is_none());
            }
            drop(pending);
            peer.sender.close().await;
            host.shutdown().await;
        }
    }

    use super::{activation_payload, is_registration_operation};
    use mtp::codec::{CommunicationType, CommunicationValue};

    fn proof(keys: &mtp::crypto::Keyring, user_id: i64, nonce: u64) -> CommunicationValue {
        use mtp::{
            codec::{DataType, DataValue},
            crypto::DualSigner,
        };
        let signer = DualSigner::new(
            &keys.sig_cl_secret_key,
            &keys.sig_pq_secret_key,
            &keys.sig_pq_public_key,
        )
        .unwrap();
        let signed = DataValue::Bytes(activation_payload(user_id, 2, 3, nonce))
            .sign(
                user_id as u64,
                crate::app_protection::purpose(crate::app_protection::REGISTRATION_ACTIVATION),
                &signer,
            )
            .unwrap();
        CommunicationValue::new(CommunicationType::RegisteringClientAuthenticate)
            .with_id(12)
            .add_typed_default(DataType::UserId, DataValue::SignedNumber(user_id.into()))
            .add_typed_default(DataType::ServerNonce, DataValue::SignedNumber(nonce.into()))
            .add_typed_default(
                DataType::Signed,
                DataValue::Bytes(signed.to_bytes().unwrap()),
            )
    }

    #[tokio::test]
    async fn registration_protocol_stages_failures_and_runs_the_client_on_success() {
        use super::RegistrationConnection;
        use crate::rho::{
            client_connection::ClientConnection,
            connection::{ConnectionKind, GeneralConnection, OmikronIdentity, admission_engine},
            iota_connection::IotaConnection,
            rho_connection::RhoConnection,
            test_support,
        };
        use mtp::{
            codec::{DataType, DataValue},
            crypto::Keyring,
        };
        use std::{sync::Arc, time::Duration};
        for scenario in [
            "success",
            "rho-unavailable",
            "attachment-occupied",
            "session-closed",
            "disconnect-during-lookup",
            "disconnect-before-response",
        ] {
            let state = test_support::state();
            let mut omega = state.omega.test_requests();
            let (host, client, connection) = test_support::guest("registering-client").await;
            let general =
                GeneralConnection::admit(connection, state.clone(), &admission_engine()).unwrap();
            let connection_id = general.tau_session.read().await.connection_id();
            let session_id = *general.session_id.read().await;
            general.tau_session.write().await.activate().unwrap();
            general.set_active_handler(ConnectionKind::RegisteringClient);
            let registration = RegistrationConnection::from_general(general.clone());
            let rho = Arc::new(
                RhoConnection::new(
                    IotaConnection::from_general(general.clone(), 2).await,
                    vec![7],
                )
                .await,
            );
            if !matches!(scenario, "rho-unavailable" | "disconnect-during-lookup") {
                state.rho.add(rho.clone()).await;
            }
            if scenario == "attachment-occupied" {
                rho.add_client_connection(ClientConnection::from_general(general.clone(), 7).await)
                    .await;
            }
            let mut before_success = None;
            let mut resume_success = None;
            if scenario == "disconnect-before-response" {
                let (reached, wait) = tokio::sync::oneshot::channel();
                let (resume, continued) = tokio::sync::oneshot::channel();
                *registration.before_success.lock().await = Some((reached, continued));
                before_success = Some(wait);
                resume_success = Some(resume);
            }
            let global = state
                .rho_connection_limits
                .all
                .clone()
                .try_acquire_owned()
                .unwrap();
            let guest = state
                .rho_connection_limits
                .anonymous
                .clone()
                .try_acquire_owned()
                .unwrap();
            let handler = tokio::spawn({
                let registration = registration.clone();
                let general = general.clone();
                async move {
                    let _permits = (global, guest);
                    registration.start().await;
                    general.tau_session.write().await.close();
                }
            });
            let keys = Keyring::generate();
            let redeem = CommunicationValue::new(CommunicationType::RedeemUserInvitation)
                .with_id(10)
                .add_typed_default(DataType::InvitationId, DataValue::SignedNumber(3))
                .add_typed_default(DataType::IotaId, DataValue::SignedNumber(2))
                .add_typed_default(
                    DataType::PublicKey,
                    DataValue::Str(keys.public_key_bundle().try_to_base64().unwrap()),
                );
            client.sender.send(&redeem).await.unwrap();
            let (request, reply) = tokio::time::timeout(Duration::from_secs(3), omega.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(request, redeem);
            reply
                .send(Ok(request.add_typed_default(
                    DataType::UserId,
                    DataValue::SignedNumber(7),
                )))
                .unwrap();
            assert!(
                client
                    .receive()
                    .await
                    .unwrap()
                    .is_type(CommunicationType::RedeemUserInvitation)
            );
            let status = CommunicationValue::new(CommunicationType::GetUserInvitationStatus)
                .with_id(11)
                .add_typed_default(DataType::InvitationId, DataValue::SignedNumber(3))
                .add_typed_default(DataType::IotaId, DataValue::SignedNumber(2));
            client.sender.send(&status).await.unwrap();
            let (request, reply) = omega.recv().await.unwrap();
            reply
                .send(Ok(request.add_typed_default(
                    DataType::InvitationState,
                    DataValue::Str("redeemed".into()),
                )))
                .unwrap();
            let challenge = client.receive().await.unwrap();
            let nonce = challenge
                .get_data(DataType::ServerNonce)
                .unwrap()
                .as_signed_number()
                .unwrap() as u64;
            // A wrong principal, wrong nonce and a proof signed by another key leave the guest unchanged.
            for invalid in [
                proof(&keys, 8, nonce),
                proof(&keys, 7, nonce + 1),
                proof(&Keyring::generate(), 7, nonce),
            ] {
                client.sender.send(&invalid).await.unwrap();
                assert!(
                    !client
                        .receive()
                        .await
                        .unwrap()
                        .is_type(CommunicationType::Success)
                );
                assert!(matches!(
                    general.tau_session.read().await.authentication(),
                    tau::ApplicationAuthentication::Guest
                ));
                assert_eq!(
                    rho.client_count().await,
                    if scenario == "attachment-occupied" {
                        1
                    } else {
                        0
                    }
                );
            }
            if scenario == "session-closed" {
                general.tau_session.write().await.close();
            }
            let activation = proof(&keys, 7, nonce);
            client.sender.send(&activation).await.unwrap();
            if matches!(scenario, "rho-unavailable" | "disconnect-during-lookup") {
                let (request, reply) = omega.recv().await.unwrap();
                assert!(request.is_type(CommunicationType::GetUserData));
                if scenario == "disconnect-during-lookup" {
                    client.sender.close().await;
                    tokio::time::timeout(Duration::from_secs(3), handler)
                        .await
                        .unwrap()
                        .unwrap();
                    assert!(
                        reply.is_closed(),
                        "disconnected activation left a live authority waiter"
                    );
                    assert!(matches!(
                        general.tau_session.read().await.authentication(),
                        tau::ApplicationAuthentication::Guest
                    ));
                    assert_eq!(state.rho_connection_limits.all.available_permits(), 2);
                    host.shutdown().await;
                    continue;
                }
                reply
                    .send(Ok(request.add_typed_default(
                        DataType::IotaId,
                        DataValue::SignedNumber(2),
                    )))
                    .unwrap();
            }
            if let Some(reached) = before_success {
                tokio::time::timeout(Duration::from_secs(3), reached)
                    .await
                    .unwrap()
                    .unwrap();
                assert!(matches!(
                    general.tau_session.read().await.authentication(),
                    tau::ApplicationAuthentication::ApplicationAuthenticated { .. }
                ));
                client.sender.close().await;
                resume_success.unwrap().send(()).unwrap();
            } else {
                let response = tokio::time::timeout(Duration::from_secs(3), client.receive())
                    .await
                    .unwrap()
                    .unwrap();
                if scenario == "success" {
                    assert!(response.is_type(CommunicationType::Success));
                    assert!(registration.pending.lock().await.is_none());
                    assert_eq!(general.active_handler(), Some(ConnectionKind::Client));
                    assert_eq!(general.connection_kind(), ConnectionKind::RegisteringClient);
                    assert!(matches!(
                        general.tau_session.read().await.authentication(),
                        tau::ApplicationAuthentication::ApplicationAuthenticated {
                            identity: OmikronIdentity::Client(7)
                        }
                    ));
                    assert_eq!(
                        general.tau_session.read().await.connection_id(),
                        connection_id
                    );
                    assert_eq!(*general.session_id.read().await, session_id);
                    assert!(matches!(
                        general.tau_session.read().await.transport(),
                        tau::TransportAuthentication::Guest { .. }
                    ));
                    client.sender.send(&activation).await.unwrap();
                    assert!(
                        client
                            .receive()
                            .await
                            .unwrap()
                            .is_type(CommunicationType::ErrorNotAuthenticated)
                    );
                    assert_eq!(rho.client_count().await, 1);
                } else {
                    assert!(!response.is_type(CommunicationType::Success), "{scenario}");
                    assert!(matches!(
                        general.tau_session.read().await.authentication(),
                        tau::ApplicationAuthentication::Guest
                    ));
                    assert!(registration.pending.lock().await.is_some());
                    assert_eq!(
                        general.active_handler(),
                        Some(ConnectionKind::RegisteringClient)
                    );
                }
                if scenario == "rho-unavailable" {
                    state.rho.add(rho.clone()).await;
                    client.sender.send(&activation).await.unwrap();
                    let response = tokio::time::timeout(Duration::from_secs(3), client.receive())
                        .await
                        .unwrap()
                        .unwrap();
                    assert!(response.is_type(CommunicationType::Success));
                    assert!(registration.pending.lock().await.is_none());
                    assert_eq!(general.active_handler(), Some(ConnectionKind::Client));
                }
                assert_eq!(state.rho_connection_limits.all.available_permits(), 1);
                assert_eq!(state.rho_connection_limits.anonymous.available_permits(), 0);
                client.sender.close().await;
            }
            // Resolve activation/disconnect notifications without a live Omega service.
            let cleanup = async {
                tokio::pin!(handler);
                loop {
                    tokio::select! {
                        result = &mut handler => { result.unwrap(); break; },
                        Some((request, reply)) = omega.recv() => {
                            if scenario == "disconnect-before-response" {
                                assert!(!request.is_type(CommunicationType::UserConnected), "failed activation reported an online client");
                            }
                            let _ = reply.send(Ok(CommunicationValue::new(CommunicationType::Success).with_id(request.id().unwrap())));
                        }
                    }
                }
            };
            tokio::time::timeout(Duration::from_secs(5), cleanup)
                .await
                .unwrap();
            assert_eq!(state.rho_connection_limits.all.available_permits(), 2);
            assert_eq!(state.rho_connection_limits.anonymous.available_permits(), 1);
            if matches!(
                scenario,
                "success" | "rho-unavailable" | "disconnect-before-response"
            ) {
                assert_eq!(rho.client_count().await, 0);
            }
            host.shutdown().await;
        }
    }

    #[tokio::test]
    async fn verified_registration_upgrade_keeps_permits_and_guest_transport() {
        use super::{PendingRegistration, RegistrationConnection};
        use crate::rho::{
            connection::{GeneralConnection, OmikronIdentity, admission_engine},
            iota_connection::IotaConnection,
            rho_connection::RhoConnection,
            test_support,
        };
        use mtp::{
            codec::{DataType, DataValue},
            crypto::{DualSigner, Keyring},
            host::AuthState,
        };
        use std::{sync::Arc, time::Duration};
        let state = test_support::state();
        let (host, client, connection) = test_support::guest("registering-client").await;
        let general =
            GeneralConnection::admit(connection, state.clone(), &admission_engine()).unwrap();
        // A local route avoids a live Omega service. Activation notification
        // fails offline, as it already may in production, without detaching the loop.
        let iota = IotaConnection::from_general(general.clone(), 2).await;
        let rho = Arc::new(RhoConnection::new(iota.clone(), vec![7]).await);
        iota.set_rho_connection(rho.clone()).await;
        state.rho.add(rho).await;
        let registration = RegistrationConnection::from_general(general.clone());
        let keys = Keyring::generate();
        *registration.pending.lock().await = Some(PendingRegistration {
            invitation_id: 3,
            iota_id: 2,
            user_id: 7,
            public_key: keys.public_key_bundle(),
            challenge: Some(4),
            journal_operation: None,
        });
        let signer = DualSigner::new(
            &keys.sig_cl_secret_key,
            &keys.sig_pq_secret_key,
            &keys.sig_pq_public_key,
        )
        .unwrap();
        let signed = DataValue::Bytes(activation_payload(7, 2, 3, 4))
            .sign(
                7,
                crate::app_protection::purpose(crate::app_protection::REGISTRATION_ACTIVATION),
                &signer,
            )
            .unwrap();
        let request = CommunicationValue::new(CommunicationType::RegisteringClientAuthenticate)
            .with_id(10)
            .add_typed_default(DataType::UserId, DataValue::SignedNumber(7))
            .add_typed_default(DataType::ServerNonce, DataValue::SignedNumber(4))
            .add_typed_default(
                DataType::Signed,
                DataValue::Bytes(signed.to_bytes().unwrap()),
            );
        general.tau_session.write().await.activate().unwrap();
        let global = state
            .rho_connection_limits
            .all
            .clone()
            .try_acquire_owned()
            .unwrap();
        let anonymous = state
            .rho_connection_limits
            .anonymous
            .clone()
            .try_acquire_owned()
            .unwrap();
        let task = tokio::spawn(async move {
            let _permits = (global, anonymous);
            registration.start().await;
        });
        let invalid = request
            .clone()
            .add_typed_default(DataType::ServerNonce, DataValue::SignedNumber(5));
        client.sender.send(&invalid).await.unwrap();
        let response = tokio::time::timeout(Duration::from_secs(3), client.receive())
            .await
            .unwrap()
            .unwrap();
        assert!(!response.is_type(CommunicationType::Success));
        assert!(matches!(
            general.tau_session.read().await.authentication(),
            tau::ApplicationAuthentication::Guest
        ));
        client.sender.send(&request).await.unwrap();
        let response = tokio::time::timeout(Duration::from_secs(3), client.receive())
            .await
            .unwrap()
            .unwrap();
        assert!(response.is_type(CommunicationType::Success));
        assert!(matches!(
            general.tau_session.read().await.authentication(),
            tau::ApplicationAuthentication::ApplicationAuthenticated {
                identity: OmikronIdentity::Client(7)
            }
        ));
        assert_eq!(
            general.mtp_connection.auth_state,
            AuthState::Unauthenticated
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !task.is_finished(),
            "registration detached the upgraded client loop"
        );
        assert_eq!(state.rho_connection_limits.all.available_permits(), 1);
        assert_eq!(state.rho_connection_limits.anonymous.available_permits(), 0);
        client.sender.close().await;
        tokio::time::timeout(Duration::from_secs(3), task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(state.rho_connection_limits.all.available_permits(), 2);
        assert_eq!(state.rho_connection_limits.anonymous.available_permits(), 1);
        host.shutdown().await;
    }

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
