use std::{sync::Arc, time::Duration};
use strum_macros::Display;
use tokio::sync::RwLock;

use crate::{
    anonymous_clients::anonymous_client_connection::AnonymousClientConnection,
    app_state::AppState,
    log_err, log_in, log_out,
    rho::{
        app_connection::AppConnection, client_connection::ClientConnection,
        iota_connection::IotaConnection, registration_connection::RegistrationConnection,
        rho_connection::RhoConnection,
    },
    util::logger::PrintType,
};
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use mtp::host::AuthState;
use mtp::webserver::{WebMTPConnection, WebMtpReceiver, WebMtpSender};
use thiserror::Error;
use uuid::Uuid;

pub type MtpSender = WebMtpSender;
pub type MtpReceiver = WebMtpReceiver;

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum FrameValidationError {
    #[error("message is missing an MTP id")]
    MissingId,
    #[error("message is missing an MTP sender")]
    MissingSender,
    #[error("message is missing an MTP receiver")]
    MissingReceiver,
}

pub trait RequiredMtpFields {
    fn require_id(&self) -> Result<u32, FrameValidationError>;
    fn require_sender(&self) -> Result<u64, FrameValidationError>;
    fn require_receiver(&self) -> Result<u64, FrameValidationError>;
}

impl RequiredMtpFields for CommunicationValue {
    fn require_id(&self) -> Result<u32, FrameValidationError> {
        self.id().ok_or(FrameValidationError::MissingId)
    }

    fn require_sender(&self) -> Result<u64, FrameValidationError> {
        self.sender().ok_or(FrameValidationError::MissingSender)
    }

    fn require_receiver(&self) -> Result<u64, FrameValidationError> {
        self.receiver().ok_or(FrameValidationError::MissingReceiver)
    }
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum ProtocolValueError {
    #[error("missing {0}")]
    Missing(&'static str),
    #[error("invalid {0}")]
    Invalid(&'static str),
    #[error("{0} is outside the supported range")]
    OutOfRange(&'static str),
}

pub fn positive_data_i64(
    value: &CommunicationValue,
    data_type: DataType,
    field: &'static str,
) -> Result<i64, ProtocolValueError> {
    let raw = value
        .get_data(data_type)
        .as_number()
        .ok_or(ProtocolValueError::Missing(field))?;
    let id = i64::try_from(raw).map_err(|_| ProtocolValueError::OutOfRange(field))?;
    if id <= 0 {
        return Err(ProtocolValueError::Invalid(field));
    }
    Ok(id)
}

pub(crate) trait OptionalDataValueCompat {
    fn as_bool(&self) -> Option<bool>;
    fn as_number(&self) -> Option<i128>;
    fn as_signed_number(&self) -> Option<i128>;
    fn as_str(&self) -> Option<&str>;
    #[allow(dead_code)]
    fn as_bytes(&self) -> Option<Vec<u8>>;
}

impl OptionalDataValueCompat for Option<&DataValue> {
    fn as_bool(&self) -> Option<bool> {
        self.and_then(|value| value.as_bool())
    }

    fn as_number(&self) -> Option<i128> {
        self.and_then(|value| value.as_number())
    }

    fn as_signed_number(&self) -> Option<i128> {
        self.and_then(|value| value.as_signed_number())
    }

    fn as_str(&self) -> Option<&str> {
        self.and_then(|value| value.as_str())
    }

    fn as_bytes(&self) -> Option<Vec<u8>> {
        self.and_then(|value| value.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ConnectionKind, FrameValidationError, ProtocolValueError, RequiredMtpFields,
        connection_kind, positive_data_i64,
    };
    use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
    use mtp::crypto::{Ed25519Signer, SignatureScheme, auth::register_proof_payload};
    use mtp::host::AuthState;

    #[test]
    fn receiver_id_rejects_missing_negative_zero_and_overflow() {
        let frame = CommunicationValue::new(CommunicationType::CallInvite);
        assert_eq!(
            positive_data_i64(&frame, DataType::ReceiverId, "receiver_id"),
            Err(ProtocolValueError::Missing("receiver_id"))
        );
        for value in [-1, 0] {
            let frame = frame
                .clone()
                .add_typed_default(DataType::ReceiverId, DataValue::SignedNumber(value));
            assert_eq!(
                positive_data_i64(&frame, DataType::ReceiverId, "receiver_id"),
                Err(ProtocolValueError::Invalid("receiver_id"))
            );
        }
        for value in [i128::from(i64::MAX) + 1, i128::from(u64::MAX)] {
            let frame = frame
                .clone()
                .add_typed_default(DataType::ReceiverId, DataValue::SignedNumber(value));
            assert_eq!(
                positive_data_i64(&frame, DataType::ReceiverId, "receiver_id"),
                Err(ProtocolValueError::OutOfRange("receiver_id"))
            );
        }
        let frame = frame.add_typed_default(
            DataType::ReceiverId,
            DataValue::SignedNumber(i128::from(i64::MAX)),
        );
        assert_eq!(
            positive_data_i64(&frame, DataType::ReceiverId, "receiver_id"),
            Ok(i64::MAX)
        );
    }

    #[test]
    fn required_fields_preserve_missing_field_errors() {
        let frame = CommunicationValue::new(CommunicationType::Success)
            .without_id()
            .without_sender()
            .without_receiver();

        assert_eq!(frame.require_id(), Err(FrameValidationError::MissingId));
        assert_eq!(
            frame.require_sender(),
            Err(FrameValidationError::MissingSender)
        );
        assert_eq!(
            frame.require_receiver(),
            Err(FrameValidationError::MissingReceiver)
        );
    }

    #[test]
    fn zero_is_a_present_routing_value() {
        let frame = CommunicationValue::new(CommunicationType::Success)
            .with_id(0)
            .with_sender(0)
            .with_receiver(0);

        assert_eq!(frame.require_id(), Ok(0));
        assert_eq!(frame.require_sender(), Ok(0));
        assert_eq!(frame.require_receiver(), Ok(0));
    }

    #[test]
    fn anonymous_roles_require_unauthenticated_mtp_state() {
        assert_eq!(
            connection_kind(Some("anonymous"), &AuthState::Unauthenticated),
            Some(ConnectionKind::AnonymousClient)
        );
        assert_eq!(
            connection_kind(Some("registering-client"), &AuthState::Unauthenticated),
            Some(ConnectionKind::RegisteringClient)
        );
        assert_eq!(
            connection_kind(Some("anonymous"), &AuthState::Authenticated),
            None
        );
        assert_eq!(
            connection_kind(Some("registering-client"), &AuthState::Authenticated),
            None
        );
    }

    #[test]
    fn iota_registration_proof_cannot_authenticate_as_client() {
        let (signer, _, _) = Ed25519Signer::generate();
        let signature = signer
            .sign(&register_proof_payload(
                "0.3",
                Some("iota"),
                b"public-key",
                1,
                2,
            ))
            .unwrap();

        assert!(
            signer
                .verify(
                    &register_proof_payload("0.3", Some("client"), b"public-key", 1, 2,),
                    &signature,
                )
                .is_err()
        );
        assert_eq!(
            connection_kind(Some("iota"), &AuthState::Authenticated),
            Some(ConnectionKind::Iota)
        );
    }
}

/*
 * How a connection identified itself during the mtp handshake driven by
 * `server.rs` ("iota" / "client" authenticated logins, "anonymous"
 * unauthenticated). TAuth apps authenticate each scoped request after transport setup.
 * not reachable through it, since mtp's host only recognizes its own
 * `Identification`/`Register` hello frames; it is kept only so
 * `app_connection.rs` still compiles.
 */
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display)]
#[allow(dead_code)]
pub enum ConnectionKind {
    Client,
    Iota,
    AnonymousClient,
    RegisteringClient,
    TAuth,
}

fn connection_kind(description: Option<&str>, auth_state: &AuthState) -> Option<ConnectionKind> {
    match (description, auth_state) {
        (Some("iota"), AuthState::Authenticated) => Some(ConnectionKind::Iota),
        (Some("client"), AuthState::Authenticated) => Some(ConnectionKind::Client),
        (Some("anonymous"), AuthState::Unauthenticated) => Some(ConnectionKind::AnonymousClient),
        (Some("registering-client"), AuthState::Unauthenticated) => {
            Some(ConnectionKind::RegisteringClient)
        }
        (Some("tauth"), AuthState::Unauthenticated) => Some(ConnectionKind::TAuth),
        _ => None,
    }
}

pub struct GeneralConnection {
    pub state: Arc<AppState>,
    pub sender: Arc<MtpSender>,
    pub receiver: Arc<MtpReceiver>,
    pub(crate) mtp_connection: Arc<WebMTPConnection>,

    connection_kind: ConnectionKind,
    id: u64,

    pub rho_connection: Arc<RwLock<Option<Arc<RhoConnection>>>>,
    pub session_id: Arc<RwLock<u64>>,
    pub client_version: Arc<RwLock<String>>,
}

impl GeneralConnection {
    /*
     * `conn` has already been authenticated (or deliberately left
     * unauthenticated) by `mtp::webserver::MTPWebServer::accept`, via the
     * `get_by_connector_id`/`complete_register` callbacks in `server.rs`
     * keyed off `conn.description`. There is no separate application-level
     * challenge step anymore; a connection whose description doesn't resolve
     * to a known, appropriately-authenticated kind is rejected here instead
     * of being handed off to a connection handler.
     */
    pub fn new(conn: WebMTPConnection, state: Arc<AppState>) -> Option<Arc<Self>> {
        let kind = connection_kind(conn.description.as_deref(), &conn.auth_state)?;

        let id = if kind == ConnectionKind::RegisteringClient {
            (rand::random::<u64>() & ((1_u64 << 48) - 1)).max(1)
        } else {
            conn.client_id
        };
        let client_version = conn.version.to_string();
        let conn = Arc::new(conn);
        Some(Arc::new(Self {
            state,
            sender: Arc::new(conn.sender.clone()),
            receiver: Arc::new(conn.receiver.clone()),
            mtp_connection: conn,
            connection_kind: kind,
            id,
            rho_connection: Arc::new(RwLock::new(None)),
            session_id: Arc::new(RwLock::new(match kind {
                ConnectionKind::Client | ConnectionKind::RegisteringClient => {
                    ((Uuid::new_v4().as_u128() as u64) & ((1_u64 << 53) - 1)).max(1)
                }
                _ => id,
            })),
            client_version: Arc::new(RwLock::new(client_version)),
        }))
    }

    pub fn connection_kind(&self) -> ConnectionKind {
        self.connection_kind
    }

    pub async fn handle(self: Arc<Self>) {
        log_in!(0, PrintType::General, "General connection handler started");
        if self.migrate().await {
            log_out!(
                0,
                PrintType::General,
                "General connection handler stopped, upgraded to {}",
                self.connection_kind
            );
        } else {
            log_out!(
                0,
                PrintType::General,
                "General connection handler stopped without upgrade"
            );
        }
    }

    async fn migrate(self: &Arc<Self>) -> bool {
        match self.connection_kind {
            ConnectionKind::Client => self.migrate_client().await,
            ConnectionKind::Iota => self.migrate_iota().await,
            ConnectionKind::AnonymousClient => {
                self.migrate_anonymous_client().await;
                true
            }
            ConnectionKind::RegisteringClient => {
                RegistrationConnection::from_general(self.clone())
                    .start()
                    .await;
                true
            }
            ConnectionKind::TAuth => {
                self.migrate_phi().await;
                true
            }
        }
    }

    async fn migrate_client(self: &Arc<Self>) -> bool {
        let id = self.id;
        let user_id = id as i64;

        let client = ClientConnection::from_general(self.clone(), id).await;
        let rho = self.find_user_rho(user_id).await;
        *self.rho_connection.write().await = rho.clone();

        if let Some(rho_conn) = rho {
            rho_conn.bind_user_id(user_id).await;
            rho_conn.add_client_connection(client.clone()).await;
            client.clone().start();

            let iota_id = rho_conn.get_iota_id().await as i64;
            let session_id = *self.session_id.read().await as i64;
            match self.notify_user_connected(user_id, iota_id).await {
                Ok(()) => {
                    log_out!(
                        user_id,
                        PrintType::Client,
                        "InitialSync user={} session={} stage=user_connected_ok",
                        user_id,
                        session_id
                    );
                }
                Err(error) => {
                    log_err!(
                        user_id,
                        PrintType::Client,
                        "InitialSync user={} session={} stage=user_connected_failed error={}",
                        user_id,
                        session_id,
                        error
                    );
                }
            }
            return true;
        } else {
            log_err!(
                user_id,
                PrintType::Client,
                "No RhoConnection found for user {}, client not attached to iota",
                id
            );
            let error = CommunicationValue::new(CommunicationType::ErrorNoIota);
            let _ = self.sender.send(&error).await;
        }

        client.start();
        true
    }

    async fn notify_user_connected(&self, user_id: i64, iota_id: i64) -> Result<(), String> {
        let session_id = *self.session_id.read().await as i64;
        self.state
            .omega
            .clone()
            .user_connected(user_id, session_id, iota_id)
            .await
    }

    async fn find_user_rho(&self, user_id: i64) -> Option<Arc<RhoConnection>> {
        if let Some(rho) = self.state.rho.get_for_user(user_id).await {
            return Some(rho);
        }

        let get_user_msg = CommunicationValue::new(CommunicationType::GetUserData)
            .with_sender(self.state.omega.omikron_id())
            .add_typed_default(DataType::UserId, DataValue::SignedNumber(user_id.into()));
        let Ok(user_data_cv) = self
            .state
            .omega
            .clone()
            .await_response(&get_user_msg, Some(Duration::from_secs(20)))
            .await
        else {
            return None;
        };

        let Some(DataValue::SignedNumber(iota_id)) = user_data_cv.get_data(DataType::IotaId) else {
            return None;
        };
        let Some(rho) = self
            .state
            .rho
            .bind_user_to_iota(user_id, *iota_id as i64)
            .await
        else {
            log_err!(
                user_id,
                PrintType::Client,
                "Omega maps user {} to Iota {}, but no local Rho exists",
                user_id,
                iota_id
            );
            return None;
        };
        rho.bind_user_id(user_id).await;
        Some(rho)
    }

    async fn migrate_iota(self: &Arc<Self>) -> bool {
        let id = self.id;
        log_in!(id as i64, PrintType::Iota, "Iota {} connected", id);

        let user_ids = match self.state.omega.iota_connected(id as i64).await {
            Ok(user_ids) => user_ids,
            Err(error) => {
                log_err!(
                    id as i64,
                    PrintType::Iota,
                    "Omega rejected Iota activation: {}",
                    error
                );
                return false;
            }
        };
        let iota = IotaConnection::from_general(self.clone(), id).await;
        let previous = self.state.rho.get_by_iota(id as i64).await;
        let rho = Arc::new(RhoConnection::new(iota.clone(), user_ids).await);
        iota.set_rho_connection(rho.clone()).await;
        if let Some(previous) = previous {
            for client in previous.drain_client_connections() {
                client.set_rho_connection(rho.clone()).await;
                rho.add_client_connection(client).await;
            }
        }
        self.state.rho.add(rho.clone()).await;
        iota.start();
        true
    }

    async fn migrate_anonymous_client(self: &Arc<Self>) {
        let client = AnonymousClientConnection::from_general(self.clone(), self.id).await;
        client.start();
    }

    pub async fn attach_registered_client(
        self: Arc<Self>,
        user_id: u64,
    ) -> Option<Arc<ClientConnection>> {
        let client = ClientConnection::from_general(self.clone(), user_id).await;
        let rho = self.find_user_rho(user_id as i64).await;
        *self.rho_connection.write().await = rho.clone();
        let Some(rho) = rho else {
            return None;
        };
        rho.bind_user_id(user_id as i64).await;
        rho.add_client_connection(client.clone()).await;
        let iota_id = rho.get_iota_id().await as i64;
        if let Err(error) = self.notify_user_connected(user_id as i64, iota_id).await {
            log_err!(
                user_id as i64,
                PrintType::Client,
                "Registered client activation notification failed: {}",
                error
            );
        }
        Some(client)
    }

    async fn migrate_phi(self: &Arc<Self>) {
        let app_conn = AppConnection::from_general(self.clone(), self.id).await;
        app_conn.start();
    }
}
