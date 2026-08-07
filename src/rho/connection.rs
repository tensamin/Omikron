use std::{sync::Arc, time::Duration};
use strum_macros::Display;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::{
    anonymous_clients::anonymous_client_connection::AnonymousClientConnection,
    app_state::AppState,
    log_err, log_in, log_out,
    rho::{
        app_connection::AppConnection, client_connection::ClientConnection,
        iota_connection::IotaConnection, rho_connection::RhoConnection,
    },
    util::logger::PrintType,
};
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use mtp::host::AuthState;
use mtp::webserver::{WebMTPConnection, WebMtpReceiver, WebMtpSender};

pub type MtpSender = WebMtpSender;
pub type MtpReceiver = WebMtpReceiver;

/*
 * How a connection identified itself during the mtp handshake driven by
 * `server.rs` ("iota" / "client" authenticated logins, "anonymous"
 * unauthenticated). `Phi` (third-party apps) predates that handshake and is
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
    Phi,
}

pub struct GeneralConnection {
    pub state: Arc<AppState>,
    pub sender: Arc<MtpSender>,
    pub receiver: Arc<MtpReceiver>,

    connection_kind: ConnectionKind,
    id: u64,

    pub rho_connection: Arc<RwLock<Option<Arc<RhoConnection>>>>,
    pub session_id: Arc<RwLock<u64>>,
    pub app_identifier: Arc<RwLock<Option<String>>>,
    pub app_session: Arc<RwLock<Option<Uuid>>>,
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
        let kind = match (conn.description.as_deref(), &conn.auth_state) {
            (Some("iota"), AuthState::Authenticated) => ConnectionKind::Iota,
            (Some("client"), AuthState::Authenticated) => ConnectionKind::Client,
            (Some("anonymous"), _) => ConnectionKind::AnonymousClient,
            _ => return None,
        };

        Some(Arc::new(Self {
            state,
            sender: Arc::new(conn.sender),
            receiver: Arc::new(conn.receiver),
            connection_kind: kind,
            id: conn.client_id,
            rho_connection: Arc::new(RwLock::new(None)),
            session_id: Arc::new(RwLock::new(match kind {
                ConnectionKind::Client => {
                    ((Uuid::new_v4().as_u128() as u64) & ((1_u64 << 53) - 1)).max(1)
                }
                _ => conn.client_id,
            })),
            app_identifier: Arc::new(RwLock::new(None)),
            app_session: Arc::new(RwLock::new(None)),
            client_version: Arc::new(RwLock::new(conn.version.to_string())),
        }))
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
            ConnectionKind::Iota => {
                self.migrate_iota().await;
                true
            }
            ConnectionKind::AnonymousClient => {
                self.migrate_anonymous_client().await;
                true
            }
            ConnectionKind::Phi => {
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
            match self
                .notify_user_connected(user_id, rho_conn.get_iota_id().await as i64)
                .await
            {
                Ok(()) => {
                    self.send_initial_client_state_request(&rho_conn, user_id)
                        .await;
                }
                Err(error) => {
                    log_err!(
                        user_id,
                        PrintType::Client,
                        "UserConnected acknowledgement failed: {}",
                        error
                    );
                }
            }
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

        let DataValue::SignedNumber(iota_id) = user_data_cv.get_data(DataType::IotaId) else {
            return None;
        };
        let rho = self
            .state
            .rho
            .bind_user_to_iota(user_id, *iota_id as i64)
            .await?;
        rho.bind_user_id(user_id).await;
        Some(rho)
    }

    async fn send_initial_client_state_request(&self, rho: &Arc<RhoConnection>, user_id: i64) {
        let session_id = *self.session_id.read().await as i64;
        let request = CommunicationValue::new(CommunicationType::ClientConnected)
            .with_sender(user_id as u64)
            .add_typed_default(DataType::UserId, DataValue::SignedNumber(user_id.into()))
            .add_typed_default(
                DataType::SessionId,
                DataValue::SignedNumber(session_id.into()),
            )
            .add_typed_default(DataType::VersionNumber, DataValue::SignedNumber(0))
            .add_typed_default(DataType::CacheValid, DataValue::Bool(false))
            .add_typed_default(DataType::CacheSchemaVersion, DataValue::SignedNumber(0));
        rho.get_iota_connection().send_message(&request).await;
    }

    async fn migrate_iota(self: &Arc<Self>) {
        let id = self.id;
        log_in!(id as i64, PrintType::Iota, "Iota {} connected", id);

        let iota = IotaConnection::from_general(self.clone(), id).await;
        let previous = self.state.rho.get_by_iota(id as i64).await;
        let user_ids = match previous.as_ref() {
            Some(previous) => previous.get_user_ids().await,
            None => Vec::new(),
        };
        let rho = Arc::new(RhoConnection::new(iota.clone(), user_ids).await);
        iota.set_rho_connection(rho.clone()).await;
        if let Some(previous) = previous {
            for client in previous.drain_client_connections() {
                client.set_rho_connection(rho.clone()).await;
                rho.add_client_connection(client).await;
            }
        }
        self.state.rho.add(rho).await;
        if let Err(error) = self.state.omega.clone().iota_connected(id as i64).await {
            log_err!(
                id as i64,
                PrintType::Iota,
                "IotaConnected acknowledgement failed: {}",
                error
            );
        }
        self.load_iota_users(id).await;
        iota.start();
    }

    async fn load_iota_users(&self, iota_id: u64) {
        let request = CommunicationValue::new(CommunicationType::GetIotaData)
            .add_typed_default(DataType::IotaId, DataValue::SignedNumber(iota_id.into()));
        let Ok(response) = self
            .state
            .omega
            .clone()
            .await_response(&request, Some(Duration::from_secs(20)))
            .await
        else {
            return;
        };
        let DataValue::Array(users) = response.get_data(DataType::UserIds) else {
            return;
        };
        let user_ids = users
            .iter()
            .filter_map(|value| match value {
                DataValue::SignedNumber(id) => Some(*id as i64),
                _ => None,
            })
            .collect();
        self.state
            .rho
            .replace_users_for_iota(iota_id as i64, user_ids)
            .await;
    }

    async fn migrate_anonymous_client(self: &Arc<Self>) {
        let client = AnonymousClientConnection::from_general(self.clone(), self.id).await;
        client.start();
    }

    async fn migrate_phi(self: &Arc<Self>) {
        let user_id = self.id as i64;
        let rho = self.find_user_rho(user_id).await;
        *self.rho_connection.write().await = rho.clone();
        let app_conn = AppConnection::from_general(self.clone(), self.id).await;
        if let Some(rho_conn) = rho {
            rho_conn.bind_user_id(user_id).await;
            rho_conn.add_app_connection(app_conn.clone()).await;
        }
        app_conn.start();
    }
}
