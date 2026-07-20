use std::{sync::Arc, time::Duration};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::{
    anonymous_clients::anonymous_client_connection::AnonymousClientConnection,
    app_state::AppState,
    log_cv_out, log_err, log_in, log_out,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
            session_id: Arc::new(RwLock::new(conn.client_id)),
            app_identifier: Arc::new(RwLock::new(None)),
            app_session: Arc::new(RwLock::new(None)),
            client_version: Arc::new(RwLock::new(conn.version.to_string())),
        }))
    }

    pub async fn handle(self: Arc<Self>) {
        log_in!(0, PrintType::General, "General connection handler started");
        self.migrate().await;
        log_out!(0, PrintType::General, "General connection handler stopped");
    }

    async fn migrate(self: &Arc<Self>) -> bool {
        match self.connection_kind {
            ConnectionKind::Client => self.migrate_client().await,
            ConnectionKind::Iota => self.migrate_iota().await,
            ConnectionKind::AnonymousClient => self.migrate_anonymous_client().await,
            ConnectionKind::Phi => self.migrate_phi().await,
        }
        true
    }

    async fn migrate_client(self: &Arc<Self>) {
        let id = self.id;
        let user_id = id as i64;
        self.notify_user_connected(user_id).await;

        let client = ClientConnection::from_general(self.clone(), id).await;
        let rho = self.find_user_rho(user_id).await;
        *self.rho_connection.write().await = rho.clone();

        if let Some(rho_conn) = rho {
            if let Some(response) = self.request_initial_client_state(&rho_conn, user_id).await {
                let response = self.add_call_state(response, user_id).await;
                log_cv_out!(response);
                let _ = self.sender.send(&response).await;
                rho_conn.bind_user_id(user_id).await;
                rho_conn.add_client_connection(client.clone()).await;
            }
        } else {
            log_err!(
                user_id,
                PrintType::Client,
                "No RhoConnection found for user {}, client not attached to iota",
                id
            );
        }

        client.start();
    }

    async fn notify_user_connected(&self, user_id: i64) {
        let notify = CommunicationValue::new(CommunicationType::UserConnected)
            .add_typed_default(DataType::UserId, DataValue::SignedNumber(user_id.into()));
        self.state.omega.clone().send_message(&notify).await;
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

    async fn request_initial_client_state(
        &self,
        rho: &Arc<RhoConnection>,
        user_id: i64,
    ) -> Option<CommunicationValue> {
        let session_id = *self.session_id.read().await as i64;
        let request = CommunicationValue::new(CommunicationType::ClientConnected)
            .add_typed_default(DataType::UserId, DataValue::SignedNumber(user_id.into()))
            .add_typed_default(
                DataType::SessionId,
                DataValue::SignedNumber(session_id.into()),
            );
        rho.get_iota_connection()
            .clone()
            .await_response(&request, Some(Duration::from_secs(20)))
            .await
            .ok()
    }

    async fn add_call_state(
        &self,
        response: CommunicationValue,
        user_id: i64,
    ) -> CommunicationValue {
        let mut output = CommunicationValue::new(CommunicationType::IdentificationResponse);

        for (key, value) in response.iter_typed_data() {
            if key == Some(DataType::Contacts) {
                if let Some(contacts) = value.as_array() {
                    let (contacts, global_calls) = self
                        .state
                        .call_state_aggregator
                        .augment_contacts(user_id as u64, contacts.clone())
                        .await;
                    output =
                        output.add_typed_default(DataType::Contacts, DataValue::Array(contacts));
                    output =
                        output.add_typed_default(DataType::Calls, DataValue::Array(global_calls));
                    continue;
                }
            }
            if let Some(data_type) = key {
                output = output.add_typed_default(data_type, value.clone());
            }
        }
        output
    }

    async fn migrate_iota(self: &Arc<Self>) {
        let id = self.id;
        log_in!(id as i64, PrintType::Iota, "Iota {} connected", id);
        let notify = CommunicationValue::new(CommunicationType::IotaConnected)
            .add_typed_default(DataType::IotaId, DataValue::SignedNumber(id.into()));
        self.state.omega.clone().send_message(&notify).await;

        let iota = IotaConnection::from_general(self.clone(), id).await;
        let rho = Arc::new(RhoConnection::new(iota.clone(), Vec::new()).await);
        iota.set_rho_connection(rho.clone()).await;
        self.state.rho.add(rho).await;
        self.load_iota_users(&iota, id).await;
        iota.start();
    }

    async fn load_iota_users(&self, iota: &Arc<IotaConnection>, iota_id: u64) {
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
                DataValue::SignedNumber(id) => Some(*id as u64),
                _ => None,
            })
            .collect();
        iota.set_user_ids(user_ids).await;
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
