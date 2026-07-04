use std::{collections::BTreeMap, collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::{
    anonymous_clients::anonymous_client_connection::AnonymousClientConnection,
    calls::call_manager,
    log_cv_out, log_err, log_in, log_out,
    omega::omega_connection::get_omega_connection,
    rho::{
        app_connection::AppConnection, client_connection::ClientConnection,
        iota_connection::IotaConnection, rho_connection::RhoConnection, rho_manager,
    },
    util::logger::PrintType,
};
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataTypeId, DataValue};
use mtp::host::{AuthState, Connection as MTPHostConnection, Receiver, Sender};

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
    pub sender: Arc<Sender>,
    pub receiver: Arc<Receiver>,

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
     * unauthenticated) by `mtp::host::Host::accept`, via the
     * `get_by_connector_id`/`complete_register` callbacks in `server.rs`
     * keyed off `conn.description`. There is no separate application-level
     * challenge step anymore; a connection whose description doesn't resolve
     * to a known, appropriately-authenticated kind is rejected here instead
     * of being handed off to a connection handler.
     */
    pub fn new(conn: MTPHostConnection) -> Option<Arc<Self>> {
        let kind = match (conn.description.as_deref(), &conn.auth_state) {
            (Some("iota"), AuthState::Authenticated) => ConnectionKind::Iota,
            (Some("client"), AuthState::Authenticated) => ConnectionKind::Client,
            (Some("anonymous"), _) => ConnectionKind::AnonymousClient,
            _ => return None,
        };

        Some(Arc::new(Self {
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
        let id = self.id;

        match self.connection_kind {
            ConnectionKind::Client => {
                let notify = CommunicationValue::new(CommunicationType::UserConnected)
                    .add_typed_default(
                        DataType::UserId,
                        DataValue::SignedNumber((id as i64).into()),
                    );
                get_omega_connection().send_message(&notify).await;

                let user_id = id as i64;

                let client = ClientConnection::from_general(self.clone(), id).await;

                let mut rho = rho_manager::get_rho_con_for_user(user_id).await;

                if rho.is_none() {
                    let get_user_msg = CommunicationValue::new(CommunicationType::GetUserData)
                        .add_typed_default(
                            DataType::UserId,
                            DataValue::SignedNumber(user_id.into()),
                        );

                    if let Ok(user_data_cv) = get_omega_connection()
                        .await_response(&get_user_msg, Some(Duration::from_secs(20)))
                        .await
                    {
                        if let DataValue::SignedNumber(iota_id) =
                            user_data_cv.get_data(DataType::IotaId)
                        {
                            if let Some(bound_rho) =
                                rho_manager::bind_user_to_iota(user_id, *iota_id as i64).await
                            {
                                bound_rho.bind_user_id(user_id).await;
                                rho = Some(bound_rho);
                            }
                        }
                    }
                }

                *self.rho_connection.write().await = rho.clone();

                if let Some(rho_conn) = rho {
                    let session_id = *self.session_id.read().await as i64;
                    let iota_msg = CommunicationValue::new(CommunicationType::ClientConnected)
                        .add_typed_default(
                            DataType::UserId,
                            DataValue::SignedNumber(user_id.into()),
                        )
                        .add_typed_default(
                            DataType::SessionId,
                            DataValue::SignedNumber(session_id.into()),
                        );

                    if let Ok(resp) = rho_conn
                        .get_iota_connection()
                        .clone()
                        .await_response(&iota_msg, Some(Duration::from_secs(20)))
                        .await
                    {
                        /*
                         * mtp's handshake already confirmed this login; this
                         * message is an unsolicited push carrying the initial
                         * contacts/calls state, not a reply to a client-side
                         * request id (the old raw hello frame this used to
                         * reply to no longer reaches application code).
                         */
                        let mut ident_resp =
                            CommunicationValue::new(CommunicationType::IdentificationResponse);
                        let tm = mtp::codec::TypeMap::latest();
                        for (k, v) in resp.iter_typed_data() {
                            let value_to_add = if k == Some(DataType::Contacts) {
                                if let Some(contacts) = v.as_array() {
                                    let call_groups =
                                        call_manager::get_call_groups(user_id as u64).await;
                                    let mut invites: HashMap<i64, Vec<DataValue>> = HashMap::new();
                                    let mut global_calls: Vec<DataValue> = Vec::new();

                                    for call in call_groups {
                                        let members = call.members.read().await;

                                        let call_self =
                                            members.iter().find(|m| m.user_id == user_id as u64);

                                        if let Some(call_self) = call_self {
                                            let timeout = *call_self.timeout.read().await;
                                            let admin = call_self.has_admin();

                                            // List of all members in the call
                                            let member_ids: Vec<DataValue> = members
                                                .iter()
                                                .map(|m| DataValue::SignedNumber(m.user_id.into()))
                                                .collect();

                                            let mut base_call_map: BTreeMap<DataTypeId, DataValue> =
                                                BTreeMap::new();
                                            base_call_map.insert(
                                                DataType::CallId.to_id(&tm),
                                                DataValue::Str(call.call_id.to_string()),
                                            );
                                            base_call_map.insert(
                                                DataType::CallMembers.to_id(&tm),
                                                DataValue::Array(member_ids),
                                            );

                                            if timeout > 0 {
                                                base_call_map.insert(
                                                    DataType::Timeout.to_id(&tm),
                                                    DataValue::SignedNumber(
                                                        (timeout as i64).into(),
                                                    ),
                                                );
                                            }

                                            if admin {
                                                base_call_map.insert(
                                                    DataType::HasAdmin.to_id(&tm),
                                                    DataValue::Bool(true),
                                                );
                                            }

                                            // Add to global calls (without contact-specific secret)
                                            global_calls.push(DataValue::container_from_map(
                                                &base_call_map,
                                            ));

                                            for member in members.iter() {
                                                let member_id = member.user_id;
                                                if member_id == user_id as u64 {
                                                    continue;
                                                }

                                                let mut contact_call_map = base_call_map.clone();

                                                if let Some(secret) = call
                                                    .secrets
                                                    .read()
                                                    .await
                                                    .get(&(member_id, user_id as u64))
                                                {
                                                    contact_call_map.insert(
                                                        DataType::CallSecret.to_id(&tm),
                                                        DataValue::Str(secret.clone()),
                                                    );
                                                }

                                                invites
                                                    .entry(member_id as i64)
                                                    .or_insert_with(Vec::new)
                                                    .push(DataValue::container_from_map(
                                                        &contact_call_map,
                                                    ));
                                            }
                                        }
                                    }

                                    let mut new_contacts: Vec<DataValue> = Vec::new();
                                    for contact in contacts {
                                        if let Some(mut contact_map) = contact.as_map() {
                                            if let Some(DataValue::SignedNumber(id)) =
                                                contact_map.get(&DataType::UserId.to_id(&tm))
                                            {
                                                if let Some(call_list) = invites.get(&(*id as i64))
                                                {
                                                    contact_map.insert(
                                                        DataType::Calls.to_id(&tm),
                                                        DataValue::Array(call_list.clone()),
                                                    );
                                                }
                                            }
                                            new_contacts
                                                .push(DataValue::container_from_map(&contact_map));
                                        } else {
                                            new_contacts.push(contact.clone());
                                        }
                                    }

                                    ident_resp = ident_resp.add_typed_default(
                                        DataType::Calls,
                                        DataValue::Array(global_calls),
                                    );
                                    DataValue::Array(new_contacts)
                                } else {
                                    v.clone()
                                }
                            } else {
                                v.clone()
                            };

                            if let Some(dt) = k {
                                ident_resp = ident_resp.add_typed_default(dt, value_to_add);
                            }
                        }
                        log_cv_out!(ident_resp);
                        let _ = self.sender.send(&ident_resp).await;
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
            ConnectionKind::Iota => {
                log_in!(id as i64, PrintType::Iota, "Iota {} connected", id);

                let notify = CommunicationValue::new(CommunicationType::IotaConnected)
                    .add_typed_default(DataType::IotaId, DataValue::SignedNumber(id.into()));
                get_omega_connection().send_message(&notify).await;

                let iota = IotaConnection::from_general(self.clone(), id).await;

                let rho = Arc::new(RhoConnection::new(iota.clone(), Vec::new()).await);

                iota.set_rho_connection(rho.clone()).await;

                rho_manager::add_rho(rho).await;

                let get_iota_msg = CommunicationValue::new(CommunicationType::GetIotaData)
                    .add_typed_default(DataType::IotaId, DataValue::SignedNumber(id.into()));

                if let Ok(iota_data_cv) = get_omega_connection()
                    .await_response(&get_iota_msg, Some(Duration::from_secs(20)))
                    .await
                {
                    if let DataValue::Array(users) = iota_data_cv.get_data(DataType::UserIds) {
                        let mut user_ids: Vec<u64> = Vec::new();
                        for value in users {
                            if let DataValue::SignedNumber(user_id) = value {
                                user_ids.push(*user_id as u64);
                            }
                        }
                        iota.set_user_ids(user_ids).await;
                    }
                }

                // mtp's handshake already confirmed this login/registration to the Iota.
                iota.clone().start();
            }
            ConnectionKind::AnonymousClient => {
                let client = AnonymousClientConnection::from_general(self.clone(), id).await;
                client.start();
            }
            ConnectionKind::Phi => {
                let user_id = id as i64;
                let mut rho = rho_manager::get_rho_con_for_user(user_id).await;

                if rho.is_none() {
                    let get_user_msg = CommunicationValue::new(CommunicationType::GetUserData)
                        .add_typed_default(
                            DataType::UserId,
                            DataValue::SignedNumber(user_id.into()),
                        );

                    if let Ok(user_data_cv) = get_omega_connection()
                        .await_response(&get_user_msg, Some(Duration::from_secs(20)))
                        .await
                    {
                        if let DataValue::SignedNumber(iota_id) =
                            user_data_cv.get_data(DataType::IotaId)
                        {
                            if let Some(bound_rho) =
                                rho_manager::bind_user_to_iota(user_id, *iota_id as i64).await
                            {
                                bound_rho.bind_user_id(user_id).await;
                                rho = Some(bound_rho);
                            }
                        }
                    }
                }

                *self.rho_connection.write().await = rho.clone();

                let app_conn = AppConnection::from_general(self.clone(), id).await;

                if let Some(rho_conn) = rho {
                    rho_conn.bind_user_id(user_id).await;
                    rho_conn.add_app_connection(app_conn.clone()).await;
                }

                app_conn.start();
            }
        }
        true
    }
}
