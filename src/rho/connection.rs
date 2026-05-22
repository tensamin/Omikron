use rand::{Rng, distributions::Alphanumeric};
use std::{collections::BTreeMap, collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::RwLock;
use ttp_core::{CommunicationType, CommunicationValue, DataTypes, DataValue};
use ttp_native::{Receiver, Sender};
use uuid::Uuid;

use crate::{
    anonymous_clients::anonymous_client_connection::AnonymousClientConnection,
    calls::call_manager,
    get_private_key, get_public_key, log_cv_in, log_cv_out, log_err, log_in, log_out,
    omega::omega_connection::get_omega_connection,
    rho::{
        app_connection::AppConnection, client_connection::ClientConnection,
        iota_connection::IotaConnection, rho_connection::RhoConnection, rho_manager,
    },
    util::{
        crypto_helper::{load_public_key, public_key_to_base64},
        crypto_util::{DataFormat, SecurePayload},
        logger::PrintType,
    },
};

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

    identified: Arc<RwLock<bool>>,
    challenged: Arc<RwLock<bool>>,
    challenge: Arc<RwLock<String>>,
    challenge_cv_id: Arc<RwLock<u32>>,

    connection_kind: Arc<RwLock<Option<ConnectionKind>>>,
    pub rho_connection: Arc<RwLock<Option<Arc<RhoConnection>>>>,
    id: Arc<RwLock<u64>>,
    pub session_id: Arc<RwLock<u64>>,
    pub app_identifier: Arc<RwLock<Option<String>>>,
    pub app_session: Arc<RwLock<Option<Uuid>>>,

    pub_key: Arc<RwLock<Option<Vec<u8>>>>,
}
impl GeneralConnection {
    pub fn new(sender: Sender, receiver: Receiver) -> Arc<Self> {
        Arc::new(Self {
            sender: Arc::new(sender),
            receiver: Arc::new(receiver),
            identified: Arc::new(RwLock::new(false)),
            challenged: Arc::new(RwLock::new(false)),
            challenge: Arc::new(RwLock::new(String::new())),
            challenge_cv_id: Arc::new(RwLock::new(0)),
            connection_kind: Arc::new(RwLock::new(None)),
            rho_connection: Arc::new(RwLock::new(None)),
            id: Arc::new(RwLock::new(0)),
            session_id: Arc::new(RwLock::new(0)),
            app_identifier: Arc::new(RwLock::new(None)),
            app_session: Arc::new(RwLock::new(None)),
            pub_key: Arc::new(RwLock::new(None)),
        })
    }
}
impl GeneralConnection {
    pub async fn handle(self: Arc<Self>) {
        log_in!(0, PrintType::General, "General connection handler started");

        while let Ok(cv) = self.receiver.receive().await {
            log_cv_in!(cv);

            if !*self.identified.read().await {
                self.handle_identification(cv).await;
                continue;
            }

            if !*self.challenged.read().await {
                self.handle_challenge_response(cv).await;
            }

            if *self.challenged.read().await {
                let self_clone = self.clone();
                tokio::spawn(async move {
                    self_clone.migrate().await;
                });
                break;
            }
        }

        log_out!(0, PrintType::General, "General connection handler stopped");
    }
    async fn handle_identification(self: &Arc<Self>, cv: CommunicationValue) {
        if cv.is_type(CommunicationType::register_iota) {
            if let DataValue::Str(pub_key) = cv.get_data(DataTypes::public_key) {
                let msg = CommunicationValue::new(CommunicationType::complete_register_iota)
                    .add_data(DataTypes::public_key, DataValue::Str(pub_key.clone()));

                let response = get_omega_connection()
                    .await_response(&msg, Some(Duration::from_secs(20)))
                    .await;

                if let Ok(response_cv) = response {
                    if let DataValue::Number(iota_id) = response_cv.get_data(DataTypes::iota_id) {
                        let success_msg = CommunicationValue::new(CommunicationType::success)
                            .with_id(cv.get_id())
                            .add_data(DataTypes::iota_id, DataValue::Number(*iota_id));

                        log_cv_out!(success_msg);
                        let _ = self.sender.send(&success_msg).await;
                    } else {
                        let err_msg =
                            CommunicationValue::new(CommunicationType::error_invalid_omikron_id)
                                .with_id(cv.get_id());
                        let _ = self.sender.send(&err_msg).await;
                    }
                }
            }
            return;
        }

        if cv.is_type(CommunicationType::app_identification) {
            let app_identifier = cv
                .get_data(DataTypes::app_identifier)
                .as_str()
                .unwrap_or("")
                .to_string();
            let app_session_id_str = cv.get_data(DataTypes::app_session).as_str().unwrap_or("");
            let app_session_id = Uuid::parse_str(app_session_id_str).unwrap_or(Uuid::new_v4());
            let pub_key_str = cv
                .get_data(DataTypes::app_public_key)
                .as_str()
                .unwrap_or("");
            let user_id = cv.get_data(DataTypes::user_id).as_number().unwrap_or(0);

            *self.id.write().await = user_id as u64;
            *self.app_identifier.write().await = Some(app_identifier);
            *self.app_session.write().await = Some(app_session_id);
            *self.connection_kind.write().await = Some(ConnectionKind::Phi);

            let pub_key = match load_public_key(pub_key_str) {
                Some(pk) => pk,
                None => return,
            };
            *self.pub_key.write().await = Some(pub_key.as_bytes().to_vec());

            let challenge: String = rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(32)
                .map(char::from)
                .collect();

            *self.challenge.write().await = challenge.clone();
            *self.identified.write().await = true;

            let encrypted_challenge =
                SecurePayload::new(challenge.as_bytes(), DataFormat::Raw, get_private_key())
                    .unwrap()
                    .encrypt_x448(pub_key)
                    .unwrap()
                    .export(DataFormat::Base64);

            let response = CommunicationValue::new(CommunicationType::app_challenge)
                .with_id(cv.get_id())
                .add_data(
                    DataTypes::public_key,
                    DataValue::Str(public_key_to_base64(&get_public_key())),
                )
                .add_data(DataTypes::challenge, DataValue::Str(encrypted_challenge));

            log_cv_out!(response);
            let _ = self.sender.send(&response).await;
            return;
        }

        if !cv.is_type(CommunicationType::identification) {
            return;
        }

        if let DataValue::Number(iota_id) = cv.get_data(DataTypes::iota_id) {
            *self.id.write().await = *iota_id as u64;
            *self.connection_kind.write().await = Some(ConnectionKind::Iota);

            let get_pub_key_msg = CommunicationValue::new(CommunicationType::get_iota_data)
                .add_data(DataTypes::iota_id, DataValue::Number(*iota_id));

            let response_cv = get_omega_connection()
                .await_response(&get_pub_key_msg, Some(Duration::from_secs(20)))
                .await;

            let response_cv = match response_cv {
                Ok(r) => r,
                Err(_) => {
                    log_err!(
                        *iota_id,
                        PrintType::Iota,
                        "Failed to get Iota data from Omega for iota_id={}",
                        iota_id
                    );
                    return;
                }
            };

            let base64_pub = response_cv
                .get_data(DataTypes::public_key)
                .as_str()
                .unwrap_or("");

            let pub_key = match load_public_key(base64_pub) {
                Some(pk) => pk,
                None => {
                    log_err!(
                        *iota_id,
                        PrintType::Iota,
                        "Failed to load public key for iota_id={}",
                        iota_id
                    );
                    return;
                }
            };

            *self.pub_key.write().await = Some(pub_key.as_bytes().to_vec());

            let challenge: String = rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(32)
                .map(char::from)
                .collect();

            *self.challenge.write().await = challenge.clone();
            *self.identified.write().await = true;

            let encrypted_challenge =
                SecurePayload::new(challenge.as_bytes(), DataFormat::Raw, get_private_key())
                    .unwrap()
                    .encrypt_x448(pub_key)
                    .unwrap()
                    .export(DataFormat::Base64);

            let response = CommunicationValue::new(CommunicationType::challenge)
                .with_id(cv.get_id())
                .add_data(
                    DataTypes::public_key,
                    DataValue::Str(public_key_to_base64(&get_public_key())),
                )
                .add_data(DataTypes::challenge, DataValue::Str(encrypted_challenge));

            log_cv_out!(response);
            let _ = self.sender.send(&response).await;
        } else if let DataValue::Number(user_id) = cv.get_data(DataTypes::user_id) {
            *self.id.write().await = *user_id as u64;
            *self.session_id.write().await = match cv.get_data(DataTypes::session_id) {
                DataValue::Number(s) => *s as u64,
                _ => cv.get_sender(),
            };

            #[allow(unused_assignments)]
            let mut base64_pub = String::new();

            if cv.is_type(CommunicationType::app_identification) {
                *self.connection_kind.write().await = Some(ConnectionKind::Phi);

                if let DataValue::Str(app_id) = cv.get_data(DataTypes::app_identifier) {
                    *self.app_identifier.write().await = Some(app_id.clone());
                }
                if let DataValue::Str(app_sess) = cv.get_data(DataTypes::app_session) {
                    if let Ok(uuid) = uuid::Uuid::parse_str(&app_sess) {
                        *self.app_session.write().await = Some(uuid);
                    }
                }

                base64_pub = cv
                    .get_data(DataTypes::app_public_key)
                    .as_str()
                    .unwrap_or("")
                    .to_string();
            } else {
                *self.connection_kind.write().await = Some(ConnectionKind::Client);

                let get_pub_key_msg = CommunicationValue::new(CommunicationType::get_user_data)
                    .add_data(DataTypes::user_id, DataValue::Number(*user_id));

                let response_cv = get_omega_connection()
                    .await_response(&get_pub_key_msg, Some(Duration::from_secs(20)))
                    .await;

                let response_cv = match response_cv {
                    Ok(r) => r,
                    Err(_) => {
                        return;
                    }
                };

                base64_pub = response_cv
                    .get_data(DataTypes::public_key)
                    .as_str()
                    .unwrap_or("")
                    .to_string();
            }

            let pub_key = match load_public_key(&base64_pub) {
                Some(pk) => pk,
                None => {
                    return;
                }
            };

            *self.pub_key.write().await = Some(pub_key.as_bytes().to_vec());

            let challenge: String = rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(32)
                .map(char::from)
                .collect();

            *self.challenge.write().await = challenge.clone();
            *self.identified.write().await = true;

            let encrypted_challenge =
                SecurePayload::new(challenge.as_bytes(), DataFormat::Raw, get_private_key())
                    .unwrap()
                    .encrypt_x448(pub_key)
                    .unwrap()
                    .export(DataFormat::Base64);

            let challenge_type = if cv.is_type(CommunicationType::app_identification) {
                CommunicationType::app_challenge
            } else {
                CommunicationType::challenge
            };

            let response = CommunicationValue::new(challenge_type)
                .with_id(cv.get_id())
                .with_receiver(*self.session_id.read().await)
                .add_data(
                    DataTypes::public_key,
                    DataValue::Str(public_key_to_base64(&get_public_key())),
                )
                .add_data(DataTypes::challenge, DataValue::Str(encrypted_challenge));

            log_cv_out!(response);
            let _ = self.sender.send(&response).await;
        }
    }
    async fn handle_challenge_response(self: &Arc<Self>, cv: CommunicationValue) {
        let id = *self.id.read().await as i64;

        if !cv.is_type(CommunicationType::challenge_response)
            && !cv.is_type(CommunicationType::app_challenge_response)
        {
            return;
        }

        if let DataValue::Str(response) = cv.get_data(DataTypes::challenge) {
            let expected = self.challenge.read().await.clone();

            if *response == expected {
                *self.challenged.write().await = true;
                *self.challenge_cv_id.write().await = cv.get_id();
            } else {
                log_err!(
                    id,
                    PrintType::Iota,
                    "Challenge response mismatch expected={} actual={}",
                    expected,
                    response
                );
                let err_msg = CommunicationValue::new(CommunicationType::error_invalid_challenge)
                    .with_id(cv.get_id())
                    .add_data(
                        DataTypes::message,
                        DataValue::Str(
                            "Challenge response mismatch; authentication rejected".to_string(),
                        ),
                    );
                let _ = self.sender.send(&err_msg).await;
            }
        } else {
            log_err!(
                id,
                PrintType::Iota,
                "Challenge response missing challenge payload"
            );
        }
    }

    async fn migrate(self: &Arc<Self>) -> bool {
        let kind = match *self.connection_kind.read().await {
            Some(kind) => kind,
            None => {
                return false;
            }
        };
        let id = *self.id.read().await;

        match kind {
            ConnectionKind::Client => {
                let notify = CommunicationValue::new(CommunicationType::user_connected)
                    .add_data(DataTypes::user_id, DataValue::Number(id as i64));
                get_omega_connection().send_message(&notify).await;

                let user_id = id as i64;

                let client = ClientConnection::from_general(self.clone(), id).await;

                let mut rho = rho_manager::get_rho_con_for_user(user_id).await;

                if rho.is_none() {
                    let get_user_msg = CommunicationValue::new(CommunicationType::get_user_data)
                        .add_data(DataTypes::user_id, DataValue::Number(user_id));

                    if let Ok(user_data_cv) = get_omega_connection()
                        .await_response(&get_user_msg, Some(Duration::from_secs(20)))
                        .await
                    {
                        if let DataValue::Number(iota_id) =
                            user_data_cv.get_data(DataTypes::iota_id)
                        {
                            if let Some(bound_rho) =
                                rho_manager::bind_user_to_iota(user_id, *iota_id).await
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
                    let iota_msg = CommunicationValue::new(CommunicationType::client_connected)
                        .add_data(DataTypes::user_id, DataValue::Number(user_id))
                        .add_data(DataTypes::session_id, DataValue::Number(session_id));

                    if let Ok(resp) = rho_conn
                        .get_iota_connection()
                        .clone()
                        .await_response(&iota_msg, Some(Duration::from_secs(20)))
                        .await
                    {
                        let mut ident_resp =
                            CommunicationValue::new(CommunicationType::identification_response)
                                .with_id(*self.challenge_cv_id.read().await);
                        for (k, v) in resp.get_data_container() {
                            let value_to_add = if k == &DataTypes::contacts {
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
                                                .map(|m| DataValue::Number(m.user_id as i64))
                                                .collect();

                                            let mut base_call_map: BTreeMap<DataTypes, DataValue> =
                                                BTreeMap::new();
                                            base_call_map.insert(
                                                DataTypes::call_id,
                                                DataValue::Str(call.call_id.to_string()),
                                            );
                                            base_call_map.insert(
                                                DataTypes::call_members,
                                                DataValue::Array(member_ids),
                                            );

                                            if timeout > 0 {
                                                base_call_map.insert(
                                                    DataTypes::timeout,
                                                    DataValue::Number(timeout as i64),
                                                );
                                            }

                                            if admin {
                                                base_call_map.insert(
                                                    DataTypes::has_admin,
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
                                                        DataTypes::call_secret,
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
                                            if let Some(DataValue::Number(id)) =
                                                contact_map.get(&DataTypes::user_id)
                                            {
                                                if let Some(call_list) = invites.get(id) {
                                                    contact_map.insert(
                                                        DataTypes::calls,
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

                                    ident_resp = ident_resp
                                        .add_data(DataTypes::calls, DataValue::Array(global_calls));
                                    DataValue::Array(new_contacts)
                                } else {
                                    v.clone()
                                }
                            } else {
                                v.clone()
                            };

                            ident_resp = ident_resp.add_data(k.clone(), value_to_add);
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
                let notify = CommunicationValue::new(CommunicationType::iota_connected)
                    .add_data(DataTypes::iota_id, DataValue::Number(id as i64));
                get_omega_connection().send_message(&notify).await;

                let iota = IotaConnection::from_general(self.clone(), id).await;

                let rho = Arc::new(RhoConnection::new(iota.clone(), Vec::new()).await);

                iota.set_rho_connection(rho.clone()).await;

                rho_manager::add_rho(rho).await;

                let get_iota_msg = CommunicationValue::new(CommunicationType::get_iota_data)
                    .add_data(DataTypes::iota_id, DataValue::Number(id as i64));

                if let Ok(iota_data_cv) = get_omega_connection()
                    .await_response(&get_iota_msg, Some(Duration::from_secs(20)))
                    .await
                {
                    if let DataValue::Array(users) = iota_data_cv.get_data(DataTypes::user_ids) {
                        let mut user_ids: Vec<u64> = Vec::new();
                        for value in users {
                            if let DataValue::Number(user_id) = value {
                                user_ids.push(*user_id as u64);
                            }
                        }
                        iota.set_user_ids(user_ids).await;
                    }
                }

                let ident_resp =
                    CommunicationValue::new(CommunicationType::identification_response)
                        .with_id(*self.challenge_cv_id.read().await)
                        .add_data(DataTypes::accepted, DataValue::Bool(true));

                log_cv_out!(ident_resp);
                let _ = self.sender.send(&ident_resp).await;

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
                    let get_user_msg = CommunicationValue::new(CommunicationType::get_user_data)
                        .add_data(DataTypes::user_id, DataValue::Number(user_id));

                    if let Ok(user_data_cv) = get_omega_connection()
                        .await_response(&get_user_msg, Some(Duration::from_secs(20)))
                        .await
                    {
                        if let DataValue::Number(iota_id) =
                            user_data_cv.get_data(DataTypes::iota_id)
                        {
                            if let Some(bound_rho) =
                                rho_manager::bind_user_to_iota(user_id, *iota_id).await
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

                let response =
                    CommunicationValue::new(CommunicationType::app_identification_response)
                        .with_id(*self.challenge_cv_id.read().await)
                        .with_receiver(*self.session_id.read().await);

                let _ = self.sender.send(&response).await;

                app_conn.start();
            }
        }
        true
    }
}
