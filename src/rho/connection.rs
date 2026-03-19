use rand::{Rng, distributions::Alphanumeric};
use std::{sync::Arc, time::Duration};
use tokio::sync::RwLock;
use ttp_core::{CommunicationType, CommunicationValue, DataTypes, DataValue};
use ttp_native::{Receiver, Sender};

use crate::{
    anonymous_clients::anonymous_client_connection::AnonymousClientConnection,
    get_private_key, get_public_key, log_cv_in, log_cv_out, log_err, log_in, log_out,
    omega::omega_connection::get_omega_connection,
    rho::{
        client_connection::ClientConnection, iota_connection::IotaConnection,
        rho_connection::RhoConnection, rho_manager,
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

    connection_kind: Arc<RwLock<Option<ConnectionKind>>>,
    id: Arc<RwLock<u64>>,

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
            connection_kind: Arc::new(RwLock::new(None)),
            id: Arc::new(RwLock::new(0)),
            pub_key: Arc::new(RwLock::new(None)),
        })
    }
}
impl GeneralConnection {
    pub async fn handle(self: Arc<Self>) {
        log_in!(0, PrintType::General, "General connection handler started");

        loop {
            let cv = match self.receiver.receive().await {
                Ok(v) => v,
                Err(_) => {
                    break;
                }
            };

            log_cv_in!(cv);

            if !*self.identified.read().await {
                self.handle_identification(cv).await;
                continue;
            }

            if !*self.challenged.read().await {
                self.handle_challenge_response(cv).await;
                if *self.challenged.read().await {
                    break;
                }
                continue;
            }

            if self.migrate().await {
                break;
            }
        }

        log_out!(0, PrintType::General, "General connection handler stopped");
    }
    async fn handle_identification(self: &Arc<Self>, cv: CommunicationValue) {
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

            let base64_pub = response_cv
                .get_data(DataTypes::public_key)
                .as_str()
                .unwrap_or("");

            let pub_key = match load_public_key(base64_pub) {
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

            let response = CommunicationValue::new(CommunicationType::challenge)
                .with_id(cv.get_id())
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

        if !cv.is_type(CommunicationType::challenge_response) {
            return;
        }

        if let DataValue::Str(response) = cv.get_data(DataTypes::challenge) {
            let expected = self.challenge.read().await.clone();

            if *response == expected {
                *self.challenged.write().await = true;

                let response = CommunicationValue::new(CommunicationType::identification_response)
                    .with_id(cv.get_id())
                    .add_data(DataTypes::accepted, DataValue::Bool(true));

                log_cv_out!(response);
                if let Err(_) = self.sender.send(&response).await {
                    return;
                }

                if self.migrate().await {
                    log_out!(id, PrintType::Iota, "Immediate migration");
                }
            } else {
                log_err!(
                    id,
                    PrintType::Iota,
                    "Challenge response mismatch expected={} actual={}",
                    expected,
                    response
                );
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

                let client = ClientConnection::from_general(self.clone(), id).await;
                client.start();
            }
            ConnectionKind::Iota => {
                let notify = CommunicationValue::new(CommunicationType::iota_connected)
                    .add_data(DataTypes::iota_id, DataValue::Number(id as i64));
                get_omega_connection().send_message(&notify).await;

                let iota = IotaConnection::from_general(self.clone(), id).await;

                let rho = Arc::new(RhoConnection::new(iota.clone(), Vec::new()).await);

                iota.set_rho_connection(Arc::downgrade(&rho)).await;

                rho_manager::add_rho(rho).await;

                iota.start();
            }
            ConnectionKind::AnonymousClient => {
                let client = AnonymousClientConnection::from_general(self.clone(), id).await;
                client.start();
            }
            ConnectionKind::Phi => {
                let iota = ClientConnection::from_general(self.clone(), id).await;
                iota.start();
            }
        }
        true
    }
}
