use epsilon_core::{CommunicationType, CommunicationValue, DataTypes, DataValue};
use epsilon_native::{Receiver, Sender};
use rand::{Rng, distributions::Alphanumeric};
use std::{sync::Arc, time::Duration};
use tokio::sync::RwLock;

use crate::{
    anonymous_clients::anonymous_client_connection::AnonymousClientConnection,
    get_private_key, get_public_key, log_err, log_in, log_out,
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
                Ok(v) => {
                    log_in!(
                        0,
                        PrintType::General,
                        "General connection received message type={:?} id={} identified={} challenged={}",
                        v.get_type(),
                        v.get_id(),
                        *self.identified.read().await,
                        *self.challenged.read().await
                    );
                    v
                }
                Err(e) => {
                    log_err!(
                        0,
                        PrintType::General,
                        "General connection receive error before upgrade completion: {:?}",
                        e
                    );
                    break;
                }
            };

            if !*self.identified.read().await {
                self.handle_identification(cv).await;
                continue;
            }

            if !*self.challenged.read().await {
                self.handle_challenge_response(cv).await;
                if *self.challenged.read().await {
                    log_out!(
                        0,
                        PrintType::General,
                        "General connection challenge flow completed, handler will stop after immediate migration"
                    );
                    break;
                }
                continue;
            }

            log_in!(
                0,
                PrintType::General,
                "General connection ready to migrate for id={} kind={:?}",
                *self.id.read().await,
                *self.connection_kind.read().await
            );

            if self.migrate().await {
                log_out!(
                    0,
                    PrintType::General,
                    "General connection migration completed, handing over to specialized connection"
                );
                break;
            }
        }

        log_out!(0, PrintType::General, "General connection handler stopped");
    }
    async fn handle_identification(self: &Arc<Self>, cv: CommunicationValue) {
        if !cv.is_type(CommunicationType::identification) {
            log_in!(
                0,
                PrintType::General,
                "Ignoring pre-identification message type={:?} id={}",
                cv.get_type(),
                cv.get_id()
            );
            return;
        }

        if let DataValue::Number(iota_id) = cv.get_data(DataTypes::iota_id) {
            log_in!(
                *iota_id,
                PrintType::Iota,
                "Received Iota identification request message_id={}",
                cv.get_id()
            );

            *self.id.write().await = *iota_id as u64;
            *self.connection_kind.write().await = Some(ConnectionKind::Iota);

            let get_pub_key_msg = CommunicationValue::new(CommunicationType::get_iota_data)
                .add_data(DataTypes::iota_id, DataValue::Number(*iota_id));

            log_out!(
                *iota_id,
                PrintType::Iota,
                "Requesting Iota public key from Omega"
            );

            let response_cv = get_omega_connection()
                .await_response(&get_pub_key_msg, Some(Duration::from_secs(20)))
                .await;

            let response_cv = match response_cv {
                Ok(r) => {
                    log_in!(
                        *iota_id,
                        PrintType::Iota,
                        "Received Iota public key response from Omega"
                    );
                    r
                }
                Err(e) => {
                    log_err!(
                        *iota_id,
                        PrintType::Iota,
                        "Failed to load Iota public key from Omega: {:?}",
                        e
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
                        "Failed to decode Iota public key from Omega response"
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

            log_out!(
                *iota_id,
                PrintType::Iota,
                "Generated challenge for Iota identification challenge_len={}",
                challenge.len()
            );

            *self.challenge.write().await = challenge.clone();
            *self.identified.write().await = true;

            let encrypted_challenge =
                SecurePayload::new(challenge.as_bytes(), DataFormat::Raw, get_private_key())
                    .unwrap()
                    .encrypt_x448(pub_key)
                    .unwrap()
                    .export(DataFormat::Base64);

            let response = CommunicationValue::new(CommunicationType::challenge)
                .add_data(
                    DataTypes::public_key,
                    DataValue::Str(public_key_to_base64(&get_public_key())),
                )
                .add_data(DataTypes::challenge, DataValue::Str(encrypted_challenge));

            log_out!(
                *iota_id,
                PrintType::Iota,
                "Sending encrypted identification challenge to Iota"
            );

            if let Err(e) = self.sender.send(&response).await {
                log_err!(
                    *iota_id,
                    PrintType::Iota,
                    "Failed to send challenge to Iota: {:?}",
                    e
                );
            }
        } else {
            log_err!(
                0,
                PrintType::General,
                "Identification message missing iota_id payload"
            );
        }
    }
    async fn handle_challenge_response(self: &Arc<Self>, cv: CommunicationValue) {
        let id = *self.id.read().await as i64;

        if !cv.is_type(CommunicationType::challenge_response) {
            log_in!(
                id,
                PrintType::Iota,
                "Ignoring pre-challenge-completion message type={:?} id={}",
                cv.get_type(),
                cv.get_id()
            );
            return;
        }

        if let DataValue::Str(response) = cv.get_data(DataTypes::challenge) {
            let expected = self.challenge.read().await.clone();

            log_in!(
                id,
                PrintType::Iota,
                "Received challenge response message_id={} response_len={} expected_len={}",
                cv.get_id(),
                response.len(),
                expected.len()
            );

            if *response == expected {
                log_in!(
                    id,
                    PrintType::Iota,
                    "Challenge response validated successfully"
                );

                *self.challenged.write().await = true;

                let response = CommunicationValue::new(CommunicationType::identification_response)
                    .with_id(cv.get_id())
                    .add_data(DataTypes::accepted, DataValue::Bool(true));

                log_out!(
                    id,
                    PrintType::Iota,
                    "Sending identification_response accepted=true"
                );

                if let Err(e) = self.sender.send(&response).await {
                    log_err!(
                        id,
                        PrintType::Iota,
                        "Failed to send identification_response: {:?}",
                        e
                    );
                    return;
                }

                log_in!(
                    id,
                    PrintType::Iota,
                    "Immediately migrating upgraded connection after successful challenge validation"
                );

                if self.migrate().await {
                    log_out!(
                        id,
                        PrintType::Iota,
                        "Immediate migration after challenge validation completed successfully"
                    );
                } else {
                    log_err!(
                        id,
                        PrintType::Iota,
                        "Immediate migration after challenge validation failed"
                    );
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
                log_err!(
                    0,
                    PrintType::General,
                    "Migration requested without a resolved connection kind"
                );
                return false;
            }
        };
        let id = *self.id.read().await;

        log_in!(
            id as i64,
            PrintType::General,
            "Starting migration for kind={:?} id={}",
            kind,
            id
        );

        match kind {
            ConnectionKind::Client => {
                let client = ClientConnection::from_general(self.clone(), id).await;
                client.start();
                log_out!(
                    id as i64,
                    PrintType::Client,
                    "Migrated general connection into ClientConnection"
                );
            }
            ConnectionKind::Iota => {
                let iota = IotaConnection::from_general(self.clone(), id).await;
                log_in!(
                    id as i64,
                    PrintType::Iota,
                    "Created upgraded IotaConnection from GeneralConnection"
                );

                let rho = Arc::new(RhoConnection::new(iota.clone(), Vec::new()).await);
                log_in!(
                    id as i64,
                    PrintType::Iota,
                    "Created RhoConnection for upgraded Iota connection"
                );

                iota.set_rho_connection(Arc::downgrade(&rho)).await;
                log_in!(
                    id as i64,
                    PrintType::Iota,
                    "Attached weak RhoConnection reference to IotaConnection"
                );

                rho_manager::add_rho(rho).await;
                log_out!(
                    id as i64,
                    PrintType::Iota,
                    "Registered upgraded Iota connection in rho_manager"
                );

                iota.start();
                log_out!(
                    id as i64,
                    PrintType::Iota,
                    "Started upgraded IotaConnection read loop"
                );
            }
            ConnectionKind::AnonymousClient => {
                let client = AnonymousClientConnection::from_general(self.clone(), id).await;
                client.start();
                log_out!(
                    id as i64,
                    PrintType::Client,
                    "Migrated general connection into AnonymousClientConnection"
                );
            }
            ConnectionKind::Phi => {
                let iota = ClientConnection::from_general(self.clone(), id).await;
                iota.start();
                log_out!(
                    id as i64,
                    PrintType::General,
                    "Migrated general connection into Phi/Client handler"
                );
            }
        }
        true
    }
}
