use crate::anonymous_clients::anonymous_manager;
use crate::omega::omega_connection::get_omega_connection;
use crate::rho::connection::GeneralConnection;
use crate::rho::{rho_connection::RhoConnection, rho_manager};
use crate::util::logger::PrintType;
use crate::{log_cv_in, log_cv_out, log_err, log_in, log_out};
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use mtp::host::{Receiver, Sender};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use uuid::Uuid;

pub struct AppConnection {
    pub user_id: u64,
    pub app_identifier: String,
    pub app_session: Uuid,
    pub client_version: String,

    pub sender: Arc<Sender>,
    pub receiver: Arc<Receiver>,
    pub ping: Arc<RwLock<i64>>,
    pub_key: Arc<RwLock<Option<Vec<u8>>>>,
    pub rho_connection: Arc<RwLock<Option<Arc<RhoConnection>>>>,
    is_open: Arc<RwLock<bool>>,
}

impl AppConnection {
    pub async fn from_general(general: Arc<GeneralConnection>, user_id: u64) -> Arc<Self> {
        Arc::new(Self {
            ping: Arc::new(RwLock::new(0)),
            pub_key: Arc::new(RwLock::new(None)),
            rho_connection: general.rho_connection.clone(),
            is_open: Arc::new(RwLock::new(true)),
            sender: general.sender.clone(),
            receiver: general.receiver.clone(),
            user_id: user_id,
            app_identifier: general.app_identifier.read().await.clone().unwrap(),
            app_session: general.app_session.read().await.clone().unwrap(),
            client_version: general.client_version.read().await.clone(),
        })
    }
    pub fn start(self: Arc<Self>) {
        let self_clone = self.clone();
        tokio::spawn(async move {
            while let Ok(cv) = self_clone.receiver.receive().await {
                self_clone.clone().handle_message(cv).await;
            }
            self_clone.handle_close().await;
        });

        let self_clone2 = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            if self_clone2.get_rho_connection().await.is_none() {
                self_clone2
                    .send_error_response(0, CommunicationType::ErrorNoIota)
                    .await;
            }
        });
    }

    /// Get the user ID
    pub async fn get_user_id(&self) -> u64 {
        self.user_id
    }

    /// Get current ping
    #[allow(unused)]
    pub async fn get_ping(&self) -> i64 {
        *self.ping.read().await
    }

    /// Get RhoConnection if available
    pub async fn get_rho_connection(&self) -> Option<Arc<RhoConnection>> {
        self.rho_connection.read().await.clone()
    }

    /// Send a CommunicationValue to the app
    pub async fn send_message(self: Arc<Self>, cv: &CommunicationValue) {
        if !*self.is_open.read().await {
            log_out!(
                self.user_id as i64,
                PrintType::App,
                "Attempted to send message to a closed connection."
            );
            return;
        }
        if !cv.is_type(CommunicationType::Pong) && !cv.is_type(CommunicationType::Ping) {
            log_cv_out!(PrintType::App, &cv);
        }
        let _ = self.sender.send(&cv).await;
    }

    /// Handle incoming message from app
    pub async fn handle_message(self: Arc<Self>, cv: CommunicationValue) {
        tokio::spawn(async move {
            if cv.is_type(CommunicationType::Ping) {
                self.handle_ping(cv).await;
                return;
            }
            log_cv_in!(PrintType::App, cv);

            if cv.is_type(CommunicationType::GetUserData) {
                if let Some(anonymous) = {
                    if let Some(user_id) = cv.get_data(DataType::UserId).as_number() {
                        anonymous_manager::get_anonymous_user(user_id as u64).await
                    } else if let Some(username) = cv.get_data(DataType::Username).as_str() {
                        anonymous_manager::get_anonymous_user_by_name(username.to_string()).await
                    } else {
                        None
                    }
                } {
                    let response = CommunicationValue::new(CommunicationType::GetUserData)
                        .with_id(cv.get_id())
                        .add_typed_default(
                            DataType::Username,
                            DataValue::Str(anonymous.get_user_name().await),
                        )
                        .add_typed_default(
                            DataType::UserId,
                            DataValue::SignedNumber(anonymous.get_user_id().into()),
                        )
                        .add_typed_default(
                            DataType::Display,
                            DataValue::Str(anonymous.get_display_name().await),
                        )
                        .add_typed_default(
                            DataType::Avatar,
                            DataValue::Str(anonymous.get_avatar().await),
                        )
                        .add_typed_default(
                            DataType::UserState,
                            DataValue::Str("online".to_string()),
                        );

                    self.send_message(&response).await;

                    return;
                }
            }

            if cv.is_type(CommunicationType::GetUserData)
                || cv.is_type(CommunicationType::GetIotaData)
            {
                let sender = self.get_user_id().await;
                self.handle_omega_forward(cv.with_sender(sender as u64))
                    .await;
                return;
            }
            // Forward other messages to Iota
            self.forward_to_iota(cv).await;
        });
    }
    async fn handle_omega_forward(self: Arc<Self>, cv: CommunicationValue) {
        let app_for_closure = self.clone();
        tokio::spawn(async move {
            let response_cv = get_omega_connection()
                .await_response(&cv.with_sender(self.user_id), Some(Duration::from_secs(20)))
                .await;
            if let Ok(response_cv) = response_cv {
                app_for_closure.send_message(&response_cv).await;
            }
        });
    }

    /// Handle ping message
    async fn handle_ping(self: Arc<Self>, cv: CommunicationValue) {
        // Update our ping if provided
        if let DataValue::SignedNumber(last_ping) = cv.get_data(DataType::LastPing) {
            let current = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis();
            let mut ping_guard = self.ping.write().await;
            *ping_guard = (current as i128 - *last_ping) as i64;
        }

        // Get Iota ping from RhoConnection
        let iota_ping = if let Some(rho_conn) = self.get_rho_connection().await {
            rho_conn.get_iota_connection().get_ping().await
        } else {
            -1
        };

        // Send pong response
        let response = CommunicationValue::new(CommunicationType::Pong)
            .with_id(cv.get_id())
            .add_typed_default(
                DataType::PingIota,
                DataValue::SignedNumber(iota_ping.into()),
            );

        self.send_message(&response).await;
    }

    /// Forward message to Iota
    async fn forward_to_iota(self: Arc<Self>, cv: CommunicationValue) {
        let sender_user_id = self.get_user_id().await;
        let msg_id = cv.get_id();
        let msg_type = cv.get_type();

        log_in!(
            sender_user_id as i64,
            PrintType::App,
            "Forwarding app->iota: sender={} type={:?} id={} receiver={}",
            sender_user_id,
            msg_type,
            msg_id,
            cv.get_receiver()
        );

        if cv.is_type(CommunicationType::AddConversation)
            && cv.get_data(DataType::ChatPartnerId).as_number().is_none()
        {
            let chat_partner_name = cv
                .get_data(DataType::ChatPartnerName)
                .as_str()
                .unwrap_or("")
                .to_string();

            if anonymous_manager::get_anonymous_user_by_name(chat_partner_name.to_string())
                .await
                .is_some()
            {
                self.send_error_response(cv.get_id(), CommunicationType::ErrorAnonymous)
                    .await;
                return;
            }

            let load_uuid_response = get_omega_connection()
                .await_response(
                    &CommunicationValue::new(CommunicationType::GetUserData)
                        .with_id(cv.clone().get_id())
                        .add_typed_default(
                            DataType::Username,
                            DataValue::Str(chat_partner_name.clone()),
                        ),
                    Some(Duration::from_secs(20)),
                )
                .await;
            let chat_partner_id = {
                if let Ok(load_uuid_response) = load_uuid_response {
                    load_uuid_response.get_data(DataType::UserId).clone()
                } else {
                    DataValue::Null
                }
            };

            if let Some(rho_conn) = self.get_rho_connection().await {
                let iota_id = rho_conn.get_iota_id().await;
                log_in!(
                    sender_user_id as i64,
                    PrintType::App,
                    "Resolved rho for add_conversation: sender={} -> iota_id={} id={}",
                    sender_user_id,
                    iota_id,
                    msg_id
                );

                let updated_cv = cv
                    .with_sender(sender_user_id as u64)
                    .add_typed_default(DataType::ChatPartnerId, chat_partner_id);
                rho_conn.message_to_iota(updated_cv).await;
            } else {
                log_err!(
                    sender_user_id as i64,
                    PrintType::App,
                    "No rho/iota mapping found for add_conversation sender={} type={:?} id={}",
                    sender_user_id,
                    msg_type,
                    msg_id
                );
            }
            return;
        }

        if let Some(rho_conn) = self.get_rho_connection().await {
            let iota_id = rho_conn.get_iota_id().await;
            log_in!(
                sender_user_id as i64,
                PrintType::App,
                "Resolved rho for forward: sender={} -> iota_id={} type={:?} id={}",
                sender_user_id,
                iota_id,
                msg_type,
                msg_id
            );

            let updated_cv = cv.with_sender(sender_user_id as u64);
            rho_conn.message_to_iota(updated_cv).await;
        } else {
            log_err!(
                sender_user_id as i64,
                PrintType::App,
                "No rho/iota mapping found for sender={} type={:?} id={}",
                sender_user_id,
                msg_type,
                msg_id
            );
            let error_cv = CommunicationValue::new(CommunicationType::ErrorNoIota)
                .with_id(msg_id)
                .add_typed_default(
                    DataType::UserId,
                    DataValue::SignedNumber(sender_user_id.into()),
                );
            self.send_message(&error_cv).await;
        }
    }

    /// Send error response
    async fn send_error_response(self: Arc<Self>, message_id: u32, error_type: CommunicationType) {
        let error = CommunicationValue::new(error_type).with_id(message_id);
        self.send_message(&error).await;
    }

    /// Close the connection
    #[allow(unused)]
    pub async fn close(&self) {
        let mut is_open_guard = self.is_open.write().await;
        if !*is_open_guard {
            return;
        }
        *is_open_guard = false;

        let _ = self.sender.close();
    }

    /// Handle connection close
    pub async fn handle_close(&self) {
        let user_id = self.get_user_id().await;
        if let Some(rho_conn) = rho_manager::get_rho_con_for_user(user_id as i64).await {
            rho_conn.close_app_connection(Arc::new(self.clone())).await;
        }
    }
}

// Implement Clone to make it easier to work with Arc<AppConnection>
impl Clone for AppConnection {
    fn clone(&self) -> Self {
        Self {
            sender: Arc::clone(&self.sender),
            receiver: Arc::clone(&self.receiver),
            user_id: self.user_id,
            app_identifier: self.app_identifier.clone(),
            app_session: self.app_session,
            client_version: self.client_version.clone(),
            ping: Arc::clone(&self.ping),
            pub_key: Arc::clone(&self.pub_key),
            rho_connection: Arc::clone(&self.rho_connection),
            is_open: Arc::clone(&self.is_open),
        }
    }
}
