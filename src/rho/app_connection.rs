use crate::anonymous_clients::anonymous_manager;
use crate::app_state::AppState;
use crate::rho::connection::{
    GeneralConnection, MtpReceiver, MtpSender, OptionalDataValueCompat, RequiredMtpFields,
};
use crate::rho::relay_router::{self, RelaySource};
use crate::rho::rho_connection::RhoConnection;
use crate::util::logger::PrintType;
use crate::{log_cv_in, log_cv_out, log_err, log_out};
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use uuid::Uuid;

pub struct AppConnection {
    pub state: Arc<AppState>,
    pub user_id: u64,
    pub app_identifier: String,
    pub app_session: Uuid,
    pub client_version: String,

    pub sender: Arc<MtpSender>,
    pub receiver: Arc<MtpReceiver>,
    pub_key: Arc<RwLock<Option<Vec<u8>>>>,
    pub rho_connection: Arc<RwLock<Option<Arc<RhoConnection>>>>,
    is_open: Arc<RwLock<bool>>,
}

impl AppConnection {
    pub async fn from_general(general: Arc<GeneralConnection>, user_id: u64) -> Arc<Self> {
        Arc::new(Self {
            state: general.state.clone(),
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
        log_cv_out!(PrintType::App, &cv);
        let _ = self.sender.send(&cv).await;
    }

    /// Handle incoming message from app
    pub async fn handle_message(self: Arc<Self>, cv: CommunicationValue) {
        tokio::spawn(async move {
            let message_id = match cv.require_id() {
                Ok(message_id) => message_id,
                Err(error) => {
                    log_err!(
                        self.user_id as i64,
                        PrintType::App,
                        "Rejected malformed message: {}",
                        error
                    );
                    let response =
                        CommunicationValue::new(CommunicationType::ErrorInvalidData).without_id();
                    self.send_message(&response).await;
                    return;
                }
            };
            log_cv_in!(PrintType::App, cv);

            if cv.is_type(CommunicationType::Relay) {
                let next_hop = match cv.require_receiver() {
                    Ok(next_hop) => next_hop,
                    Err(error) => {
                        log_err!(
                            self.user_id as i64,
                            PrintType::App,
                            "Rejected malformed relay: {}",
                            error
                        );
                        self.send_error_response(message_id, CommunicationType::ErrorInvalidData)
                            .await;
                        return;
                    }
                };
                let result = match self.get_rho_connection().await {
                    Some(rho) => {
                        relay_router::route_relay(
                            &self.state,
                            RelaySource::Client {
                                iota_id: rho.get_iota_id().await,
                            },
                            relay_router::ensure_relay_frame_id(cv),
                        )
                        .await
                    }
                    None => Err(relay_router::RelayRouteError::DestinationIotaNotLocal),
                };
                let response = match result {
                    Ok(()) => {
                        CommunicationValue::new(CommunicationType::Success).with_id(message_id)
                    }
                    Err(error) => {
                        log_err!(
                            self.user_id as i64,
                            PrintType::App,
                            "Relay routing failed for destination Iota {}: {}",
                            next_hop,
                            error
                        );
                        CommunicationValue::new(relay_router::error_response_type(&error))
                            .with_id(message_id)
                    }
                };
                self.send_message(&response).await;
                return;
            }

            if cv.is_type(CommunicationType::Success) {
                if let Some(rho) = self.get_rho_connection().await {
                    rho.forward_relay_ack(self.user_id, message_id).await;
                }
                return;
            }

            if matches!(
                relay_router::message_security_class(&cv),
                relay_router::MessageSecurityClass::RelayOnly
            ) {
                self.send_error_response(message_id, CommunicationType::ErrorInvalidData)
                    .await;
                return;
            }

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
                        .with_id(message_id)
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
            log_err!(
                self.user_id as i64,
                PrintType::App,
                "Rejected unsupported communication type {}",
                cv.get_type()
            );
            self.send_error_response(message_id, CommunicationType::ErrorInvalidData)
                .await;
        });
    }
    async fn handle_omega_forward(self: Arc<Self>, cv: CommunicationValue) {
        let app_for_closure = self.clone();
        tokio::spawn(async move {
            let response_cv = self
                .state
                .omega
                .clone()
                .await_response(&cv.with_sender(self.user_id), Some(Duration::from_secs(20)))
                .await;
            if let Ok(response_cv) = response_cv {
                app_for_closure.send_message(&response_cv).await;
            }
        });
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
        if let Some(rho_conn) = self.state.rho.get_for_user(user_id as i64).await {
            rho_conn.close_app_connection(Arc::new(self.clone())).await;
        }
    }
}

// Implement Clone to make it easier to work with Arc<AppConnection>
impl Clone for AppConnection {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
            sender: Arc::clone(&self.sender),
            receiver: Arc::clone(&self.receiver),
            user_id: self.user_id,
            app_identifier: self.app_identifier.clone(),
            app_session: self.app_session,
            client_version: self.client_version.clone(),
            pub_key: Arc::clone(&self.pub_key),
            rho_connection: Arc::clone(&self.rho_connection),
            is_open: Arc::clone(&self.is_open),
        }
    }
}
