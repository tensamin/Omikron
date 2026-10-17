use crate::app_state::AppState;
use crate::rho::connection::{
    GeneralConnection, MtpReceiver, MtpSender, OptionalDataValueExt, RequiredCommunicationFields,
};
use crate::util::logger::PrintType;
use crate::{log_cv_in, log_cv_out, log_err};
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

#[derive(Deserialize)]
struct TAuthLocator {
    target_iota_id: u64,
}

pub struct AppConnection {
    pub state: Arc<AppState>,
    _mtp_connection: Option<Arc<mtp::webserver::WebMTPConnection>>,
    connection_id: u64,
    pub sender: Arc<MtpSender>,
    pub receiver: Arc<MtpReceiver>,
    is_open: Arc<RwLock<bool>>,
    message_slots: Arc<tokio::sync::Semaphore>,
    tasks: super::tasks::MessageTasks,
}

impl AppConnection {
    pub async fn from_general(general: Arc<GeneralConnection>, connection_id: u64) -> Arc<Self> {
        Arc::new(Self {
            state: general.state.clone(),
            _mtp_connection: Some(general.mtp_connection.clone()),
            connection_id,
            sender: general.sender.clone(),
            receiver: general.receiver.clone(),
            is_open: Arc::new(RwLock::new(true)),
            message_slots: Arc::new(tokio::sync::Semaphore::new(32)),
            tasks: super::tasks::MessageTasks::new(
                general.shutdown.subscribe(),
                general.state.config.message_drain,
            ),
        })
    }

    pub async fn run(self: Arc<Self>) {
        while let Some(Ok(value)) = self
            .tasks
            .while_connected(&self.receiver, self.receiver.receive())
            .await
        {
            self.clone().handle_message(value).await;
        }
        self.tasks.drain().await;
        *self.is_open.write().await = false;
    }

    pub async fn send_message(self: Arc<Self>, value: &CommunicationValue) {
        if !*self.is_open.read().await {
            return;
        }
        log_cv_out!(PrintType::App, value);
        let _ = self.sender.send(value).await;
    }

    pub async fn handle_message(self: Arc<Self>, value: CommunicationValue) {
        let Some(Ok(permit)) = self
            .tasks
            .while_connected(&self.receiver, self.message_slots.clone().acquire_owned())
            .await
        else {
            return;
        };
        let connection = self.clone();
        if let Err(error) = connection.tasks.spawn_cancellable(async move {
            let _permit = permit;
            let message_id = match value.require_id() {
                Ok(message_id) => message_id,
                Err(_) => {
                    self.send_error(&value, "missing message ID").await;
                    return;
                }
            };
            log_cv_in!(PrintType::App, &value);
            if !is_tauth_command(&value) {
                self.send_error(&value, "raw MTP command is not available to TAuth apps")
                    .await;
                return;
            }
            let locator_value = value.get_data(DataType::Locator);
            let Some(locator_json) = locator_value.as_str() else {
                self.send_error(&value, "missing signed user route").await;
                return;
            };
            let locator = match serde_json::from_str::<TAuthLocator>(locator_json) {
                Ok(locator) if locator.target_iota_id > 0 => locator,
                _ => {
                    self.send_error(&value, "invalid signed user route").await;
                    return;
                }
            };
            let Some(rho) = self
                .state
                .rho
                .get_by_iota(locator.target_iota_id as i64)
                .await
            else {
                self.send_error(&value, "target Iota is offline").await;
                return;
            };
            let forwarded = value.clone().with_sender(self.connection_id);
            match rho
                .get_iota_connection()
                .clone()
                .await_response(&forwarded, Some(Duration::from_secs(20)))
                .await
            {
                Ok(response) => self.send_message(&response.with_id(message_id)).await,
                Err(error) => {
                    log_err!(
                        self.connection_id as i64,
                        PrintType::App,
                        "TAuth forwarding failed: {}",
                        error
                    );
                    self.send_error(&value, "target Iota request failed").await;
                }
            }
        }) {
            log_err!(
                connection.connection_id as i64,
                PrintType::App,
                "App message submission failed: {}",
                error
            );
            connection.sender.close();
        }
    }

    async fn send_error(self: Arc<Self>, request: &CommunicationValue, message: &str) {
        let latest = mtp::codec::TypeMap::latest();
        let response = tau::error_response(
            request,
            CommunicationType::ErrorInvalidData,
            request.type_map().unwrap_or(&latest),
        )
        .add_typed_default(DataType::Message, DataValue::Str(message.to_owned()));
        self.send_message(&response).await;
    }
}

fn is_tauth_command(value: &CommunicationValue) -> bool {
    matches!(
        value.get_comm_type_enum(),
        Some(
            CommunicationType::TAuthExchangeCode
                | CommunicationType::TAuthUser
                | CommunicationType::TAuthContacts
                | CommunicationType::TAuthPublicLookup
                | CommunicationType::TAuthMetadataGet
                | CommunicationType::TAuthMetadataSet
                | CommunicationType::TAuthMetadataDelete
                | CommunicationType::TAuthDisconnectDelete
        )
    )
}
