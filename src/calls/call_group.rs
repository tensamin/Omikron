use epsilon_core::{CommunicationType, CommunicationValue, DataTypes, DataValue};

use std::{env, sync::Arc, time::Duration};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::{
    calls::{call_util, caller::Caller},
    omega::omega_connection::get_omega_connection,
};

pub struct CallGroup {
    pub call_id: Uuid,
    pub members: RwLock<Vec<Arc<Caller>>>,
    pub show: RwLock<bool>,
    pub anonymous_joining: RwLock<bool>,
    pub short_link: RwLock<Option<String>>,
}

impl CallGroup {
    pub fn new(call_id: Uuid, user: Arc<Caller>) -> Self {
        CallGroup {
            call_id,
            members: RwLock::new(vec![user]),
            show: RwLock::new(true),
            anonymous_joining: RwLock::new(false),
            short_link: RwLock::new(None),
        }
    }

    pub async fn get_caller(&self, user_id: u64) -> Option<Arc<Caller>> {
        self.members
            .read()
            .await
            .iter()
            .find(|caller| caller.user_id == user_id)
            .cloned()
    }

    pub async fn is_anonymous(&self) -> bool {
        *self.anonymous_joining.read().await
    }

    pub async fn set_anonymous_joining(&self, enable: bool) {
        *self.anonymous_joining.write().await = enable;

        let _ = call_util::set_room_metadata(
            self.call_id,
            format!("{{\"anonymous_joining\": \"{}\"}}", enable),
        )
        .await;

        if self.short_link.read().await.is_none() {
            let long_link = format!(
                "https://app.tensamin.net/call/anonymous?call_id={}&omikron_id={}",
                self.call_id,
                env::var("ID")
                    .unwrap_or("0".to_string())
                    .parse::<i64>()
                    .unwrap_or(0),
            );
            let response_cv = get_omega_connection()
                .await_response(
                    &CommunicationValue::new(CommunicationType::shorten_link)
                        .add_data(DataTypes::link, DataValue::Str(long_link)),
                    Some(Duration::from_secs(20)),
                )
                .await;
            if let Ok(response) = response_cv {
                *self.short_link.write().await = Some(
                    response
                        .get_data(DataTypes::link)
                        .as_str()
                        .unwrap()
                        .to_string(),
                );
                log::info!(
                    "Shortened link for call {} is {}",
                    self.call_id,
                    self.short_link.read().await.as_ref().unwrap()
                );
            }
        }
    }

    pub async fn create_anonymous_token(&self, user_id: u64) -> Option<String> {
        if self.is_anonymous().await {
            if let Ok(token) = call_util::create_token(user_id, self.call_id, false) {
                return Some(token);
            }
        }
        None
    }

    pub async fn remove_caller(&self, user_id: u64) {
        let _ = call_util::remove_participant(self.call_id, user_id).await;
        self.members
            .write()
            .await
            .retain(|caller| caller.user_id != user_id);
    }

    pub async fn get_short_link(self: Arc<Self>) -> Option<String> {
        self.short_link.read().await.clone()
    }
}
