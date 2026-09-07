use std::{str::FromStr, sync::Arc, time::Duration};

use livekit_api::{
    access_token::{self},
    services::room::{CreateRoomOptions, RoomClient},
};
use livekit_protocol::Room;
use uuid::Uuid;

use crate::{
    calls::{call_manager::CallManager, error::CallError},
    config::LiveKitConfig,
    log, log_err,
    util::logger::PrintType,
};

const LIVEKIT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

pub struct LiveKitService {
    config: Option<LiveKitConfig>,
}

impl LiveKitService {
    pub fn new(config: Option<LiveKitConfig>) -> Self {
        Self { config }
    }

    fn livekit_config(&self) -> Result<&LiveKitConfig, CallError> {
        self.config.as_ref().ok_or(CallError::NotConfigured)
    }

    fn room_client(&self) -> Result<RoomClient, CallError> {
        let config = self.livekit_config()?;
        Ok(RoomClient::with_api_key(
            &config.hostname,
            &config.api_key,
            &config.api_secret,
        ))
    }

    pub async fn create_room(&self, call_id: Uuid) -> Result<(), CallError> {
        tokio::time::timeout(
            LIVEKIT_REQUEST_TIMEOUT,
            self.room_client()?
                .create_room(&call_id.to_string(), CreateRoomOptions::default()),
        )
        .await
        .map_err(|_| CallError::RequestTimedOut { call_id })?
        .map_err(|error| CallError::RoomCreationFailed {
            call_id,
            detail: error.to_string(),
        })?;
        Ok(())
    }

    pub fn create_token(
        &self,
        user_id: u64,
        call_id: Uuid,
        has_admin: bool,
    ) -> Result<String, CallError> {
        let config = self.livekit_config()?;
        access_token::AccessToken::with_api_key(&config.api_key, &config.api_secret)
            .with_identity(&user_id.to_string())
            .with_grants(access_token::VideoGrants {
                room_join: true,
                can_update_own_metadata: true,
                room_admin: has_admin,
                room: call_id.to_string(),
                ..Default::default()
            })
            .to_jwt()
            .map_err(|error| CallError::TokenCreationFailed {
                detail: error.to_string(),
            })
    }

    #[allow(dead_code)]
    pub async fn get_room(&self, call_id: Uuid) -> Result<(RoomClient, Room), CallError> {
        let room_service = self.room_client()?;
        let rooms =
            tokio::time::timeout(LIVEKIT_REQUEST_TIMEOUT, room_service.list_rooms(Vec::new()))
                .await
                .map_err(|_| CallError::RequestTimedOut { call_id })?
                .map_err(|error| CallError::RoomLookupFailed {
                    detail: error.to_string(),
                })?;

        rooms
            .into_iter()
            .find(|room| room.name == call_id.to_string())
            .map(|room| (room_service, room))
            .ok_or(CallError::RoomNotFound { call_id })
    }

    pub async fn remove_participant(&self, call_id: Uuid, user_id: u64) -> Result<(), CallError> {
        tokio::time::timeout(
            LIVEKIT_REQUEST_TIMEOUT,
            self.room_client()?
                .remove_participant(&call_id.to_string(), &user_id.to_string()),
        )
        .await
        .map_err(|_| CallError::RequestTimedOut { call_id })?
        .map_err(|error| CallError::ParticipantRemovalFailed {
            call_id,
            user_id,
            detail: error.to_string(),
        })?;
        Ok(())
    }

    pub async fn delete_room(&self, call_id: Uuid) -> Result<(), CallError> {
        tokio::time::timeout(
            LIVEKIT_REQUEST_TIMEOUT,
            self.room_client()?.delete_room(&call_id.to_string()),
        )
        .await
        .map_err(|_| CallError::RequestTimedOut { call_id })?
        .map_err(|error| CallError::RoomCreationFailed {
            call_id,
            detail: error.to_string(),
        })?;
        Ok(())
    }

    #[allow(dead_code)]
    pub async fn get_room_metadata(&self, call_id: Uuid) -> Result<String, CallError> {
        let (_, room) = self.get_room(call_id).await?;
        Ok(room.metadata)
    }

    pub async fn set_room_metadata(
        &self,
        call_id: Uuid,
        metadata: String,
    ) -> Result<(), CallError> {
        tokio::time::timeout(
            LIVEKIT_REQUEST_TIMEOUT,
            self.room_client()?
                .update_room_metadata(&call_id.to_string(), &metadata),
        )
        .await
        .map_err(|_| CallError::RequestTimedOut { call_id })?
        .map_err(|error| CallError::MetadataUpdateFailed {
            call_id,
            detail: error.to_string(),
        })?;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn garbage_collect_calls(self: Arc<Self>, manager: Arc<CallManager>) {
        tokio::spawn(async move {
            loop {
                match self.room_client() {
                    Ok(room_service) => clean_calls(&manager, room_service).await,
                    Err(CallError::NotConfigured) => return,
                    Err(error) => log_err!(0, PrintType::Call, "Call cleanup skipped: {error}"),
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        });
    }
}

#[allow(dead_code)]
pub async fn clean_calls(manager: &CallManager, room_service: RoomClient) {
    let rooms =
        match tokio::time::timeout(LIVEKIT_REQUEST_TIMEOUT, room_service.list_rooms(Vec::new()))
            .await
        {
            Ok(Ok(rooms)) => rooms,
            Ok(Err(error)) => {
                log_err!(
                    0,
                    PrintType::Call,
                    "Unable to list LiveKit rooms during cleanup: {error}"
                );
                return;
            }
            Err(_) => {
                log_err!(0, PrintType::Call, "LiveKit room cleanup timed out");
                return;
            }
        };

    let mut call_ids = Vec::new();
    for room in rooms {
        if let Ok(id) = Uuid::from_str(&room.name) {
            call_ids.push(id);
        }
    }

    let size_pre = manager.groups.len();
    let tracked_calls = manager
        .groups
        .iter()
        .map(|entry| *entry.key())
        .collect::<Vec<_>>();
    for id in tracked_calls {
        if !call_ids.contains(&id) {
            manager.groups.remove(&id);
        }
    }

    let size_post = manager.groups.len();
    if size_pre != size_post {
        log!(
            0,
            PrintType::Call,
            "Cleaned {} calls, {} remaining",
            size_pre.saturating_sub(size_post),
            size_post
        );
    }
}
