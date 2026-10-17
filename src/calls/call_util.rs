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
    mutation_journal_path: std::path::PathBuf,
}

struct LiveKitMutation {
    journal: crate::omega::MutationJournal,
    operation_id: String,
    call_id: Uuid,
}

impl LiveKitMutation {
    fn complete(self) -> Result<(), CallError> {
        self.journal
            .resolve_record(&self.operation_id, br#"{"outcome":"completed"}"#)
            .map_err(|detail| CallError::MutationRecovery {
                call_id: self.call_id,
                detail,
            })
    }
}

impl LiveKitService {
    pub fn new(config: Option<LiveKitConfig>) -> Self {
        Self {
            config,
            mutation_journal_path: crate::omega::mutation_journal_path(),
        }
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

    fn mutation(
        &self,
        call_id: Uuid,
        operation: &str,
        arguments: serde_json::Value,
    ) -> Result<LiveKitMutation, CallError> {
        let hostname = &self.livekit_config()?.hostname;
        let prepare = || -> Result<_, String> {
            let journal = crate::omega::MutationJournal::open(&self.mutation_journal_path)?;
            let request = serde_json::to_vec(&serde_json::json!({
                "service": "livekit", "hostname": hostname, "call_id": call_id.to_string(),
                "operation": operation,
                "user_id": arguments.get("user_id").and_then(serde_json::Value::as_u64),
                "arguments_fingerprint": mtp::crypto::sha256(&serde_json::to_vec(&arguments).map_err(|error| error.to_string())?),
            }))
            .map_err(|error| error.to_string())?;
            let operation_id = journal.begin_record(&request)?;
            Ok(LiveKitMutation {
                journal,
                operation_id,
                call_id,
            })
        };
        prepare().map_err(|detail| CallError::MutationRecovery { call_id, detail })
    }

    pub async fn create_room(&self, call_id: Uuid) -> Result<(), CallError> {
        let client = self.room_client()?;
        let mutation = self.mutation(call_id, "create_room", serde_json::json!({}))?;
        tokio::time::timeout(
            LIVEKIT_REQUEST_TIMEOUT,
            client.create_room(&call_id.to_string(), CreateRoomOptions::default()),
        )
        .await
        .map_err(|_| CallError::RequestTimedOut { call_id })?
        .map_err(|error| CallError::RoomCreationFailed {
            call_id,
            detail: error.to_string(),
        })?;
        mutation.complete()
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
        let client = self.room_client()?;
        let mutation = self.mutation(
            call_id,
            "remove_participant",
            serde_json::json!({"user_id": user_id}),
        )?;
        let result = tokio::time::timeout(
            LIVEKIT_REQUEST_TIMEOUT,
            client.remove_participant(&call_id.to_string(), &user_id.to_string()),
        )
        .await
        .map_err(|_| CallError::RequestTimedOut { call_id })?
        .map_err(|error| {
            let detail = error.to_string();
            if detail.contains("not_found:") || detail.contains("does not exist") {
                CallError::RoomNotFound { call_id }
            } else {
                CallError::ParticipantRemovalFailed {
                    call_id,
                    user_id,
                    detail,
                }
            }
        });
        if result.is_ok() || matches!(result, Err(CallError::RoomNotFound { .. })) {
            mutation.complete()?;
        }
        result.map(|_| ())
    }

    pub async fn participant_ids(&self, call_id: Uuid) -> Result<Vec<u64>, CallError> {
        let participants = tokio::time::timeout(
            LIVEKIT_REQUEST_TIMEOUT,
            self.room_client()?.list_participants(&call_id.to_string()),
        )
        .await
        .map_err(|_| CallError::RequestTimedOut { call_id })?
        .map_err(|error| {
            let detail = error.to_string();
            if detail.contains("not_found:") || detail.contains("requested room does not exist") {
                CallError::RoomNotFound { call_id }
            } else {
                CallError::RoomLookupFailed { detail }
            }
        })?;
        Ok(participants
            .into_iter()
            .filter_map(|p| p.identity.parse().ok())
            .collect())
    }

    pub async fn delete_room(&self, call_id: Uuid) -> Result<(), CallError> {
        let client = self.room_client()?;
        let mutation = self.mutation(call_id, "delete_room", serde_json::json!({}))?;
        let result = tokio::time::timeout(
            LIVEKIT_REQUEST_TIMEOUT,
            client.delete_room(&call_id.to_string()),
        )
        .await
        .map_err(|_| CallError::RequestTimedOut { call_id })?
        .map_err(|error| {
            let detail = error.to_string();
            if detail.contains("not_found:") || detail.contains("requested room does not exist") {
                CallError::RoomNotFound { call_id }
            } else {
                CallError::RoomCreationFailed { call_id, detail }
            }
        });
        if result.is_ok() || matches!(result, Err(CallError::RoomNotFound { .. })) {
            mutation.complete()?;
        }
        result.map(|_| ())
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
        let client = self.room_client()?;
        let mutation = self.mutation(
            call_id,
            "set_room_metadata",
            serde_json::json!({"metadata": metadata}),
        )?;
        tokio::time::timeout(
            LIVEKIT_REQUEST_TIMEOUT,
            client.update_room_metadata(&call_id.to_string(), &metadata),
        )
        .await
        .map_err(|_| CallError::RequestTimedOut { call_id })?
        .map_err(|error| CallError::MetadataUpdateFailed {
            call_id,
            detail: error.to_string(),
        })?;
        mutation.complete()
    }

    #[allow(dead_code)]
    pub fn garbage_collect_calls(
        self: Arc<Self>,
        manager: Arc<CallManager>,
        rho: Arc<crate::rho::rho_manager::RhoManager>,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) {
        let mut tasks = tokio::task::JoinSet::new();
        tasks.spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(2));
            loop {
                tokio::select! {
                    biased;
                    _ = shutdown.wait_for(|stop| *stop) => return,
                    _ = interval.tick() => {},
                }
                // Once admitted, finish this mutation-bearing cycle even if
                // shutdown starts. The process drain observes it under its budget.
                match self.room_client() {
                    Ok(room_service) => clean_calls(&manager, room_service, &rho).await,
                    Err(CallError::NotConfigured) => return,
                    Err(error) => log_err!(0, PrintType::Call, "Call cleanup skipped: {error}"),
                }
            }
        });
        drop(crate::rho::tasks::supervise(tasks));
    }
}

/*
 * Server-side teardown (expiry, empty-room grace, vanished room) must reach
 * connected clients the same way an explicit end does.
 */
async fn notify_call_ended(
    rho: &crate::rho::rho_manager::RhoManager,
    id: Uuid,
    group: &crate::calls::call_group::CallGroup,
) {
    use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
    let users: Vec<u64> = {
        let state = group.state.read().await;
        state
            .members
            .keys()
            .chain(state.pending_invites.keys())
            .copied()
            .collect()
    };
    for user in users {
        if let Some(rho_conn) = rho.get_for_user(user as i64).await {
            let event = CommunicationValue::new(CommunicationType::CallEnded)
                .with_receiver(user)
                .add_typed_default(DataType::CallId, DataValue::Str(id.to_string()));
            let _ = rho_conn.send_to_local_user(user, &event).await;
        }
    }
}

#[allow(dead_code)]
pub async fn clean_calls(
    manager: &CallManager,
    room_service: RoomClient,
    rho: &crate::rho::rho_manager::RhoManager,
) {
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

    let mut live_rooms = std::collections::HashMap::new();
    for room in rooms {
        if let Ok(id) = Uuid::from_str(&room.name) {
            live_rooms.insert(id, room.num_participants);
        }
    }

    let size_pre = manager.groups.len();
    let tracked_calls = manager
        .groups
        .iter()
        .map(|entry| *entry.key())
        .collect::<Vec<_>>();
    for id in tracked_calls {
        let now = CallManager::timestamp();
        let Some(group) = manager.get_call(id).await else {
            continue;
        };
        if now >= group.created_at_ms + 259_200_000 {
            if !matches!(
                manager.livekit.delete_room(id).await,
                Ok(()) | Err(CallError::RoomNotFound { .. })
            ) {
                continue;
            }
            {
                let mut state = group.state.write().await;
                if let Some(db) = &manager.persistence
                    && db.remove(id).is_err()
                {
                    continue;
                }
                state.ending = true;
                manager.groups.remove(&id);
            }
            notify_call_ended(rho, id, &group).await;
            continue;
        }

        match live_rooms.get(&id) {
            Some(&participants) if participants > 0 => {
                let identities = match tokio::time::timeout(
                    LIVEKIT_REQUEST_TIMEOUT,
                    room_service.list_participants(&id.to_string()),
                )
                .await
                {
                    Ok(Ok(participants)) => participants
                        .into_iter()
                        .filter_map(|p| p.identity.parse().ok())
                        .collect::<Vec<_>>(),
                    _ => continue,
                };
                if manager
                    .reconcile_participants(id, &identities)
                    .await
                    .is_err()
                {
                    continue;
                }
                if let Some(db) = &manager.persistence {
                    let _ = db.set_empty_since(id, None);
                }
            }
            _ => {
                if manager.reconcile_participants(id, &[]).await.is_err() {
                    continue;
                }
                if let Some(db) = &manager.persistence
                    && let Ok(since) = db.empty_since(id, now)
                    && now - since >= 300_000
                {
                    if !matches!(
                        manager.livekit.delete_room(id).await,
                        Ok(()) | Err(CallError::RoomNotFound { .. })
                    ) {
                        continue;
                    }
                    {
                        let mut state = group.state.write().await;
                        if db.remove(id).is_err() {
                            continue;
                        }
                        state.ending = true;
                        manager.groups.remove(&id);
                    }
                    notify_call_ended(rho, id, &group).await;
                }
            }
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
