use std::{str::FromStr, sync::Arc, time::Duration};

use livekit_api::services::room::{CreateRoomOptions, RoomClient};
use uuid::Uuid;

use crate::{
    calls::{call_manager::CallManager, error::CallError},
    config::LiveKitConfig,
    log_err,
    util::logger::PrintType,
};

const LIVEKIT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

pub struct LiveKitService {
    config: Option<LiveKitConfig>,
    pub(super) management_lock: tokio::sync::Mutex<()>,
    pub(super) legacy_call_bindings:
        dashmap::DashMap<tau::calls::CallId, tau::calls::CallAuthority>,
    pub(super) management_owner_id: std::sync::atomic::AtomicU64,
    pub(super) metadata_revisions: dashmap::DashMap<tau::calls::CallId, u64>,
}

impl LiveKitService {
    pub fn new(config: Option<LiveKitConfig>) -> Self {
        Self {
            config,
            management_lock: tokio::sync::Mutex::new(()),
            legacy_call_bindings: dashmap::DashMap::new(),
            management_owner_id: std::sync::atomic::AtomicU64::new(0),
            metadata_revisions: dashmap::DashMap::new(),
        }
    }

    pub(super) fn livekit_config(&self) -> Result<&LiveKitConfig, CallError> {
        self.config.as_ref().ok_or(CallError::NotConfigured)
    }

    pub(super) fn room_client(&self) -> Result<RoomClient, CallError> {
        let config = self.livekit_config()?;
        Ok(
            RoomClient::with_api_key(&config.hostname, &config.api_key, &config.api_secret)
                .with_request_timeout(LIVEKIT_REQUEST_TIMEOUT),
        )
    }

    pub async fn create_room(&self, call_id: Uuid) -> Result<(), CallError> {
        let client = self.room_client()?;
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
        Ok(())
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

#[allow(dead_code)]
pub async fn clean_calls(
    manager: &CallManager,
    room_service: RoomClient,
    _rho: &crate::rho::rho_manager::RhoManager,
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

    let tracked_calls = manager
        .groups
        .iter()
        .map(|entry| *entry.key())
        .collect::<Vec<_>>();
    for id in tracked_calls {
        let now = CallManager::timestamp();
        let Some(_group) = manager.get_call(id).await else {
            continue;
        };
        let occupied = match live_rooms.get(&id) {
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
                true
            }
            _ => {
                if manager.reconcile_participants(id, &[]).await.is_err() {
                    continue;
                }
                false
            }
        };
        if let Err(error) = manager.cleanup_observed(id, occupied, now).await {
            log_err!(
                0,
                PrintType::Call,
                "Call presence reconciliation failed for {id}: {error}"
            );
        }
    }
}
