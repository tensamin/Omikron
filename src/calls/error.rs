use thiserror::Error;

#[derive(Debug, Error)]
pub enum CallError {
    #[error("LiveKit is not configured")]
    NotConfigured,
    #[error("LiveKit request for room {call_id} timed out")]
    RequestTimedOut { call_id: uuid::Uuid },
    #[error("LiveKit mutation recovery for room {call_id} requires attention: {detail}")]
    MutationRecovery { call_id: uuid::Uuid, detail: String },
    #[error("failed to create room {call_id}: {detail}")]
    RoomCreationFailed { call_id: uuid::Uuid, detail: String },
    #[error("room {call_id} was not found")]
    RoomNotFound { call_id: uuid::Uuid },
    #[error("failed to list rooms: {detail}")]
    RoomLookupFailed { detail: String },
    #[error("failed to remove participant {user_id} from room {call_id}: {detail}")]
    ParticipantRemovalFailed {
        call_id: uuid::Uuid,
        user_id: u64,
        detail: String,
    },
    #[error("failed to update room {call_id} metadata: {detail}")]
    MetadataUpdateFailed { call_id: uuid::Uuid, detail: String },
    #[error("failed to create access token: {detail}")]
    TokenCreationFailed { detail: String },
}
