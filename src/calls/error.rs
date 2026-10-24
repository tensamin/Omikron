use thiserror::Error;

#[derive(Debug, Error)]
pub enum CallError {
    #[error("LiveKit is not configured")]
    NotConfigured,
    #[error("LiveKit request for room {call_id} timed out")]
    RequestTimedOut { call_id: uuid::Uuid },
    #[error("failed to create room {call_id}: {detail}")]
    RoomCreationFailed { call_id: uuid::Uuid, detail: String },
}
