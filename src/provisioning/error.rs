use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ProvisioningError {
    #[error("provisioning session does not exist")]
    UnknownSession,
    #[error("provisioning session expired")]
    Expired,
    #[error("participant belongs to another session")]
    WrongSession,
    #[error("participant already has an active session")]
    AlreadyInSession,
    #[error("provisioning session limit reached")]
    SessionLimit,
    #[error("provisioning role is already occupied")]
    RoleOccupied,
    #[error("wrong provisioning participant")]
    WrongParticipant,
    #[error("operation is invalid in the current state")]
    InvalidState,
    #[error("operation is invalid for this provisioning method")]
    WrongMethod,
    #[error("credential recipient is not the contact")]
    WrongRecipient,
    #[error("required peer is missing")]
    PeerMissing,
    #[error("owner confirmation is required")]
    ConfirmationRequired,
}

// The connection handler still returns static errors for its wire parsing helpers.
impl From<ProvisioningError> for &'static str {
    fn from(error: ProvisioningError) -> Self {
        match error {
            ProvisioningError::UnknownSession => "provisioning session does not exist",
            ProvisioningError::Expired => "provisioning session expired",
            ProvisioningError::WrongSession => "participant belongs to another session",
            ProvisioningError::AlreadyInSession => "participant already has an active session",
            ProvisioningError::SessionLimit => "provisioning session limit reached",
            ProvisioningError::RoleOccupied => "provisioning role is already occupied",
            ProvisioningError::WrongParticipant => "wrong provisioning participant",
            ProvisioningError::InvalidState => "operation is invalid in the current state",
            ProvisioningError::WrongMethod => "operation is invalid for this provisioning method",
            ProvisioningError::WrongRecipient => "credential recipient is not the contact",
            ProvisioningError::PeerMissing => "required peer is missing",
            ProvisioningError::ConfirmationRequired => "owner confirmation is required",
        }
    }
}
