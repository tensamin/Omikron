use std::{
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};

use mtp::codec::{
    CommunicationType, CommunicationValue, DataType, DataValue, RelayError, forward_relay_frame,
};
use thiserror::Error;

use crate::{
    app_state::AppState, omega::omega_connection::OmegaConnection, rho::rho_manager::RhoManager,
};

const TARGET_KIND_MASK: u64 = 0xC000_0000_0000_0000;
const TARGET_ID_MASK: u64 = (1_u64 << 48) - 1;
const USER_TARGET_KIND: u64 = 0x4000_0000_0000_0000;
const IOTA_TARGET_KIND: u64 = 0x8000_0000_0000_0000;
static NEXT_RELAY_FRAME_ID: AtomicU32 = AtomicU32::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteTarget {
    User(u64),
    Iota(u64),
}

impl RouteTarget {
    #[allow(dead_code)]
    pub fn wire_id(self) -> Option<u64> {
        let (kind, id) = match self {
            Self::User(id) => (USER_TARGET_KIND, id),
            Self::Iota(id) => (IOTA_TARGET_KIND, id),
        };
        (id > 0 && id <= TARGET_ID_MASK).then_some(kind | id)
    }

    pub fn from_wire_id(value: u64) -> Option<Self> {
        let id = value & TARGET_ID_MASK;
        if id == 0 || value & !(TARGET_KIND_MASK | TARGET_ID_MASK) != 0 {
            return None;
        }

        match value & TARGET_KIND_MASK {
            USER_TARGET_KIND => Some(Self::User(id)),
            IOTA_TARGET_KIND => Some(Self::Iota(id)),
            _ => None,
        }
    }

    pub const fn id(self) -> u64 {
        match self {
            Self::User(id) | Self::Iota(id) => id,
        }
    }
}

impl std::fmt::Display for RouteTarget {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::User(id) => write!(formatter, "User({id})"),
            Self::Iota(id) => write!(formatter, "Iota({id})"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelaySource {
    Client { iota_id: u64 },
    Iota { iota_id: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageSecurityClass {
    RelayOnly,
    AuthenticatedPeerControl,
    AuthenticatedLocalRequest,
}

pub fn message_security_class(frame: &CommunicationValue) -> MessageSecurityClass {
    const RELAY_ONLY_TYPES: &[CommunicationType] = &[
        CommunicationType::MessageSend,
        CommunicationType::MessageLive,
        CommunicationType::MessageState,
        CommunicationType::MessageEdit,
        CommunicationType::MessageEditLive,
        CommunicationType::MessageReactionAdd,
        CommunicationType::MessageReactionRemove,
        CommunicationType::MessageReactionLive,
        CommunicationType::MessageDelete,
        CommunicationType::MessageDeleteLive,
        CommunicationType::MessageOtherIota,
        CommunicationType::SetChatSecret,
        CommunicationType::SendChat,
        CommunicationType::SettingsSave,
        CommunicationType::GlobalSettingsSave,
        CommunicationType::AddConversation,
        CommunicationType::AddCommunity,
        CommunicationType::RemoveCommunity,
    ];

    if RELAY_ONLY_TYPES.iter().any(|kind| frame.is_type(*kind)) {
        MessageSecurityClass::RelayOnly
    } else if frame.is_type(CommunicationType::GetChatSecret)
        || frame.is_type(CommunicationType::MessageGet)
        || frame.is_type(CommunicationType::MessagesGet)
        || frame.is_type(CommunicationType::SyncedSettingSet)
        || frame.is_type(CommunicationType::SyncedSettingGet)
        || frame.is_type(CommunicationType::SyncedSettingDelete)
        || frame.is_type(CommunicationType::SyncedSettingsList)
        || frame.is_type(CommunicationType::UserBlobPut)
        || frame.is_type(CommunicationType::UserBlobGet)
        || frame.is_type(CommunicationType::UserBlobDelete)
        || frame.is_type(CommunicationType::UserBlobList)
        || frame.is_type(CommunicationType::UserAssetUploadStart)
        || frame.is_type(CommunicationType::UserAssetUploadChunk)
        || frame.is_type(CommunicationType::UserAssetUploadStatus)
        || frame.is_type(CommunicationType::UserAssetUploadCommit)
        || frame.is_type(CommunicationType::UserAssetUploadAbort)
        || frame.is_type(CommunicationType::UserAssetGetChunk)
        || frame.is_type(CommunicationType::UserAssetList)
        || frame.is_type(CommunicationType::UserAssetDelete)
        || frame.is_type(CommunicationType::UserBlock)
        || frame.is_type(CommunicationType::UserUnblock)
        || frame.is_type(CommunicationType::BlockedUsersGet)
        || frame.is_type(CommunicationType::ReceiptPolicyGet)
        || frame.is_type(CommunicationType::ReceiptPolicySet)
        || frame.is_type(CommunicationType::MessageStoragePolicyGet)
        || frame.is_type(CommunicationType::MessageStoragePolicySet)
        || frame.is_type(CommunicationType::ReadNotification)
    {
        MessageSecurityClass::AuthenticatedPeerControl
    } else {
        MessageSecurityClass::AuthenticatedLocalRequest
    }
}

#[derive(Debug, Error)]
pub enum RelayRouteError {
    #[error("relay has no next-hop receiver")]
    MissingReceiver,
    #[error("relay has invalid route target {0}")]
    InvalidRouteTarget(u64),
    #[error("client relay destination {actual} is not its associated Iota {expected}")]
    InvalidClientRoute { expected: u64, actual: u64 },
    #[error("relay destination Iota is not connected to this Omikron")]
    DestinationIotaNotLocal,
    #[error("relay destination client is offline")]
    ClientOffline,
    #[error("relay route resolves back to its source Iota")]
    RouteLoop,
    #[error("relay send failed: {0}")]
    Send(String),
    #[error(transparent)]
    Relay(#[from] RelayError),
}

pub fn error_response_type(error: &RelayRouteError) -> CommunicationType {
    match error {
        RelayRouteError::DestinationIotaNotLocal | RelayRouteError::ClientOffline => {
            CommunicationType::ErrorNoIota
        }
        RelayRouteError::Send(_) => CommunicationType::ErrorInternal,
        RelayRouteError::MissingReceiver
        | RelayRouteError::InvalidRouteTarget(_)
        | RelayRouteError::InvalidClientRoute { .. }
        | RelayRouteError::RouteLoop
        | RelayRouteError::Relay(_) => CommunicationType::ErrorInvalidData,
    }
}

pub fn relay_route_error_response(
    message_id: u32,
    target: Option<RouteTarget>,
    error: &RelayRouteError,
) -> CommunicationValue {
    let mut response = CommunicationValue::new(error_response_type(error)).with_id(message_id);
    match (error, target) {
        (RelayRouteError::ClientOffline, Some(RouteTarget::User(user_id))) => {
            response = response
                .add_typed_default(DataType::ErrorType, DataValue::Str("client_offline".into()))
                .add_typed_default(DataType::UserId, DataValue::UnsignedNumber(user_id.into()));
        }
        (RelayRouteError::DestinationIotaNotLocal, Some(RouteTarget::Iota(iota_id))) => {
            response = response
                .add_typed_default(
                    DataType::ErrorType,
                    DataValue::Str("destination_iota_not_local".into()),
                )
                .add_typed_default(DataType::IotaId, DataValue::UnsignedNumber(iota_id.into()));
        }
        _ => {}
    }
    response
}

pub async fn route_relay(
    state: &Arc<AppState>,
    source: RelaySource,
    frame: CommunicationValue,
) -> Result<CommunicationValue, RelayRouteError> {
    let frame = ensure_relay_frame_id(frame);
    let (next_hop, frame) = match source {
        RelaySource::Client { iota_id } => prepare_client_frame(frame, iota_id)?,
        RelaySource::Iota { .. } => prepare_frame(frame)?,
    };
    validate_source_next_hop(source, next_hop)?;

    match source {
        RelaySource::Client { iota_id } => {
            let rho = state
                .rho
                .get_by_iota(
                    i64::try_from(iota_id)
                        .map_err(|_| RelayRouteError::InvalidRouteTarget(iota_id))?,
                )
                .await
                .ok_or(RelayRouteError::DestinationIotaNotLocal)?;
            let response = rho
                .await_relay_to_iota(&frame)
                .await
                .map_err(RelayRouteError::Send)?;
            route_response(response)
        }
        RelaySource::Iota { iota_id } => {
            route_from_iota(&state.rho, &state.omega, iota_id, next_hop, frame).await
        }
    }
}

pub async fn route_from_omega(
    rho: &RhoManager,
    frame: CommunicationValue,
) -> Result<CommunicationValue, RelayRouteError> {
    let (next_hop, frame) = prepare_frame(ensure_relay_frame_id(frame))?;
    let RouteTarget::Iota(iota_id) = next_hop else {
        return Err(RelayRouteError::InvalidRouteTarget(next_hop.id()));
    };
    let target = rho
        .get_by_iota(
            i64::try_from(iota_id).map_err(|_| RelayRouteError::InvalidRouteTarget(iota_id))?,
        )
        .await
        .ok_or(RelayRouteError::DestinationIotaNotLocal)?;
    let response = target
        .await_relay_to_iota(&frame)
        .await
        .map_err(RelayRouteError::Send)?;
    route_response(response)
}

async fn route_from_iota(
    rho: &RhoManager,
    omega: &OmegaConnection,
    source_iota_id: u64,
    next_hop: RouteTarget,
    frame: CommunicationValue,
) -> Result<CommunicationValue, RelayRouteError> {
    match next_hop {
        RouteTarget::User(user_id) => {
            let target = rho
                .get_for_user(
                    i64::try_from(user_id)
                        .map_err(|_| RelayRouteError::InvalidRouteTarget(user_id))?,
                )
                .await
                .ok_or(RelayRouteError::ClientOffline)?;
            target
                .send_relay_to_client(&frame)
                .await
                .map(|_| CommunicationValue::new(CommunicationType::Success))
                .map_err(|error| {
                    if error == "client offline" {
                        RelayRouteError::ClientOffline
                    } else {
                        RelayRouteError::Send(error)
                    }
                })
        }
        RouteTarget::Iota(iota_id) => {
            if iota_id == source_iota_id {
                return Err(RelayRouteError::RouteLoop);
            }
            if let Some(target) = rho
                .get_by_iota(
                    i64::try_from(iota_id)
                        .map_err(|_| RelayRouteError::InvalidRouteTarget(iota_id))?,
                )
                .await
            {
                let response = target
                    .await_relay_to_iota(&frame)
                    .await
                    .map_err(RelayRouteError::Send)?;
                return route_response(response);
            }
            let response = omega
                .await_response(&frame, Some(Duration::from_secs(20)))
                .await
                .map_err(RelayRouteError::Send)?;
            route_response(response)
        }
    }
}

fn route_response(response: CommunicationValue) -> Result<CommunicationValue, RelayRouteError> {
    if response.is_type(CommunicationType::Success)
        || response
            .get_type_name()
            .is_some_and(|name| name.starts_with("Error"))
    {
        Ok(response)
    } else {
        Err(RelayRouteError::Send(format!(
            "next Relay hop rejected the frame with {}",
            response.get_type()
        )))
    }
}

pub fn ensure_relay_frame_id(frame: CommunicationValue) -> CommunicationValue {
    if frame.id().is_some() {
        return frame;
    }
    let id = NEXT_RELAY_FRAME_ID.fetch_add(1, Ordering::Relaxed).max(1);
    frame.with_id(id)
}

fn prepare_frame(
    frame: CommunicationValue,
) -> Result<(RouteTarget, CommunicationValue), RelayRouteError> {
    let next_hop = frame.receiver().ok_or(RelayRouteError::MissingReceiver)?;
    let target =
        RouteTarget::from_wire_id(next_hop).ok_or(RelayRouteError::InvalidRouteTarget(next_hop))?;
    let frame = forward_relay_frame(&frame, next_hop)?;
    Ok((target, frame))
}

/*
 * Older clients sent their authenticated Iota's raw ID as the first relay
 * hop. Accept only that exact value, then restore the namespace tag before
 * forwarding so legacy clients cannot select a different route.
 */
fn prepare_client_frame(
    frame: CommunicationValue,
    source_iota_id: u64,
) -> Result<(RouteTarget, CommunicationValue), RelayRouteError> {
    let receiver = frame.receiver().ok_or(RelayRouteError::MissingReceiver)?;
    if let Some(target) = RouteTarget::from_wire_id(receiver) {
        let frame = forward_relay_frame(&frame, receiver)?;
        return Ok((target, frame));
    }
    if receiver != source_iota_id {
        return Err(RelayRouteError::InvalidRouteTarget(receiver));
    }
    let target = RouteTarget::Iota(source_iota_id);
    let wire_id = target
        .wire_id()
        .ok_or(RelayRouteError::InvalidRouteTarget(source_iota_id))?;
    let frame = forward_relay_frame(&frame, wire_id)?;
    Ok((target, frame))
}

fn validate_source_next_hop(
    source: RelaySource,
    next_hop: RouteTarget,
) -> Result<(), RelayRouteError> {
    match source {
        RelaySource::Client { iota_id } => match next_hop {
            RouteTarget::Iota(actual) if actual == iota_id => Ok(()),
            _ => Err(RelayRouteError::InvalidClientRoute {
                expected: iota_id,
                actual: next_hop.id(),
            }),
        },
        RelaySource::Iota { iota_id } => {
            if next_hop == RouteTarget::Iota(iota_id) {
                Err(RelayRouteError::RouteLoop)
            } else {
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};

    use crate::rho::connection::OptionalDataValueCompat;

    use super::{
        MessageSecurityClass, RelayRouteError, RelaySource, RouteTarget, message_security_class,
        prepare_client_frame, prepare_frame, relay_route_error_response, validate_source_next_hop,
    };

    fn wire(target: RouteTarget) -> u64 {
        let Some(value) = target.wire_id() else {
            panic!("valid route target was rejected");
        };
        value
    }

    fn relay(receiver: Option<u64>) -> CommunicationValue {
        let frame = CommunicationValue::new(CommunicationType::Relay)
            .without_sender()
            .with_payload(DataValue::Bytes(vec![1, 2, 3]));
        receiver.map_or(frame.clone(), |id| frame.with_receiver(id))
    }

    #[test]
    fn relay_requires_a_next_hop() {
        assert!(matches!(
            prepare_frame(relay(None)),
            Err(RelayRouteError::MissingReceiver)
        ));
    }

    #[test]
    fn iota_target_round_trips() {
        let original = RouteTarget::Iota(42);
        let wire = wire(original);

        assert_eq!(RouteTarget::from_wire_id(wire), Some(original));
    }

    #[test]
    fn raw_iota_id_is_not_a_valid_typed_route() {
        assert_ne!(RouteTarget::from_wire_id(42), Some(RouteTarget::Iota(42)));
    }

    #[test]
    fn client_raw_iota_receiver_is_rewritten_to_a_typed_route() {
        let (target, forwarded) = match prepare_client_frame(relay(Some(42)), 42) {
            Ok(value) => value,
            Err(error) => panic!("legacy client relay was rejected: {error}"),
        };

        assert_eq!(target, RouteTarget::Iota(42));
        assert_eq!(forwarded.receiver(), Some(wire(RouteTarget::Iota(42))));
    }

    #[test]
    fn client_raw_receiver_cannot_select_another_iota() {
        assert!(matches!(
            prepare_client_frame(relay(Some(43)), 42),
            Err(RelayRouteError::InvalidRouteTarget(43))
        ));
    }

    #[test]
    fn relay_rejects_an_outer_sender() {
        let frame = relay(Some(wire(RouteTarget::Iota(7)))).with_sender(9);
        assert!(matches!(
            prepare_frame(frame),
            Err(RelayRouteError::Relay(
                mtp::codec::RelayError::OuterSenderPresent
            ))
        ));
    }

    #[test]
    fn relay_forwarding_preserves_payload_and_next_hop() {
        let frame = relay(Some(wire(RouteTarget::Iota(7))));
        let (next_hop, forwarded) = match prepare_frame(frame.clone()) {
            Ok(value) => value,
            Err(error) => panic!("valid relay was rejected: {error}"),
        };
        assert_eq!(next_hop, RouteTarget::Iota(7));
        assert_eq!(forwarded.receiver(), Some(wire(RouteTarget::Iota(7))));
        assert_eq!(forwarded.sender(), None);
        assert_eq!(forwarded.payload(), frame.payload());
    }

    #[test]
    fn non_relay_frames_are_rejected() {
        let frame = CommunicationValue::new(CommunicationType::Ping)
            .with_receiver(wire(RouteTarget::Iota(7)));
        assert!(matches!(
            prepare_frame(frame),
            Err(RelayRouteError::Relay(mtp::codec::RelayError::NotRelay))
        ));
    }

    #[test]
    fn client_cannot_address_another_iota() {
        assert!(matches!(
            validate_source_next_hop(RelaySource::Client { iota_id: 7 }, RouteTarget::Iota(8)),
            Err(RelayRouteError::InvalidClientRoute {
                expected: 7,
                actual: 8
            })
        ));
    }

    #[test]
    fn client_cannot_address_a_user() {
        assert!(matches!(
            validate_source_next_hop(RelaySource::Client { iota_id: 7 }, RouteTarget::User(8)),
            Err(RelayRouteError::InvalidClientRoute {
                expected: 7,
                actual: 8
            })
        ));
    }

    #[test]
    fn iota_cannot_route_to_itself() {
        assert!(matches!(
            validate_source_next_hop(RelaySource::Iota { iota_id: 7 }, RouteTarget::Iota(7)),
            Err(RelayRouteError::RouteLoop)
        ));
    }

    #[tokio::test]
    async fn omega_does_not_forward_to_another_omikron() {
        let rho = crate::rho::rho_manager::RhoManager::new();
        let result = super::route_from_omega(&rho, relay(Some(wire(RouteTarget::Iota(7))))).await;
        assert!(matches!(
            result,
            Err(RelayRouteError::DestinationIotaNotLocal)
        ));
    }

    #[test]
    fn route_target_namespace_is_explicit() {
        assert_eq!(
            RouteTarget::from_wire_id(wire(RouteTarget::User(7))),
            Some(RouteTarget::User(7))
        );
        assert_eq!(
            RouteTarget::from_wire_id(wire(RouteTarget::Iota(7))),
            Some(RouteTarget::Iota(7))
        );
        assert_eq!(RouteTarget::from_wire_id(7), None);
    }

    #[test]
    fn client_offline_response_keeps_legacy_type_and_identifies_user() {
        let response = relay_route_error_response(
            4,
            Some(RouteTarget::User(42)),
            &RelayRouteError::ClientOffline,
        );
        assert!(response.is_type(CommunicationType::ErrorNoIota));
        assert_eq!(
            response.get_data(DataType::ErrorType).as_str(),
            Some("client_offline")
        );
        assert_eq!(response.get_data(DataType::UserId).as_number(), Some(42));
    }

    #[test]
    fn unavailable_iota_response_keeps_legacy_type_and_identifies_iota() {
        let response = relay_route_error_response(
            4,
            Some(RouteTarget::Iota(99)),
            &RelayRouteError::DestinationIotaNotLocal,
        );
        assert!(response.is_type(CommunicationType::ErrorNoIota));
        assert_eq!(
            response.get_data(DataType::ErrorType).as_str(),
            Some("destination_iota_not_local")
        );
        assert_eq!(response.get_data(DataType::IotaId).as_number(), Some(99));
    }

    #[test]
    fn successful_route_response_is_not_reconstructed() {
        let response = CommunicationValue::new(CommunicationType::Success)
            .with_payload(DataValue::Bytes(vec![9, 8, 7]));
        let routed = match super::route_response(response.clone()) {
            Ok(value) => value,
            Err(_) => return,
        };
        assert_eq!(routed.payload(), response.payload());
    }

    #[test]
    fn synchronized_setting_requests_use_authenticated_peer_control() {
        for setting_type in [
            CommunicationType::SyncedSettingSet,
            CommunicationType::SyncedSettingGet,
            CommunicationType::SyncedSettingDelete,
            CommunicationType::SyncedSettingsList,
        ] {
            let frame = CommunicationValue::new(setting_type);
            assert_eq!(
                message_security_class(&frame),
                MessageSecurityClass::AuthenticatedPeerControl
            );
        }
    }

    #[test]
    fn synchronized_setting_requests_are_not_relay_only() {
        for setting_type in [
            CommunicationType::SyncedSettingSet,
            CommunicationType::SyncedSettingGet,
            CommunicationType::SyncedSettingDelete,
            CommunicationType::SyncedSettingsList,
            CommunicationType::SyncedSettingChanged,
        ] {
            let frame = CommunicationValue::new(setting_type);
            assert_ne!(
                message_security_class(&frame),
                MessageSecurityClass::RelayOnly
            );
        }
    }
}
