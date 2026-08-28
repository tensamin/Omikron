use std::collections::BTreeSet;

const OMIKRON_PREFIX: &str = "omikron;caps=";
const OMEGA_PREFIX: &str = "omega;caps=";
const SET_USER_STATE: &str = "set_user_state_v1";
const STATE_SUBSCRIBE: &str = "state_subscribe_v1";
const SESSION_SNAPSHOT: &str = "session_snapshot_v1";
const CLIENT_STATE_PUSH: &str = "client_state_push_v1";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PeerCapabilities {
    pub set_user_state_v1: bool,
    pub state_subscribe_v1: bool,
    pub session_snapshot_v1: bool,
    pub client_state_push_v1: bool,
}

impl PeerCapabilities {
    pub fn current() -> Self {
        Self {
            set_user_state_v1: true,
            state_subscribe_v1: true,
            session_snapshot_v1: true,
            client_state_push_v1: true,
        }
    }

    pub fn identification_description(&self) -> String {
        let mut names = Vec::new();
        if self.set_user_state_v1 {
            names.push(SET_USER_STATE);
        }
        if self.state_subscribe_v1 {
            names.push(STATE_SUBSCRIBE);
        }
        if self.session_snapshot_v1 {
            names.push(SESSION_SNAPSHOT);
        }
        if self.client_state_push_v1 {
            names.push(CLIENT_STATE_PUSH);
        }
        format!("{OMIKRON_PREFIX}{}", names.join(","))
    }

    #[allow(dead_code)]
    pub fn from_identification_description(description: Option<&str>) -> Result<Self, ()> {
        parse_capabilities(description, OMIKRON_PREFIX)
    }

    pub fn from_omega_identification_description(description: Option<&str>) -> Result<Self, ()> {
        // A missing Omega descriptor selects the documented legacy wire
        // contracts: tuple route snapshots, GetStates-only subscriptions,
        // and ClientChanged pushes.
        parse_capabilities(description, OMEGA_PREFIX)
    }
}

fn parse_capabilities(description: Option<&str>, prefix: &str) -> Result<PeerCapabilities, ()> {
    let Some(description) = description else {
        return Ok(PeerCapabilities::default());
    };
    if description == "omega" {
        return Ok(PeerCapabilities::default());
    }
    let Some(capabilities) = description.strip_prefix(prefix) else {
        return Err(());
    };
    let mut seen = BTreeSet::new();
    for capability in capabilities.split(',') {
        if capability.is_empty() || !seen.insert(capability) {
            return Err(());
        }
    }
    if seen.iter().any(|capability| {
        !matches!(
            *capability,
            SET_USER_STATE | STATE_SUBSCRIBE | SESSION_SNAPSHOT | CLIENT_STATE_PUSH
        )
    }) {
        return Err(());
    }
    Ok(PeerCapabilities {
        set_user_state_v1: seen.contains(SET_USER_STATE),
        state_subscribe_v1: seen.contains(STATE_SUBSCRIBE),
        session_snapshot_v1: seen.contains(SESSION_SNAPSHOT),
        client_state_push_v1: seen.contains(CLIENT_STATE_PUSH),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_description_round_trips() {
        let capabilities = PeerCapabilities::current();
        assert_eq!(
            PeerCapabilities::from_identification_description(Some(
                &capabilities.identification_description()
            )),
            Ok(capabilities)
        );
    }

    #[test]
    fn malformed_capabilities_are_rejected() {
        assert!(
            PeerCapabilities::from_identification_description(Some("omikron;caps=unknown_v9"))
                .is_err()
        );
        assert!(
            PeerCapabilities::from_identification_description(Some(
                "omikron;caps=state_subscribe_v1,state_subscribe_v1"
            ))
            .is_err()
        );
        assert!(PeerCapabilities::from_identification_description(Some("omikron;caps=")).is_err());
    }

    #[test]
    fn missing_capabilities_mean_legacy_peer() {
        assert_eq!(
            PeerCapabilities::from_identification_description(None),
            Ok(PeerCapabilities::default())
        );
        assert_eq!(
            PeerCapabilities::from_omega_identification_description(Some("omega")),
            Ok(PeerCapabilities::default())
        );
    }

    #[test]
    fn omega_capabilities_use_the_omega_namespace() {
        assert!(
            PeerCapabilities::from_omega_identification_description(Some(
                "omega;caps=set_user_state_v1"
            ))
            .unwrap()
            .set_user_state_v1
        );
        assert!(
            PeerCapabilities::from_identification_description(Some("omega;caps=set_user_state_v1"))
                .is_err()
        );
    }
}
