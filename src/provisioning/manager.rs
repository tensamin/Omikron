use std::{collections::HashMap, sync::Mutex, time::Duration};

use uuid::Uuid;

use super::ProvisioningError;
use super::session::{
    ProvisioningFailure, ProvisioningMethod, ProvisioningParticipant, ProvisioningRole,
    ProvisioningSession, ProvisioningState, ResolvedAccount, TerminatedProvisioning,
};

#[derive(Default)]
struct Sessions {
    by_id: HashMap<Uuid, ProvisioningSession>,
    by_participant: HashMap<u64, Uuid>,
}

pub struct ProvisioningManager {
    pub password_admission: super::password_admission::PasswordAdmission,
    sessions: Mutex<Sessions>,
    ttl: Duration,
    max_sessions: usize,
}

impl ProvisioningManager {
    pub fn remaining_seconds(&self, id: Uuid) -> Result<u64, ProvisioningError> {
        let sessions = self.sessions.lock().unwrap();
        let session = sessions
            .by_id
            .get(&id)
            .ok_or(ProvisioningError::UnknownSession)?;
        Ok(self
            .ttl
            .saturating_sub(session.created_at.elapsed())
            .as_secs())
    }
    fn require_active_locked<'a>(
        &self,
        sessions: &'a mut Sessions,
        id: Uuid,
        participant_id: u64,
    ) -> Result<&'a mut ProvisioningSession, ProvisioningError> {
        let expired = sessions
            .by_id
            .get(&id)
            .ok_or(ProvisioningError::UnknownSession)?
            .created_at
            .elapsed()
            >= self.ttl;
        if expired {
            self.remove_locked(sessions, id);
            return Err(ProvisioningError::Expired);
        }
        if sessions.by_participant.get(&participant_id) != Some(&id) {
            return Err(ProvisioningError::WrongSession);
        }
        sessions
            .by_id
            .get_mut(&id)
            .ok_or(ProvisioningError::UnknownSession)
    }

    pub fn new(ttl: Duration, max_sessions: usize) -> Self {
        Self {
            password_admission: super::password_admission::PasswordAdmission::default(),
            sessions: Mutex::new(Sessions::default()),
            ttl,
            max_sessions,
        }
    }

    pub fn prune_expired(&self) {
        let mut sessions = self.sessions.lock().unwrap();
        let ttl = self.ttl;
        sessions
            .by_id
            .retain(|_, session| session.created_at.elapsed() < ttl);
        let active: std::collections::HashSet<_> = sessions.by_id.keys().copied().collect();
        sessions.by_participant.retain(|_, id| active.contains(id));
    }

    #[cfg(test)]
    pub fn create(
        &self,
        method: ProvisioningMethod,
        participant: ProvisioningParticipant,
    ) -> Result<Uuid, ProvisioningError> {
        self.create_with_id(Uuid::new_v4(), method, participant)
    }

    pub fn create_with_id(
        &self,
        id: Uuid,
        method: ProvisioningMethod,
        participant: ProvisioningParticipant,
    ) -> Result<Uuid, ProvisioningError> {
        self.prune_expired();
        let mut sessions = self.sessions.lock().unwrap();
        if sessions.by_participant.contains_key(&participant.id) {
            return Err(ProvisioningError::AlreadyInSession);
        }
        if sessions.by_id.len() >= self.max_sessions {
            return Err(ProvisioningError::SessionLimit);
        }
        if method == ProvisioningMethod::Password && participant.role != ProvisioningRole::Contact {
            return Err(ProvisioningError::WrongParticipant);
        }
        if sessions.by_id.contains_key(&id) {
            return Err(ProvisioningError::AlreadyInSession);
        }
        let (contact, owner) = match participant.role {
            ProvisioningRole::Contact => (Some(participant.clone()), None),
            ProvisioningRole::Owner => (None, Some(participant.clone())),
        };
        sessions.by_id.insert(
            id,
            ProvisioningSession {
                id,
                method,
                contact,
                owner,
                account: None,
                state: ProvisioningState::Created,
                owner_confirmed: false,
                created_at: std::time::Instant::now(),
            },
        );
        sessions.by_participant.insert(participant.id, id);
        Ok(id)
    }

    pub fn join(
        &self,
        id: Uuid,
        participant: ProvisioningParticipant,
    ) -> Result<ProvisioningSession, ProvisioningError> {
        self.prune_expired();
        let mut sessions = self.sessions.lock().unwrap();
        if sessions.by_participant.contains_key(&participant.id) {
            return Err(ProvisioningError::AlreadyInSession);
        }
        let session = sessions
            .by_id
            .get_mut(&id)
            .ok_or(ProvisioningError::UnknownSession)?;
        if session.created_at.elapsed() >= self.ttl {
            self.remove_locked(&mut sessions, id);
            return Err(ProvisioningError::Expired);
        }
        if session.method == ProvisioningMethod::Password
            || session.state != ProvisioningState::Created
        {
            return Err(ProvisioningError::InvalidState);
        }
        let slot = match participant.role {
            ProvisioningRole::Contact => &mut session.contact,
            ProvisioningRole::Owner => &mut session.owner,
        };
        if slot.is_some() {
            return Err(ProvisioningError::RoleOccupied);
        }
        *slot = Some(participant.clone());
        session.state = ProvisioningState::PeerReady;
        let snapshot = session.clone();
        sessions.by_participant.insert(participant.id, id);
        Ok(snapshot)
    }

    pub fn claim(
        &self,
        id: Uuid,
        owner: ProvisioningParticipant,
        account: ResolvedAccount,
    ) -> Result<ProvisioningSession, ProvisioningError> {
        let mut sessions = self.sessions.lock().unwrap();
        if sessions.by_participant.contains_key(&owner.id) {
            return Err(ProvisioningError::AlreadyInSession);
        }
        let session = sessions
            .by_id
            .get_mut(&id)
            .ok_or(ProvisioningError::UnknownSession)?;
        if session.created_at.elapsed() >= self.ttl {
            self.remove_locked(&mut sessions, id);
            return Err(ProvisioningError::Expired);
        }
        if session.method != ProvisioningMethod::QrContactCreated
            || session.state != ProvisioningState::Created
            || owner.role != ProvisioningRole::Owner
            || session.owner.is_some()
        {
            return Err(ProvisioningError::InvalidState);
        }
        session.owner = Some(owner.clone());
        session.account = Some(account);
        session.state = ProvisioningState::AccountBound;
        let snapshot = session.clone();
        sessions.by_participant.insert(owner.id, id);
        Ok(snapshot)
    }

    pub fn snapshot(
        &self,
        id: Uuid,
        participant_id: u64,
    ) -> Result<ProvisioningSession, ProvisioningError> {
        self.prune_expired();
        let sessions = self.sessions.lock().unwrap();
        if sessions.by_participant.get(&participant_id) != Some(&id) {
            return Err(ProvisioningError::WrongSession);
        }
        sessions
            .by_id
            .get(&id)
            .cloned()
            .ok_or(ProvisioningError::UnknownSession)
    }

    pub fn for_participant(
        &self,
        participant_id: u64,
    ) -> Result<ProvisioningSession, ProvisioningError> {
        self.prune_expired();
        let sessions = self.sessions.lock().unwrap();
        let id = sessions
            .by_participant
            .get(&participant_id)
            .ok_or(ProvisioningError::UnknownSession)?;
        sessions
            .by_id
            .get(id)
            .cloned()
            .ok_or(ProvisioningError::UnknownSession)
    }

    pub fn bind(
        &self,
        id: Uuid,
        participant_id: u64,
        account: ResolvedAccount,
    ) -> Result<ProvisioningSession, ProvisioningError> {
        let mut sessions = self.sessions.lock().unwrap();
        let session = self.require_active_locked(&mut sessions, id, participant_id)?;
        if session.method != ProvisioningMethod::Password {
            session.require_actor(participant_id, ProvisioningRole::Owner)?;
            if session.state != ProvisioningState::PeerReady {
                return Err(ProvisioningError::InvalidState);
            }
        } else {
            session.require_actor(participant_id, ProvisioningRole::Contact)?;
            if session.state != ProvisioningState::Created {
                return Err(ProvisioningError::InvalidState);
            }
        }
        session.account = Some(account);
        session.state = ProvisioningState::AccountBound;
        Ok(session.clone())
    }

    pub fn confirm(&self, id: Uuid, participant_id: u64) -> Result<(), ProvisioningError> {
        let mut sessions = self.sessions.lock().unwrap();
        let session = self.require_active_locked(&mut sessions, id, participant_id)?;
        if session.method == ProvisioningMethod::QrContactCreated {
            if session.contact.as_ref().map(|contact| contact.id) == Some(participant_id) {
                if session.state != ProvisioningState::AccountBound {
                    return Err(ProvisioningError::InvalidState);
                }
                session.state = ProvisioningState::PeerReady;
                return Ok(());
            }
            session.require_actor(participant_id, ProvisioningRole::Owner)?;
            if session.state != ProvisioningState::PeerReady {
                return Err(ProvisioningError::ConfirmationRequired);
            }
            session.state = ProvisioningState::AccountBound;
            session.owner_confirmed = true;
            return Ok(());
        }
        session.require_actor(participant_id, ProvisioningRole::Owner)?;
        if session.method == ProvisioningMethod::Password
            || session.state != ProvisioningState::AccountBound
        {
            return Err(ProvisioningError::InvalidState);
        }
        session.owner_confirmed = true;
        Ok(())
    }

    pub fn password_start(
        &self,
        id: Uuid,
        participant_id: u64,
    ) -> Result<ProvisioningSession, ProvisioningError> {
        let mut sessions = self.sessions.lock().unwrap();
        let session = self.require_active_locked(&mut sessions, id, participant_id)?;
        session.require_actor(participant_id, ProvisioningRole::Contact)?;
        if session.method != ProvisioningMethod::Password {
            return Err(ProvisioningError::WrongMethod);
        }
        if session.state != ProvisioningState::AccountBound {
            return Err(ProvisioningError::InvalidState);
        }
        session.state = ProvisioningState::Authorizing;
        Ok(session.clone())
    }

    pub fn password_finish(
        &self,
        id: Uuid,
        participant_id: u64,
    ) -> Result<ProvisioningSession, ProvisioningError> {
        let mut sessions = self.sessions.lock().unwrap();
        let session = self.require_active_locked(&mut sessions, id, participant_id)?;
        session.require_actor(participant_id, ProvisioningRole::Contact)?;
        if session.method != ProvisioningMethod::Password {
            return Err(ProvisioningError::WrongMethod);
        }
        if session.state != ProvisioningState::Authorizing {
            return Err(ProvisioningError::InvalidState);
        }
        session.state = ProvisioningState::Finishing;
        Ok(session.clone())
    }

    pub fn password_delivered(
        &self,
        id: Uuid,
        participant_id: u64,
    ) -> Result<(), ProvisioningError> {
        let mut sessions = self.sessions.lock().unwrap();
        let session = self.require_active_locked(&mut sessions, id, participant_id)?;
        session.require_actor(participant_id, ProvisioningRole::Contact)?;
        if session.method != ProvisioningMethod::Password {
            return Err(ProvisioningError::WrongMethod);
        }
        if session.state != ProvisioningState::Finishing {
            return Err(ProvisioningError::InvalidState);
        }
        session.state = ProvisioningState::CredentialDelivered;
        Ok(())
    }

    pub fn authorize_delivery(
        &self,
        id: Uuid,
        participant_id: u64,
        receiver_id: u64,
    ) -> Result<ProvisioningSession, ProvisioningError> {
        let mut sessions = self.sessions.lock().unwrap();
        let session = self.require_active_locked(&mut sessions, id, participant_id)?;
        session.require_actor(participant_id, ProvisioningRole::Owner)?;
        session.can_deliver()?;
        if session.contact.as_ref().map(|contact| contact.id) != Some(receiver_id) {
            return Err(ProvisioningError::WrongRecipient);
        }
        session.state = ProvisioningState::Authorizing;
        Ok(session.clone())
    }

    pub fn delivered(&self, id: Uuid, participant_id: u64) -> Result<(), ProvisioningError> {
        let mut sessions = self.sessions.lock().unwrap();
        let session = self.require_active_locked(&mut sessions, id, participant_id)?;
        session.require_actor(participant_id, ProvisioningRole::Owner)?;
        if session.state != ProvisioningState::Authorizing {
            return Err(ProvisioningError::InvalidState);
        }
        session.state = ProvisioningState::CredentialDelivered;
        Ok(())
    }

    pub fn complete(
        &self,
        id: Uuid,
        participant_id: u64,
    ) -> Result<Option<ProvisioningParticipant>, ProvisioningError> {
        let mut sessions = self.sessions.lock().unwrap();
        let session = self.require_active_locked(&mut sessions, id, participant_id)?;
        session.require_actor(participant_id, ProvisioningRole::Contact)?;
        if session.state != ProvisioningState::CredentialDelivered {
            return Err(ProvisioningError::InvalidState);
        }
        let owner = session.owner.clone();
        self.remove_locked(&mut sessions, id);
        Ok(owner)
    }

    pub fn remove_participant(&self, participant_id: u64) {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(id) = sessions.by_participant.get(&participant_id).copied() {
            self.remove_locked(&mut sessions, id);
        }
    }

    pub fn fail_forward(
        &self,
        id: Uuid,
        participant_id: u64,
        reason: ProvisioningFailure,
    ) -> Result<TerminatedProvisioning, ProvisioningError> {
        let mut sessions = self.sessions.lock().unwrap();
        if sessions.by_participant.get(&participant_id) != Some(&id) {
            return Err(ProvisioningError::WrongSession);
        }
        let session = sessions
            .by_id
            .get(&id)
            .ok_or(ProvisioningError::UnknownSession)?;
        if session.contact.as_ref().map(|participant| participant.id) != Some(participant_id)
            && session.owner.as_ref().map(|participant| participant.id) != Some(participant_id)
        {
            return Err(ProvisioningError::WrongParticipant);
        }
        let terminated = TerminatedProvisioning {
            id,
            method: session.method,
            reason,
            contact: session.contact.clone(),
            owner: session.owner.clone(),
        };
        self.remove_locked(&mut sessions, id);
        Ok(terminated)
    }

    fn remove_locked(&self, sessions: &mut Sessions, id: Uuid) {
        if let Some(session) = sessions.by_id.remove(&id) {
            for participant in [session.contact, session.owner].into_iter().flatten() {
                sessions.by_participant.remove(&participant.id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mtp::crypto::Keyring;

    fn participant(id: u64, role: ProvisioningRole) -> ProvisioningParticipant {
        ProvisioningParticipant {
            id,
            role,
            temporary_public_key: Keyring::generate().public_key_bundle(),
            sender: std::sync::Weak::new(),
        }
    }

    fn account() -> ResolvedAccount {
        ResolvedAccount {
            user_id: 7,
            username: "alice".into(),
            principal: "omega-key:example#7".into(),
            iota_id: 11,
            public_key: Keyring::generate().public_key_bundle(),
        }
    }

    #[test]
    fn authenticated_claim_is_atomic_and_keeps_registered_key() {
        let manager = ProvisioningManager::new(Duration::from_secs(60), 10);
        let contact = participant(1, ProvisioningRole::Contact);
        let public_key = contact.temporary_public_key.try_to_base64().unwrap();
        let id = manager
            .create(ProvisioningMethod::QrContactCreated, contact)
            .unwrap();
        let claimed = manager
            .claim(id, participant(2, ProvisioningRole::Owner), account())
            .unwrap();
        assert_eq!(
            claimed
                .contact
                .unwrap()
                .temporary_public_key
                .try_to_base64()
                .unwrap(),
            public_key
        );
        assert!(
            manager
                .claim(id, participant(3, ProvisioningRole::Owner), account())
                .is_err()
        );
        assert!(manager.authorize_delivery(id, 3, 1).is_err());
        assert!(manager.authorize_delivery(id, 2, 1).is_err());
        assert!(manager.confirm(id, 2).is_err());
        manager.confirm(id, 1).unwrap();
        manager.confirm(id, 2).unwrap();
        manager.authorize_delivery(id, 2, 1).unwrap();
        assert!(manager.authorize_delivery(id, 2, 1).is_err());
        manager.delivered(id, 2).unwrap();
        manager.complete(id, 1).unwrap();
        assert!(
            manager
                .claim(id, participant(3, ProvisioningRole::Owner), account())
                .is_err()
        );
    }

    #[test]
    fn concurrent_claims_have_exactly_one_winner() {
        let manager = std::sync::Arc::new(ProvisioningManager::new(Duration::from_secs(60), 10));
        let id = manager
            .create(
                ProvisioningMethod::QrContactCreated,
                participant(1, ProvisioningRole::Contact),
            )
            .unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let attempts: Vec<_> = [2, 3]
            .into_iter()
            .map(|actor| {
                let manager = manager.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let owner = participant(actor, ProvisioningRole::Owner);
                    let account = account();
                    barrier.wait();
                    manager.claim(id, owner, account).is_ok()
                })
            })
            .collect();
        assert_eq!(
            attempts
                .into_iter()
                .map(|attempt| attempt.join().unwrap())
                .filter(|won| *won)
                .count(),
            1
        );
    }

    #[test]
    fn failed_forward_removes_session_and_participant_mapping() {
        let manager = ProvisioningManager::new(Duration::from_secs(60), 10);
        let contact = participant(7, ProvisioningRole::Contact);
        let id = manager
            .create(ProvisioningMethod::Password, contact.clone())
            .unwrap();
        manager.bind(id, 7, account()).unwrap();
        manager.password_start(id, 7).unwrap();
        let terminated = manager
            .fail_forward(id, 7, ProvisioningFailure::UpstreamUnavailable)
            .unwrap();
        assert_eq!(terminated.reason, ProvisioningFailure::UpstreamUnavailable);
        assert!(manager.snapshot(id, 7).is_err());
        assert!(manager.password_finish(id, 7).is_err());
        assert!(
            manager
                .create(ProvisioningMethod::Password, contact)
                .is_ok()
        );
    }

    #[test]
    fn failed_qr_forward_releases_both_participants() {
        let manager = ProvisioningManager::new(Duration::from_secs(60), 10);
        let id = manager
            .create(
                ProvisioningMethod::QrOwnerCreated,
                participant(1, ProvisioningRole::Owner),
            )
            .unwrap();
        manager
            .join(id, participant(2, ProvisioningRole::Contact))
            .unwrap();
        manager.bind(id, 1, account()).unwrap();
        manager.confirm(id, 1).unwrap();
        manager.authorize_delivery(id, 1, 2).unwrap();
        manager
            .fail_forward(id, 1, ProvisioningFailure::PeerDisconnected)
            .unwrap();
        assert!(manager.for_participant(1).is_err());
        assert!(manager.for_participant(2).is_err());
    }

    #[test]
    fn failed_ke3_forward_cannot_deliver_or_complete_old_session() {
        let manager = ProvisioningManager::new(Duration::from_secs(60), 10);
        let id = manager
            .create(
                ProvisioningMethod::Password,
                participant(7, ProvisioningRole::Contact),
            )
            .unwrap();
        manager.bind(id, 7, account()).unwrap();
        manager.password_start(id, 7).unwrap();
        manager.password_finish(id, 7).unwrap();
        manager
            .fail_forward(id, 7, ProvisioningFailure::UpstreamRejected)
            .unwrap();
        assert!(manager.password_delivered(id, 7).is_err());
        assert!(manager.complete(id, 7).is_err());
        assert!(
            manager
                .create(
                    ProvisioningMethod::Password,
                    participant(7, ProvisioningRole::Contact)
                )
                .is_ok()
        );
    }

    #[test]
    fn delivered_credential_cannot_be_relayed_twice() {
        let manager = ProvisioningManager::new(Duration::from_secs(60), 10);
        let id = manager
            .create(
                ProvisioningMethod::Password,
                participant(7, ProvisioningRole::Contact),
            )
            .unwrap();
        manager.bind(id, 7, account()).unwrap();
        manager.password_start(id, 7).unwrap();
        manager.password_finish(id, 7).unwrap();
        manager.password_delivered(id, 7).unwrap();
        assert!(manager.password_delivered(id, 7).is_err());
        assert!(manager.password_finish(id, 7).is_err());
    }

    #[test]
    fn qr_delivery_requires_correct_roles_account_and_confirmation() {
        let manager = ProvisioningManager::new(Duration::from_secs(60), 10);
        let id = manager
            .create(
                ProvisioningMethod::QrOwnerCreated,
                participant(1, ProvisioningRole::Owner),
            )
            .unwrap();
        assert!(
            manager
                .create(
                    ProvisioningMethod::QrOwnerCreated,
                    participant(1, ProvisioningRole::Owner)
                )
                .is_err()
        );
        assert!(
            manager
                .join(id, participant(3, ProvisioningRole::Owner))
                .is_err()
        );
        manager
            .join(id, participant(2, ProvisioningRole::Contact))
            .unwrap();
        assert!(manager.bind(id, 2, account()).is_err());
        manager.bind(id, 1, account()).unwrap();
        assert!(manager.authorize_delivery(id, 1, 2).is_err());
        assert!(manager.confirm(id, 2).is_err());
        manager.confirm(id, 1).unwrap();
        assert!(manager.authorize_delivery(id, 1, 3).is_err());
        manager.authorize_delivery(id, 1, 2).unwrap();
        assert!(manager.complete(id, 1).is_err());
        manager.delivered(id, 1).unwrap();
        manager.complete(id, 2).unwrap();
        assert!(manager.snapshot(id, 1).is_err());
    }

    #[test]
    fn contact_created_qr_requires_confirmation_and_is_single_claim() {
        let manager = ProvisioningManager::new(Duration::from_secs(60), 10);
        let id = manager
            .create(
                ProvisioningMethod::QrContactCreated,
                participant(1, ProvisioningRole::Contact),
            )
            .unwrap();
        manager
            .join(id, participant(2, ProvisioningRole::Owner))
            .unwrap();
        manager.bind(id, 2, account()).unwrap();
        assert!(
            manager
                .join(id, participant(3, ProvisioningRole::Owner))
                .is_err()
        );
        assert!(manager.authorize_delivery(id, 2, 1).is_err());
        manager.confirm(id, 1).unwrap();
        manager.confirm(id, 2).unwrap();
        assert!(manager.authorize_delivery(id, 2, 1).is_ok());
        manager.delivered(id, 2).unwrap();
        manager.complete(id, 1).unwrap();
        assert!(manager.snapshot(id, 1).is_err());
    }

    #[test]
    fn password_session_has_one_contact_and_single_use_finish() {
        let manager = ProvisioningManager::new(Duration::from_secs(60), 10);
        assert!(
            manager
                .create(
                    ProvisioningMethod::Password,
                    participant(2, ProvisioningRole::Owner)
                )
                .is_err()
        );
        let id = manager
            .create(
                ProvisioningMethod::Password,
                participant(1, ProvisioningRole::Contact),
            )
            .unwrap();
        assert!(
            manager
                .join(id, participant(2, ProvisioningRole::Owner))
                .is_err()
        );
        assert!(manager.password_start(id, 1).is_err());
        manager.bind(id, 1, account()).unwrap();
        assert!(manager.password_start(id, 2).is_err());
        manager.password_start(id, 1).unwrap();
        assert!(manager.password_start(id, 1).is_err());
        manager.password_finish(id, 1).unwrap();
        assert!(manager.password_finish(id, 1).is_err());
        assert!(manager.complete(id, 1).is_err());
        manager.password_delivered(id, 1).unwrap();
        manager.complete(id, 1).unwrap();
    }

    #[test]
    fn expired_password_session_cannot_transition() {
        let manager = ProvisioningManager::new(Duration::ZERO, 10);
        let id = manager
            .create(
                ProvisioningMethod::Password,
                participant(1, ProvisioningRole::Contact),
            )
            .unwrap();
        assert!(matches!(
            manager.bind(id, 1, account()),
            Err(ProvisioningError::Expired)
        ));
        assert!(manager.password_start(id, 1).is_err());
        assert!(manager.password_finish(id, 1).is_err());
        assert!(manager.password_delivered(id, 1).is_err());
        assert!(manager.complete(id, 1).is_err());
    }

    #[test]
    fn expired_qr_sessions_cannot_transition() {
        for (method, role) in [
            (
                ProvisioningMethod::QrContactCreated,
                ProvisioningRole::Contact,
            ),
            (ProvisioningMethod::QrOwnerCreated, ProvisioningRole::Owner),
        ] {
            let manager = ProvisioningManager::new(Duration::ZERO, 10);
            let id = manager.create(method, participant(1, role)).unwrap();
            assert_eq!(
                manager.bind(id, 1, account()).err(),
                Some(ProvisioningError::Expired)
            );
            assert!(manager.confirm(id, 1).is_err());
            assert!(manager.authorize_delivery(id, 1, 2).is_err());
            assert!(manager.delivered(id, 1).is_err());
            assert!(manager.complete(id, 1).is_err());
        }
    }

    #[test]
    fn delivery_requires_active_membership_and_unexpired_session() {
        let manager = ProvisioningManager::new(Duration::from_secs(60), 10);
        let password = manager
            .create(
                ProvisioningMethod::Password,
                participant(1, ProvisioningRole::Contact),
            )
            .unwrap();
        manager.bind(password, 1, account()).unwrap();
        manager.password_start(password, 1).unwrap();
        manager.password_finish(password, 1).unwrap();
        let other = manager
            .create(
                ProvisioningMethod::Password,
                participant(2, ProvisioningRole::Contact),
            )
            .unwrap();
        assert_eq!(
            manager.password_delivered(password, 2),
            Err(ProvisioningError::WrongSession)
        );
        assert_eq!(
            manager.password_delivered(other, 1),
            Err(ProvisioningError::WrongSession)
        );
        manager
            .sessions
            .lock()
            .unwrap()
            .by_id
            .get_mut(&password)
            .unwrap()
            .created_at -= Duration::from_secs(61);
        assert_eq!(
            manager.password_delivered(password, 1),
            Err(ProvisioningError::Expired)
        );

        let qr = manager
            .create(
                ProvisioningMethod::QrOwnerCreated,
                participant(3, ProvisioningRole::Owner),
            )
            .unwrap();
        manager
            .join(qr, participant(4, ProvisioningRole::Contact))
            .unwrap();
        manager.bind(qr, 3, account()).unwrap();
        manager.confirm(qr, 3).unwrap();
        manager.authorize_delivery(qr, 3, 4).unwrap();
        assert_eq!(
            manager.delivered(qr, 4),
            Err(ProvisioningError::WrongParticipant)
        );
        manager
            .sessions
            .lock()
            .unwrap()
            .by_id
            .get_mut(&qr)
            .unwrap()
            .created_at -= Duration::from_secs(61);
        assert_eq!(manager.delivered(qr, 3), Err(ProvisioningError::Expired));
    }
}
