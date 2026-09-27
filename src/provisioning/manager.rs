use std::{collections::HashMap, sync::Mutex, time::Duration};

use uuid::Uuid;

use super::session::{
    ProvisioningMethod, ProvisioningParticipant, ProvisioningRole, ProvisioningSession,
    ProvisioningState, ResolvedAccount,
};

#[derive(Default)]
struct Sessions {
    by_id: HashMap<Uuid, ProvisioningSession>,
    by_participant: HashMap<u64, Uuid>,
}

pub struct ProvisioningManager {
    sessions: Mutex<Sessions>,
    ttl: Duration,
    max_sessions: usize,
}

impl ProvisioningManager {
    pub fn new(ttl: Duration, max_sessions: usize) -> Self {
        Self {
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

    pub fn create(
        &self,
        method: ProvisioningMethod,
        participant: ProvisioningParticipant,
    ) -> Result<Uuid, &'static str> {
        self.prune_expired();
        let mut sessions = self.sessions.lock().unwrap();
        if sessions.by_participant.contains_key(&participant.id)
            || sessions.by_id.len() >= self.max_sessions
        {
            return Err("session limit reached");
        }
        if method == ProvisioningMethod::Password && participant.role != ProvisioningRole::Contact {
            return Err("password sessions require a contact");
        }
        let id = Uuid::new_v4();
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
    ) -> Result<ProvisioningSession, &'static str> {
        self.prune_expired();
        let mut sessions = self.sessions.lock().unwrap();
        if sessions.by_participant.contains_key(&participant.id) {
            return Err("already in a session");
        }
        let session = sessions.by_id.get_mut(&id).ok_or("unknown session")?;
        if session.method == ProvisioningMethod::Password
            || session.state != ProvisioningState::Created
        {
            return Err("session cannot be joined");
        }
        let slot = match participant.role {
            ProvisioningRole::Contact => &mut session.contact,
            ProvisioningRole::Owner => &mut session.owner,
        };
        if slot.is_some() {
            return Err("role already occupied");
        }
        *slot = Some(participant.clone());
        session.state = ProvisioningState::PeerReady;
        let snapshot = session.clone();
        sessions.by_participant.insert(participant.id, id);
        Ok(snapshot)
    }

    pub fn snapshot(
        &self,
        id: Uuid,
        participant_id: u64,
    ) -> Result<ProvisioningSession, &'static str> {
        self.prune_expired();
        let sessions = self.sessions.lock().unwrap();
        if sessions.by_participant.get(&participant_id) != Some(&id) {
            return Err("wrong session");
        }
        sessions.by_id.get(&id).cloned().ok_or("unknown session")
    }

    pub fn for_participant(
        &self,
        participant_id: u64,
    ) -> Result<ProvisioningSession, &'static str> {
        self.prune_expired();
        let sessions = self.sessions.lock().unwrap();
        let id = sessions
            .by_participant
            .get(&participant_id)
            .ok_or("no active session")?;
        sessions.by_id.get(id).cloned().ok_or("unknown session")
    }

    pub fn bind(
        &self,
        id: Uuid,
        participant_id: u64,
        account: ResolvedAccount,
    ) -> Result<ProvisioningSession, &'static str> {
        let mut sessions = self.sessions.lock().unwrap();
        if sessions.by_participant.get(&participant_id) != Some(&id) {
            return Err("wrong session");
        }
        let session = sessions.by_id.get_mut(&id).ok_or("unknown session")?;
        if session.method != ProvisioningMethod::Password {
            session.require_actor(participant_id, ProvisioningRole::Owner)?;
            if session.state != ProvisioningState::PeerReady {
                return Err("peer not ready");
            }
        } else {
            session.require_actor(participant_id, ProvisioningRole::Contact)?;
            if session.state != ProvisioningState::Created {
                return Err("already bound");
            }
        }
        session.account = Some(account);
        session.state = ProvisioningState::AccountBound;
        Ok(session.clone())
    }

    pub fn confirm(&self, id: Uuid, participant_id: u64) -> Result<(), &'static str> {
        let mut sessions = self.sessions.lock().unwrap();
        if sessions.by_participant.get(&participant_id) != Some(&id) {
            return Err("wrong session");
        }
        let session = sessions.by_id.get_mut(&id).ok_or("unknown session")?;
        session.require_actor(participant_id, ProvisioningRole::Owner)?;
        if session.method != ProvisioningMethod::QrOwnerCreated
            || session.state != ProvisioningState::AccountBound
        {
            return Err("confirmation not allowed");
        }
        session.owner_confirmed = true;
        Ok(())
    }

    pub fn password_start(
        &self,
        id: Uuid,
        participant_id: u64,
    ) -> Result<ProvisioningSession, &'static str> {
        let mut sessions = self.sessions.lock().unwrap();
        if sessions.by_participant.get(&participant_id) != Some(&id) {
            return Err("wrong session");
        }
        let session = sessions.by_id.get_mut(&id).ok_or("unknown session")?;
        session.require_actor(participant_id, ProvisioningRole::Contact)?;
        if session.method != ProvisioningMethod::Password
            || session.state != ProvisioningState::AccountBound
        {
            return Err("password session is not ready");
        }
        session.state = ProvisioningState::Authorizing;
        Ok(session.clone())
    }

    pub fn password_finish(
        &self,
        id: Uuid,
        participant_id: u64,
    ) -> Result<ProvisioningSession, &'static str> {
        let mut sessions = self.sessions.lock().unwrap();
        if sessions.by_participant.get(&participant_id) != Some(&id) {
            return Err("wrong session");
        }
        let session = sessions.by_id.get_mut(&id).ok_or("unknown session")?;
        session.require_actor(participant_id, ProvisioningRole::Contact)?;
        if session.method != ProvisioningMethod::Password
            || session.state != ProvisioningState::Authorizing
        {
            return Err("password session is not authorizing");
        }
        session.state = ProvisioningState::Finishing;
        Ok(session.clone())
    }

    pub fn password_delivered(&self, id: Uuid, participant_id: u64) -> Result<(), &'static str> {
        let mut sessions = self.sessions.lock().unwrap();
        let session = sessions.by_id.get_mut(&id).ok_or("unknown session")?;
        session.require_actor(participant_id, ProvisioningRole::Contact)?;
        if session.method != ProvisioningMethod::Password
            || session.state != ProvisioningState::Finishing
        {
            return Err("password session is not finishing");
        }
        session.state = ProvisioningState::CredentialDelivered;
        Ok(())
    }

    pub fn authorize_delivery(
        &self,
        id: Uuid,
        participant_id: u64,
        receiver_id: u64,
    ) -> Result<ProvisioningSession, &'static str> {
        let mut sessions = self.sessions.lock().unwrap();
        if sessions.by_participant.get(&participant_id) != Some(&id) {
            return Err("wrong session");
        }
        let session = sessions.by_id.get_mut(&id).ok_or("unknown session")?;
        session.require_actor(participant_id, ProvisioningRole::Owner)?;
        session.can_deliver()?;
        if session.contact.as_ref().map(|contact| contact.id) != Some(receiver_id) {
            return Err("wrong recipient");
        }
        session.state = ProvisioningState::Authorizing;
        Ok(session.clone())
    }

    pub fn delivered(&self, id: Uuid, participant_id: u64) -> Result<(), &'static str> {
        let mut sessions = self.sessions.lock().unwrap();
        let session = sessions.by_id.get_mut(&id).ok_or("unknown session")?;
        session.require_actor(participant_id, ProvisioningRole::Owner)?;
        if session.state != ProvisioningState::Authorizing {
            return Err("not delivering");
        }
        session.state = ProvisioningState::CredentialDelivered;
        Ok(())
    }

    pub fn complete(
        &self,
        id: Uuid,
        participant_id: u64,
    ) -> Result<Option<ProvisioningParticipant>, &'static str> {
        let mut sessions = self.sessions.lock().unwrap();
        let session = sessions.by_id.get(&id).ok_or("unknown session")?;
        session.require_actor(participant_id, ProvisioningRole::Contact)?;
        if session.state != ProvisioningState::CredentialDelivered {
            return Err("credential not delivered");
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
    fn contact_created_qr_does_not_require_confirmation() {
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
        assert!(manager.authorize_delivery(id, 2, 1).is_ok());
        manager.remove_participant(2);
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
}
