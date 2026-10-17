use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use super::rho_connection::RhoConnection;

#[derive(Clone, Default)]
struct RoutingSnapshot {
    generation: u64,
    by_iota: HashMap<i64, Arc<RhoConnection>>,
    by_node: HashMap<super::relay_router::IotaNodeId, Arc<RhoConnection>>,
    by_user: HashMap<i64, Arc<RhoConnection>>,
    members: HashMap<i64, HashSet<i64>>,
}

/// Ownership readers share a single publication generation.
#[derive(Default)]
pub struct RhoManager {
    // Lock order: routing mutation, membership locks, registration-local locks.
    mutations: tokio::sync::Mutex<()>,
    published: RwLock<Arc<RoutingSnapshot>>,
    #[cfg(test)]
    before_publish: std::sync::Mutex<Option<(Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>>,
}

impl RhoManager {
    fn snapshot(&self) -> Arc<RoutingSnapshot> {
        self.published
            .read()
            .expect("routing snapshot poisoned")
            .clone()
    }

    fn publish(&self, next: RoutingSnapshot) {
        #[cfg(test)]
        if let Some((reached, resume)) = self.before_publish.lock().unwrap().take() {
            reached.wait();
            resume.wait();
        }
        *self.published.write().expect("routing snapshot poisoned") = Arc::new(next);
    }

    pub(crate) fn owns_iota_user(
        &self,
        user: i64,
        iota: &super::iota_connection::IotaConnection,
    ) -> bool {
        let snapshot = self.snapshot();
        snapshot.by_user.get(&user).is_some_and(|rho| {
            std::ptr::eq(rho.get_iota_connection().as_ref(), iota)
                && snapshot
                    .by_iota
                    .get(&(iota.iota_id as i64))
                    .is_some_and(|current| Arc::ptr_eq(current, rho))
                && snapshot
                    .members
                    .get(&(iota.iota_id as i64))
                    .is_some_and(|members| members.contains(&user))
        })
    }

    pub(crate) fn is_current_rho(&self, rho: &RhoConnection) -> bool {
        self.snapshot()
            .by_iota
            .get(&(rho.iota_id() as i64))
            .is_some_and(|current| std::ptr::eq(current.as_ref(), rho))
    }

    pub(crate) fn owns_rho_user(&self, user: i64, rho: &RhoConnection) -> bool {
        self.user_route_generation(user, rho).is_some()
    }

    pub(crate) fn user_route_generation(&self, user: i64, rho: &RhoConnection) -> Option<u64> {
        let snapshot = self.snapshot();
        (snapshot
            .by_user
            .get(&user)
            .is_some_and(|owner| std::ptr::eq(owner.as_ref(), rho))
            && snapshot
                .by_iota
                .get(&(rho.iota_id() as i64))
                .is_some_and(|current| std::ptr::eq(current.as_ref(), rho))
            && snapshot
                .members
                .get(&(rho.iota_id() as i64))
                .is_some_and(|members| members.contains(&user)))
        .then_some(snapshot.generation)
    }
    pub(crate) async fn mutation_guard(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.mutations.lock().await
    }

    /// Hold the current-route check through the synchronous registration commit.
    pub(crate) fn attach_registered_client(
        &self,
        _mutation: &tokio::sync::MutexGuard<'_, ()>,
        rho: &Arc<RhoConnection>,
        prepared_generation: u64,
        client: Arc<super::client_connection::ClientConnection>,
        commit: impl FnOnce() -> Result<(), tau::AdmissionError>,
    ) -> Result<(), tau::AdmissionError> {
        let snapshot = self.snapshot();
        if snapshot.generation != prepared_generation {
            return Err(tau::AdmissionError::RejectedActivation);
        }
        let current = snapshot
            .by_iota
            .get(&(rho.iota_id() as i64))
            .ok_or(tau::AdmissionError::RejectedActivation)?;
        if !Arc::ptr_eq(current, rho) {
            return Err(tau::AdmissionError::RejectedActivation);
        }
        // The mutation guard keeps this snapshot current through the commit.
        let owner = snapshot
            .by_user
            .get(&(client.user_id as i64))
            .ok_or(tau::AdmissionError::RejectedActivation)?;
        if !Arc::ptr_eq(owner, rho) {
            return Err(tau::AdmissionError::RejectedActivation);
        }
        if !snapshot
            .members
            .get(&(rho.iota_id() as i64))
            .is_some_and(|members| members.contains(&(client.user_id as i64)))
        {
            return Err(tau::AdmissionError::RejectedActivation);
        }
        rho.attach_registered_client(client, commit)
    }

    pub(crate) fn prepare_registration_route(
        &self,
        user_id: i64,
        iota_id: u64,
    ) -> Option<(Arc<RhoConnection>, u64)> {
        let snapshot = self.snapshot();
        let rho = snapshot.by_user.get(&user_id)?;
        (rho.iota_id() == iota_id
            && snapshot
                .by_iota
                .get(&(iota_id as i64))
                .is_some_and(|current| Arc::ptr_eq(current, rho))
            && snapshot
                .members
                .get(&(iota_id as i64))
                .is_some_and(|members| members.contains(&user_id)))
        .then(|| (rho.clone(), snapshot.generation))
    }
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn get_for_user(&self, user_id: i64) -> Option<Arc<RhoConnection>> {
        self.snapshot().by_user.get(&user_id).cloned()
    }

    pub fn get_for_user_on_iota(
        &self,
        user_id: i64,
        expected_iota_id: u64,
    ) -> Option<Arc<RhoConnection>> {
        let snapshot = self.snapshot();
        let rho = snapshot.by_user.get(&user_id)?.clone();
        if rho.iota_id() != expected_iota_id {
            return None;
        }
        if !snapshot
            .members
            .get(&(expected_iota_id as i64))
            .is_some_and(|members| members.contains(&user_id))
        {
            return None;
        }
        snapshot
            .by_iota
            .get(&(expected_iota_id as i64))
            .filter(|current| Arc::ptr_eq(current, &rho))
            .map(|_| rho)
    }

    pub(crate) fn has_replacement_client(
        &self,
        client: &super::client_connection::ClientConnection,
    ) -> bool {
        self.snapshot()
            .by_user
            .get(&(client.user_id as i64))
            .is_some_and(|rho| rho.has_replacement_client(client))
    }

    #[allow(dead_code)]
    pub async fn contains_iota(&self, iota_id: i64) -> bool {
        self.snapshot().by_iota.contains_key(&iota_id)
    }

    pub async fn bind_user_to_iota(
        &self,
        user_id: i64,
        iota_id: i64,
    ) -> Option<Arc<RhoConnection>> {
        let _mutation = self.mutation_guard().await;
        if user_id <= 0 {
            return None;
        }
        let rho = self.snapshot().by_iota.get(&iota_id).cloned()?;
        self.publish_assignments_locked(
            HashMap::from([(user_id, Some(rho.clone()))]),
            None,
            None,
            false,
        )
        .await;
        Some(rho)
    }

    pub async fn replace_users_for_iota(&self, iota_id: i64, user_ids: Vec<i64>) {
        let _mutation = self.mutation_guard().await;
        let rho = self.snapshot().by_iota.get(&iota_id).cloned();
        let Some(rho) = rho else {
            return;
        };

        let mut assignments = self.assignments_removed_with(&rho);
        for user in user_ids.into_iter().filter(|id| *id > 0) {
            assignments.insert(user, Some(rho.clone()));
        }
        self.publish_assignments_locked(assignments, None, None, false)
            .await;
    }

    #[cfg(test)]
    pub fn remove_user_binding(&self, user_id: i64, expected: &RhoConnection) {
        let mut next = (*self.snapshot()).clone();
        if next
            .by_user
            .get(&user_id)
            .is_some_and(|rho| std::ptr::eq(rho.as_ref(), expected))
        {
            next.by_user.remove(&user_id);
            if let Some(members) = next.members.get_mut(&(expected.iota_id() as i64)) {
                members.remove(&user_id);
            }
            next.generation = next
                .generation
                .checked_add(1)
                .expect("routing generation exhausted");
            self.publish(next);
        }
    }

    pub async fn invalidate_user(&self, user_id: i64) {
        let _mutation = self.mutation_guard().await;
        self.publish_assignments_locked(HashMap::from([(user_id, None)]), None, None, true)
            .await;
    }

    fn assignments_removed_with(
        &self,
        rho: &Arc<RhoConnection>,
    ) -> HashMap<i64, Option<Arc<RhoConnection>>> {
        self.snapshot()
            .by_user
            .iter()
            .filter(|(_, owner)| Arc::ptr_eq(owner, rho))
            .map(|(user, _)| (*user, None))
            .collect()
    }

    /// The caller holds the routing mutation guard. Acquire membership locks
    /// in stable order, then all client locks, before the synchronous commit.
    async fn publish_assignments_locked(
        &self,
        mut assignments: HashMap<i64, Option<Arc<RhoConnection>>>,
        installing: Option<Arc<RhoConnection>>,
        retiring: Option<Arc<RhoConnection>>,
        revoke: bool,
    ) {
        let previous = self.snapshot();
        assignments.retain(|user, owner| match (previous.by_user.get(user), owner) {
            (Some(old), Some(new)) => !Arc::ptr_eq(old, new),
            (None, None) => false,
            _ => true,
        });
        if assignments.is_empty() && installing.is_none() && retiring.is_none() {
            return;
        }
        let mut next = (*previous).clone();
        next.generation = next
            .generation
            .checked_add(1)
            .expect("routing generation exhausted");
        // Compute ownership and membership from the published snapshot, never
        // from the mutable membership mirrors acquired below.
        let mut rhos = Vec::new();
        for (user, owner) in &assignments {
            if let Some(old) = previous.by_user.get(user) {
                rhos.push(old.clone());
                if let Some(members) = next.members.get_mut(&(old.iota_id() as i64)) {
                    members.remove(user);
                }
            }
            match owner {
                Some(owner) => {
                    rhos.push(owner.clone());
                    next.by_user.insert(*user, owner.clone());
                    next.members
                        .entry(owner.iota_id() as i64)
                        .or_default()
                        .insert(*user);
                }
                None => {
                    next.by_user.remove(user);
                }
            }
        }
        if let Some(old) = &retiring {
            let id = old.iota_id() as i64;
            if next
                .by_iota
                .get(&id)
                .is_some_and(|current| Arc::ptr_eq(current, old))
            {
                next.by_iota.remove(&id);
                // A same-ID replacement receives its members from assignments.
                if installing
                    .as_ref()
                    .is_none_or(|new| new.iota_id() != old.iota_id())
                {
                    next.members.remove(&id);
                }
            }
        }
        if let Some(rho) = &installing {
            next.by_iota.insert(rho.iota_id() as i64, rho.clone());
            next.members.entry(rho.iota_id() as i64).or_default();
            rhos.push(rho.clone());
        }
        // Publish canonical key bindings in the same generation as ownership.
        // Ambiguous keys cannot select an arbitrary numeric transport identity.
        next.by_node.clear();
        let mut ambiguous = HashSet::new();
        for rho in next.by_iota.values() {
            if let Some(node) = &rho.get_iota_connection().node_id
                && next.by_node.insert(node.clone(), rho.clone()).is_some()
            {
                ambiguous.insert(node.clone());
            }
        }
        for node in ambiguous {
            next.by_node.remove(&node);
        }
        if let Some(rho) = &retiring {
            rhos.push(rho.clone());
        }
        rhos.sort_by_key(|rho| (rho.iota_id(), Arc::as_ptr(rho) as usize));
        rhos.dedup_by(|a, b| Arc::ptr_eq(a, b));
        let mut clients = Vec::new();
        for rho in &rhos {
            for client in rho.get_client_connections().await {
                let user = client.user_id as i64;
                let changed = assignments.get(&user).is_some_and(|owner| {
                    owner.as_ref().is_none_or(|owner| !Arc::ptr_eq(owner, rho))
                });
                if changed || retiring.as_ref().is_some_and(|old| Arc::ptr_eq(old, rho)) {
                    clients.push((rho.clone(), client));
                }
            }
        }
        clients.sort_by_key(|(rho, client)| {
            (
                rho.iota_id(),
                Arc::as_ptr(rho) as usize,
                client.user_id,
                client.session_id,
            )
        });
        // Reconstructed Rhos can share an Iota's membership mirror. Lock each
        // mirror once, retaining the deterministic Rho order above.
        let mut seen_memberships = HashSet::new();
        let membership_sources: Vec<_> = rhos
            .iter()
            .filter(|rho| seen_memberships.insert(Arc::as_ptr(&rho.user_ids) as usize))
            .collect();
        let mut memberships = Vec::with_capacity(membership_sources.len());
        for rho in &membership_sources {
            memberships.push(rho.user_ids.write().await);
        }
        let mut routes = Vec::with_capacity(clients.len());
        let mut open = Vec::with_capacity(clients.len());
        let mut requests = Vec::with_capacity(clients.len());
        for (_, client) in &clients {
            routes.push(client.rho_connection.write().await);
            if revoke {
                open.push(client.is_open.write().await);
                requests.push(client.foreground_requests.lock().await);
            }
        }
        // No awaits after this point. Cancellation during lock acquisition
        // leaves membership, indexes and client attachments unchanged.
        for (rho, members) in membership_sources.iter().zip(&mut memberships) {
            **members = if next
                .by_iota
                .get(&(rho.iota_id() as i64))
                .is_some_and(|current| Arc::ptr_eq(&current.user_ids, &rho.user_ids))
            {
                next.members
                    .get(&(rho.iota_id() as i64))
                    .cloned()
                    .unwrap_or_default()
            } else {
                HashSet::new()
            };
        }
        for (index, (source, client)) in clients.iter().enumerate() {
            *routes[index] = None;
            if !revoke
                && let Some(new) = &installing
                && source.iota_id() == new.iota_id()
                && assignments
                    .get(&(client.user_id as i64))
                    .and_then(Option::as_ref)
                    .is_some_and(|owner| Arc::ptr_eq(owner, new))
                && new
                    .attach_registered_client(client.clone(), || Ok(()))
                    .is_ok()
            {
                *routes[index] = Some(new.clone());
            }
            source.remove_user_clients(client.user_id as i64);
            if revoke {
                *open[index] = false;
                requests[index].clear();
                client.sender.close();
                if !next
                    .by_user
                    .get(&(client.user_id as i64))
                    .is_some_and(|rho| rho.has_replacement_client(client))
                {
                    client.cleanup_local();
                }
            }
        }
        debug_assert!(next.by_user.iter().all(|(user, rho)| {
            next.by_iota
                .get(&(rho.iota_id() as i64))
                .is_some_and(|active| Arc::ptr_eq(active, rho))
                && next
                    .members
                    .get(&(rho.iota_id() as i64))
                    .is_some_and(|members| members.contains(user))
        }));
        self.publish(next);
    }

    pub async fn remove_if_current(
        &self,
        iota_id: i64,
        expected: &RhoConnection,
    ) -> Option<Arc<RhoConnection>> {
        let _mutation = self.mutation_guard().await;
        let rho = self.snapshot().by_iota.get(&iota_id).cloned()?;
        if !std::ptr::eq(rho.as_ref(), expected) {
            return None;
        }
        self.publish_assignments_locked(
            self.assignments_removed_with(&rho),
            None,
            Some(rho.clone()),
            true,
        )
        .await;
        Some(rho)
    }

    pub async fn add(&self, rho_connection: Arc<RhoConnection>) {
        let _mutation = self.mutation_guard().await;
        let iota_id = rho_connection.get_iota_id().await as i64;
        let user_ids = rho_connection.get_user_ids().await;
        let previous = self.snapshot().by_iota.get(&iota_id).cloned();
        if previous
            .as_ref()
            .is_some_and(|previous| Arc::ptr_eq(previous, &rho_connection))
        {
            return;
        }
        let mut assignments = previous
            .as_ref()
            .map(|old| self.assignments_removed_with(old))
            .unwrap_or_default();
        for user_id in user_ids {
            assignments.insert(user_id, Some(rho_connection.clone()));
        }
        self.publish_assignments_locked(assignments, Some(rho_connection), previous, false)
            .await;
        // Retained members transfer to the new Rho. Removed members keep their
        // authenticated transport, but lose Iota forwarding until reassigned.
    }

    pub async fn get_by_iota(&self, iota_id: i64) -> Option<Arc<RhoConnection>> {
        self.snapshot().by_iota.get(&iota_id).cloned()
    }

    pub(crate) fn relay_routes(
        &self,
        source: &super::iota_connection::IotaConnection,
        destination: &super::relay_router::IotaNodeId,
    ) -> Option<(super::relay_router::IotaNodeId, Option<Arc<RhoConnection>>)> {
        let snapshot = self.snapshot();
        let rho = snapshot.by_iota.get(&i64::try_from(source.iota_id).ok()?)?;
        if !std::ptr::eq(rho.get_iota_connection().as_ref(), source) {
            return None;
        }
        let node = rho.get_iota_connection().node_id.as_ref()?;
        snapshot
            .by_node
            .get(node)
            .filter(|current| Arc::ptr_eq(current, rho))
            .map(|_| (node.clone(), snapshot.by_node.get(destination).cloned()))
    }

    #[cfg(test)]
    fn canonical_iota(&self, iota_id: u64) -> Option<super::relay_router::IotaNodeId> {
        let snapshot = self.snapshot();
        let rho = snapshot.by_iota.get(&i64::try_from(iota_id).ok()?)?;
        let node = rho.get_iota_connection().node_id.as_ref()?;
        snapshot
            .by_node
            .get(node)
            .filter(|current| Arc::ptr_eq(current, rho))
            .map(|_| node.clone())
    }

    pub(crate) fn get_by_node(
        &self,
        node: &super::relay_router::IotaNodeId,
    ) -> Option<Arc<RhoConnection>> {
        self.snapshot().by_node.get(node).cloned()
    }

    pub async fn connection_count(&self) -> usize {
        self.snapshot().by_iota.len()
    }

    pub async fn iota_ids(&self) -> Vec<i64> {
        self.snapshot().by_iota.keys().copied().collect()
    }

    pub async fn connections(&self) -> Vec<Arc<RhoConnection>> {
        self.snapshot().by_iota.values().cloned().collect()
    }

    pub async fn get_client_connection(
        &self,
        user_id: i64,
        session_id: i64,
    ) -> Option<Arc<super::client_connection::ClientConnection>> {
        self.get_for_user(user_id)
            .await?
            .get_client_connection(user_id, session_id)
            .await
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn identical_assignment_updates_do_not_lock_mirrors_or_change_generation() {
        use crate::rho::{
            connection::{GeneralConnection, admission_engine},
            iota_connection::IotaConnection,
            rho_connection::RhoConnection,
            test_support,
        };
        use std::{sync::Arc, time::Duration};

        let state = test_support::state();
        let (host, peer, transport) = test_support::guest("anonymous").await;
        let general =
            GeneralConnection::admit(transport, state.clone(), &admission_engine()).unwrap();
        let rho = Arc::new(
            RhoConnection::new(IotaConnection::from_general(general, 2).await, vec![7]).await,
        );
        state.rho.add(rho.clone()).await;
        let generation = state.rho.snapshot().generation;
        let mirror = rho.user_ids.write().await;
        tokio::time::timeout(Duration::from_secs(1), async {
            state.rho.bind_user_to_iota(7, 2).await.unwrap();
            state.rho.replace_users_for_iota(2, vec![7, 7]).await;
        })
        .await
        .expect("unchanged ownership must not wait for a derived mirror");
        assert_eq!(state.rho.snapshot().generation, generation);
        drop(mirror);
        peer.sender.close().await;
        host.shutdown().await;
    }

    #[tokio::test]
    async fn canonical_routes_follow_verified_key_replacement_and_removal() {
        use crate::rho::{
            connection::{GeneralConnection, admission_engine},
            iota_connection::IotaConnection,
            relay_router::IotaNodeId,
            rho_connection::RhoConnection,
            test_support,
        };
        use std::sync::Arc;

        let state = test_support::state();
        let (host, peer, transport) = test_support::authenticated("iota").await;
        let expected =
            IotaNodeId::from_public_keys(transport.client_public_key.as_ref().unwrap()).unwrap();
        let general =
            GeneralConnection::admit(transport, state.clone(), &admission_engine()).unwrap();
        let old = Arc::new(
            RhoConnection::new(
                IotaConnection::from_general(general.clone(), 42).await,
                vec![7],
            )
            .await,
        );
        state.rho.add(old.clone()).await;
        assert!(
            state
                .rho
                .relay_routes(old.get_iota_connection(), &expected)
                .is_some()
        );
        assert_eq!(state.rho.canonical_iota(42), Some(expected.clone()));
        assert!(Arc::ptr_eq(
            &state.rho.get_by_node(&expected).unwrap(),
            &old
        ));

        let (new_host, new_peer, transport) = test_support::authenticated("iota").await;
        let replacement_key =
            IotaNodeId::from_public_keys(transport.client_public_key.as_ref().unwrap()).unwrap();
        assert_ne!(expected, replacement_key);
        let replacement_general =
            GeneralConnection::admit(transport, state.clone(), &admission_engine()).unwrap();
        let replacement = Arc::new(
            RhoConnection::new(
                IotaConnection::from_general(replacement_general, 42).await,
                vec![7],
            )
            .await,
        );
        state.rho.add(replacement.clone()).await;
        assert!(
            state
                .rho
                .relay_routes(old.get_iota_connection(), &replacement_key)
                .is_none()
        );
        assert!(
            state
                .rho
                .relay_routes(replacement.get_iota_connection(), &replacement_key)
                .is_some()
        );
        assert!(state.rho.get_by_node(&expected).is_none());
        assert!(Arc::ptr_eq(
            &state.rho.get_by_node(&replacement_key).unwrap(),
            &replacement
        ));
        assert!(state.rho.remove_if_current(42, &old).await.is_none());
        assert!(state.rho.get_by_node(&replacement_key).is_some());
        state.rho.remove_if_current(42, &replacement).await.unwrap();
        assert!(state.rho.get_by_node(&replacement_key).is_none());

        // The same verified key under two numeric transport IDs is ambiguous.
        let a = Arc::new(
            RhoConnection::new(
                IotaConnection::from_general(general.clone(), 42).await,
                vec![],
            )
            .await,
        );
        let b = Arc::new(
            RhoConnection::new(IotaConnection::from_general(general, 43).await, vec![]).await,
        );
        state.rho.add(a.clone()).await;
        state.rho.add(b.clone()).await;
        assert!(state.rho.get_by_node(&expected).is_none());
        assert!(state.rho.canonical_iota(42).is_none());
        state.rho.remove_if_current(43, &b).await.unwrap();
        assert!(Arc::ptr_eq(&state.rho.get_by_node(&expected).unwrap(), &a));
        peer.sender.close().await;
        new_peer.sender.close().await;
        host.shutdown().await;
        new_host.shutdown().await;
    }

    #[tokio::test]
    async fn unsigned_numeric_identity_cannot_create_a_canonical_route() {
        use crate::rho::{
            connection::{GeneralConnection, admission_engine},
            iota_connection::IotaConnection,
            rho_connection::RhoConnection,
            test_support,
        };
        use std::sync::Arc;
        let state = test_support::state();
        let (host, peer, transport) = test_support::guest("anonymous").await;
        let general =
            GeneralConnection::admit(transport, state.clone(), &admission_engine()).unwrap();
        let rho = Arc::new(
            RhoConnection::new(IotaConnection::from_general(general, 42).await, vec![7]).await,
        );
        state.rho.add(rho).await;
        assert!(state.rho.get_by_iota(42).await.is_some());
        assert!(state.rho.canonical_iota(42).is_none());
        assert!(state.rho.snapshot().by_node.is_empty());
        peer.sender.close().await;
        host.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn readers_see_whole_snapshots_while_publication_is_paused() {
        use crate::rho::{
            connection::{GeneralConnection, admission_engine},
            iota_connection::IotaConnection,
            rho_connection::RhoConnection,
            test_support,
        };
        use std::sync::{Arc, Barrier};
        let state = test_support::state();
        let (host, peer, transport) = test_support::guest("anonymous").await;
        let general =
            GeneralConnection::admit(transport, state.clone(), &admission_engine()).unwrap();
        let old = Arc::new(
            RhoConnection::new(
                IotaConnection::from_general(general.clone(), 2).await,
                vec![7],
            )
            .await,
        );
        state.rho.add(old.clone()).await;
        let before = state.rho.snapshot();
        let next = Arc::new(
            RhoConnection::new(IotaConnection::from_general(general, 3).await, vec![7]).await,
        );
        let reached = Arc::new(Barrier::new(2));
        let resume = Arc::new(Barrier::new(2));
        *state.rho.before_publish.lock().unwrap() = Some((reached.clone(), resume.clone()));
        let publication = tokio::spawn({
            let state = state.clone();
            let next = next.clone();
            async move { state.rho.add(next).await }
        });
        reached.wait();
        let paused = state.rho.snapshot();
        assert_eq!(paused.generation, before.generation);
        assert!(Arc::ptr_eq(paused.by_user.get(&7).unwrap(), &old));
        assert!(!paused.by_iota.contains_key(&3));
        assert!(paused.members.get(&2).unwrap().contains(&7));
        resume.wait();
        publication.await.unwrap();
        let after = state.rho.snapshot();
        assert!(after.generation > before.generation);
        assert!(Arc::ptr_eq(
            after.by_user.get(&7).unwrap(),
            after.by_iota.get(&3).unwrap()
        ));
        assert!(after.members.get(&3).unwrap().contains(&7));
        assert!(!after.members.get(&2).unwrap().contains(&7));
        assert!(!state.rho.owns_iota_user(7, old.get_iota_connection()));
        assert!(before.members.get(&2).unwrap().contains(&7));
        peer.sender.close().await;
        host.shutdown().await;
    }

    #[tokio::test]
    async fn reassignment_replacement_and_revocation_share_membership_authority() {
        use crate::rho::{
            connection::{GeneralConnection, admission_engine},
            iota_connection::IotaConnection,
            rho_connection::RhoConnection,
            test_support,
        };
        use std::sync::Arc;
        let state = test_support::state();
        let (host, peer, transport) = test_support::guest("anonymous").await;
        let general =
            GeneralConnection::admit(transport, state.clone(), &admission_engine()).unwrap();
        let a = Arc::new(
            RhoConnection::new(
                IotaConnection::from_general(general.clone(), 2).await,
                vec![7, 7],
            )
            .await,
        );
        let b = Arc::new(
            RhoConnection::new(
                IotaConnection::from_general(general.clone(), 3).await,
                vec![],
            )
            .await,
        );
        state.rho.add(a.clone()).await;
        state.rho.add(b.clone()).await;
        assert!(Arc::ptr_eq(&a.user_ids, &a.get_iota_connection().user_ids));
        assert_eq!(a.get_user_ids().await, vec![7]);
        let client =
            crate::rho::client_connection::ClientConnection::from_general(general.clone(), 7).await;
        *client.rho_connection.write().await = Some(a.clone());
        a.add_client_connection(client.clone()).await;
        state.rho.bind_user_to_iota(7, 3).await.unwrap();
        assert!(a.get_user_ids().await.is_empty());
        assert!(a.get_iota_connection().get_user_ids().await.is_empty());
        assert_eq!(b.get_user_ids().await, vec![7]);
        assert_eq!(b.get_iota_connection().get_user_ids().await, vec![7]);
        assert!(Arc::ptr_eq(&state.rho.get_for_user(7).await.unwrap(), &b));
        assert!(client.get_rho_connection().await.is_none());
        assert_eq!(a.client_count().await, 0);
        state.rho.bind_user_to_iota(7, 2).await.unwrap();
        state.rho.bind_user_to_iota(7, 2).await.unwrap();
        assert_eq!(a.get_user_ids().await, vec![7]);
        assert!(b.get_user_ids().await.is_empty());
        state.rho.replace_users_for_iota(3, vec![7, 8]).await;
        assert!(a.get_user_ids().await.is_empty());
        assert_eq!(b.get_user_ids().await, vec![7, 8]);
        let replacement = Arc::new(
            RhoConnection::new(IotaConnection::from_general(general, 2).await, vec![7]).await,
        );
        state.rho.add(replacement.clone()).await;
        assert_eq!(b.get_user_ids().await, vec![8]);
        assert!(a.get_user_ids().await.is_empty());
        assert!(state.rho.remove_if_current(2, &a).await.is_none());
        assert!(Arc::ptr_eq(
            &state.rho.get_for_user(7).await.unwrap(),
            &replacement
        ));
        state.rho.invalidate_user(7).await;
        assert!(replacement.get_user_ids().await.is_empty());
        assert!(
            replacement
                .get_iota_connection()
                .get_user_ids()
                .await
                .is_empty()
        );
        assert!(state.rho.get_for_user(7).await.is_none());
        state.rho.remove_if_current(3, &b).await.unwrap();
        assert!(b.get_user_ids().await.is_empty());
        assert!(state.rho.get_for_user(8).await.is_none());
        peer.sender.close().await;
        host.shutdown().await;
    }

    #[tokio::test]
    async fn binding_and_replacement_share_one_ownership_boundary() {
        use crate::rho::{
            connection::{GeneralConnection, admission_engine},
            iota_connection::IotaConnection,
            rho_connection::RhoConnection,
            test_support,
        };
        use std::sync::Arc;
        let state = test_support::state();
        let (host, peer, transport) = test_support::guest("anonymous").await;
        let general =
            GeneralConnection::admit(transport, state.clone(), &admission_engine()).unwrap();
        let old = Arc::new(
            RhoConnection::new(
                IotaConnection::from_general(general.clone(), 2).await,
                vec![7, 8],
            )
            .await,
        );
        state.rho.add(old.clone()).await;
        let client =
            crate::rho::client_connection::ClientConnection::from_general(general.clone(), 7).await;
        *client.rho_connection.write().await = Some(old.clone());
        old.add_client_connection(client.clone()).await;
        // Hold membership so binding pauses after acquiring the mutation guard.
        let members = old.user_ids.write().await;
        let binding = tokio::spawn({
            let state = state.clone();
            async move { state.rho.bind_user_to_iota(9, 2).await }
        });
        loop {
            if state.rho.mutations.try_lock().is_err() {
                break;
            }
            tokio::task::yield_now().await;
        }
        let replacement = Arc::new(
            RhoConnection::new(
                IotaConnection::from_general(general.clone(), 2).await,
                vec![7],
            )
            .await,
        );
        let replacing = tokio::spawn({
            let state = state.clone();
            let replacement = replacement.clone();
            async move { state.rho.add(replacement).await }
        });
        drop(members);
        binding.await.unwrap().unwrap();
        replacing.await.unwrap();
        assert!(state.rho.get_for_user(8).await.is_none());
        assert!(state.rho.get_for_user(9).await.is_none());
        assert!(Arc::ptr_eq(
            &state.rho.get_for_user(7).await.unwrap(),
            &replacement
        ));
        assert!(Arc::ptr_eq(
            &client.get_rho_connection().await.unwrap(),
            &replacement
        ));
        assert_eq!(replacement.client_count().await, 1);
        assert_eq!(old.client_count().await, 0);
        let disjoint = Arc::new(
            RhoConnection::new(IotaConnection::from_general(general, 2).await, vec![10]).await,
        );
        state.rho.add(disjoint.clone()).await;
        assert!(client.get_rho_connection().await.is_none());
        assert_eq!(disjoint.client_count().await, 0);
        assert!(state.rho.get_for_user(7).await.is_none());
        state.rho.remove_if_current(2, &old).await;
        assert!(Arc::ptr_eq(
            &state.rho.get_for_user(10).await.unwrap(),
            &disjoint
        ));
        peer.sender.close().await;
        host.shutdown().await;
    }

    #[tokio::test]
    async fn registration_commit_rejects_stale_generation_after_assignment_returns() {
        use crate::rho::{
            connection::{GeneralConnection, admission_engine},
            iota_connection::IotaConnection,
            rho_connection::RhoConnection,
            test_support,
        };
        use std::sync::Arc;
        let state = test_support::state();
        let (host, peer, transport) = test_support::guest("registering-client").await;
        let general =
            GeneralConnection::admit(transport, state.clone(), &admission_engine()).unwrap();
        let rho = Arc::new(
            RhoConnection::new(
                IotaConnection::from_general(general.clone(), 2).await,
                vec![7],
            )
            .await,
        );
        state.rho.add(rho).await;
        let (client, rho, generation) = general.prepare_registered_client(7, 2).await.unwrap();
        state.rho.replace_users_for_iota(2, Vec::new()).await;
        {
            let mutation = state.rho.mutation_guard().await;
            assert!(
                state
                    .rho
                    .attach_registered_client(
                        &mutation,
                        &rho,
                        generation,
                        client.clone(),
                        || panic!("removed assignment committed"),
                    )
                    .is_err()
            );
        }
        state.rho.bind_user_to_iota(7, 2).await.unwrap();
        let mut committed = false;
        let mutation = state.rho.mutation_guard().await;
        assert!(
            state
                .rho
                .attach_registered_client(&mutation, &rho, generation, client, || {
                    committed = true;
                    Ok(())
                })
                .is_err()
        );
        assert!(!committed);
        assert_eq!(rho.client_count().await, 0);
        assert!(matches!(
            general.tau_session.read().await.authentication(),
            tau::ApplicationAuthentication::Guest
        ));
        drop(mutation);
        let (client, prepared_rho, generation) =
            general.prepare_registered_client(7, 2).await.unwrap();
        let replacement = Arc::new(
            RhoConnection::new(
                IotaConnection::from_general(general.clone(), 2).await,
                vec![7],
            )
            .await,
        );
        state.rho.add(replacement.clone()).await;
        let mutation = state.rho.mutation_guard().await;
        assert!(
            state
                .rho
                .attach_registered_client(&mutation, &prepared_rho, generation, client, || panic!(
                    "obsolete Rho registration committed"
                ),)
                .is_err()
        );
        assert_eq!(replacement.client_count().await, 0);
        drop(mutation);
        peer.sender.close().await;
        host.shutdown().await;
    }

    #[tokio::test]
    async fn publication_does_not_wait_for_unrelated_rho_or_client_locks() {
        use std::sync::Arc;

        use crate::rho::{
            client_connection::ClientConnection,
            connection::{GeneralConnection, admission_engine},
            iota_connection::IotaConnection,
            rho_connection::RhoConnection,
            test_support,
        };
        let state = test_support::state();
        let (host, peer, transport) = test_support::guest("anonymous").await;
        let general =
            GeneralConnection::admit(transport, state.clone(), &admission_engine()).unwrap();
        let affected = Arc::new(
            RhoConnection::new(
                IotaConnection::from_general(general.clone(), 2).await,
                vec![7],
            )
            .await,
        );
        let unrelated = Arc::new(
            RhoConnection::new(
                IotaConnection::from_general(general.clone(), 3).await,
                vec![8],
            )
            .await,
        );
        state.rho.add(affected.clone()).await;
        state.rho.add(unrelated.clone()).await;
        // A stale mirror must not become authoritative during publication.
        affected.user_ids.write().await.insert(99);
        let client = ClientConnection::from_general(general, 8).await;
        unrelated.add_client_connection(client.clone()).await;
        let members = unrelated.user_ids.write().await;
        let route = client.rho_connection.write().await;
        let open = client.is_open.write().await;
        let requests = client.foreground_requests.lock().await;
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            state.rho.invalidate_user(7),
        )
        .await
        .expect("unrelated locks must not block routing publication");
        assert!(state.rho.get_for_user(7).await.is_none());
        assert!(state.rho.snapshot().members.get(&2).unwrap().is_empty());
        assert!(affected.get_user_ids().await.is_empty());
        assert!(Arc::ptr_eq(
            &state.rho.get_for_user(8).await.unwrap(),
            &unrelated
        ));
        assert!(members.contains(&8));
        drop((members, route, open, requests));
        peer.sender.close().await;
        host.shutdown().await;
    }
}
