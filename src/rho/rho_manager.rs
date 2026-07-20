use std::sync::Arc;

use dashmap::DashMap;

use super::rho_connection::RhoConnection;

/*
 * Owns both indices for active Iota connections. Keeping the user index next
 * to the Iota index makes binding updates atomic from the manager's caller's
 * perspective and lets separate Omikron instances keep separate routing state.
 */
#[derive(Default)]
pub struct RhoManager {
    connections: DashMap<i64, Arc<RhoConnection>>,
    users: DashMap<i64, Arc<RhoConnection>>,
}

impl RhoManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn get_for_user(&self, user_id: i64) -> Option<Arc<RhoConnection>> {
        self.users.get(&user_id).map(|entry| entry.value().clone())
    }

    pub async fn contains_iota(&self, iota_id: i64) -> bool {
        self.connections.contains_key(&iota_id)
    }

    pub async fn bind_user_to_iota(
        &self,
        user_id: i64,
        iota_id: i64,
    ) -> Option<Arc<RhoConnection>> {
        let rho = self
            .connections
            .get(&iota_id)
            .map(|entry| entry.value().clone());
        if let Some(rho) = rho {
            rho.add_user_id(user_id).await;
            self.users.insert(user_id, rho.clone());
            Some(rho)
        } else {
            None
        }
    }

    pub async fn replace_users_for_iota(&self, iota_id: i64, user_ids: Vec<i64>) {
        let rho = self
            .connections
            .get(&iota_id)
            .map(|entry| entry.value().clone());
        let Some(rho) = rho else {
            return;
        };

        let previous_users = rho.get_user_ids().await;
        rho.set_user_ids(user_ids.clone()).await;
        rho.get_iota_connection()
            .set_user_ids(
                user_ids
                    .iter()
                    .filter_map(|user_id| u64::try_from(*user_id).ok())
                    .collect(),
            )
            .await;

        for user_id in previous_users {
            if self
                .users
                .get(&user_id)
                .is_some_and(|entry| Arc::ptr_eq(entry.value(), &rho))
            {
                self.users.remove(&user_id);
            }
        }
        for user_id in user_ids {
            self.users.insert(user_id, rho.clone());
        }
    }

    pub async fn remove_user_binding(&self, user_id: i64, iota_id: i64) {
        let rho = self.users.get(&user_id).map(|entry| entry.value().clone());
        if let Some(rho) = rho {
            if rho.get_iota_id().await as i64 == iota_id {
                self.users.remove(&user_id);
            }
        }
    }

    pub async fn remove(&self, iota_id: i64) -> Option<Arc<RhoConnection>> {
        let rho = self.connections.remove(&iota_id).map(|(_, rho)| rho);
        if let Some(rho) = rho.as_ref() {
            self.users.retain(|_, mapped| !Arc::ptr_eq(mapped, rho));
        }
        rho
    }

    pub async fn add(&self, rho_connection: Arc<RhoConnection>) {
        let iota_id = rho_connection.get_iota_id().await as i64;
        let user_ids = rho_connection.get_user_ids().await;
        self.connections.insert(iota_id, rho_connection.clone());
        for user_id in user_ids {
            self.users.insert(user_id, rho_connection.clone());
        }
    }

    pub async fn get_by_iota(&self, iota_id: i64) -> Option<Arc<RhoConnection>> {
        self.connections
            .get(&iota_id)
            .map(|entry| entry.value().clone())
    }

    pub async fn connection_count(&self) -> usize {
        self.connections.len()
    }

    pub async fn iota_ids(&self) -> Vec<i64> {
        self.connections.iter().map(|entry| *entry.key()).collect()
    }

    pub async fn connections(&self) -> Vec<Arc<RhoConnection>> {
        self.connections
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }
}
