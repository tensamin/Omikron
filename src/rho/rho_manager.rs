use super::rho_connection::RhoConnection;
use crate::log_in;
use crate::util::logger::PrintType;
use std::{
    collections::HashMap,
    sync::{Arc, LazyLock},
};
use tokio::sync::RwLock;

pub static RHO_CONNECTIONS: LazyLock<Arc<RwLock<HashMap<i64, Arc<RhoConnection>>>>> =
    LazyLock::new(|| Arc::new(RwLock::new(HashMap::new())));

pub async fn get_rho_con_for_user(user_id: i64) -> Option<Arc<RhoConnection>> {
    let connections = RHO_CONNECTIONS.read().await;
    for rho_connection in connections.values() {
        let rho_user_ids = rho_connection.get_user_ids().await;
        log_in!(
            user_id,
            PrintType::Client,
            "Comparing user IDs: {:?}",
            rho_user_ids
        );
        if rho_user_ids.contains(&user_id) {
            return Some(Arc::clone(rho_connection));
        }
    }
    None
}

#[allow(dead_code)]
pub async fn contains_iota(iota_id: i64) -> bool {
    let connections = RHO_CONNECTIONS.read().await;
    connections.contains_key(&iota_id)
}

/// Bind a user ID to an already tracked iota/rho connection.
pub async fn bind_user_to_iota(user_id: i64, iota_id: i64) -> Option<Arc<RhoConnection>> {
    let connections = RHO_CONNECTIONS.read().await;
    if let Some(rho_connection) = connections.get(&iota_id) {
        let rho = Arc::clone(rho_connection);
        drop(connections);

        rho.add_user_id(user_id).await;

        log_in!(
            user_id,
            PrintType::Client,
            "Bound user {} to iota {}",
            user_id,
            iota_id
        );

        Some(rho)
    } else {
        None
    }
}

/// Remove a RhoConnection by Iota ID
pub async fn remove_rho(iota_id: i64) -> Option<Arc<RhoConnection>> {
    let mut connections = RHO_CONNECTIONS.write().await;
    connections.remove(&iota_id)
}

/// Add a RhoConnection to the manager
pub async fn add_rho(rho_connection: Arc<RhoConnection>) {
    let mut connections = RHO_CONNECTIONS.write().await;
    let iota_id = rho_connection.get_iota_id().await;
    connections.insert(iota_id as i64, rho_connection);
}

/// Get a RhoConnection by Iota ID directly
#[allow(dead_code)]
pub async fn get_rho_by_iota(iota_id: i64) -> Option<Arc<RhoConnection>> {
    let connections = RHO_CONNECTIONS.read().await;
    connections.get(&iota_id).map(Arc::clone)
}

/// Get the count of active connections
pub async fn connection_count() -> usize {
    let connections = RHO_CONNECTIONS.read().await;
    connections.len()
}
