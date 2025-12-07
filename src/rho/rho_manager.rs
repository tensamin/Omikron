use super::rho_connection::RhoConnection;
use crate::util::print::PrintType;
use crate::util::print::line;
use std::{
    collections::HashMap,
    sync::{Arc, LazyLock},
};
use tokio::sync::RwLock;

pub static RHO_CONNECTIONS: LazyLock<Arc<RwLock<HashMap<i64, Arc<RhoConnection>>>>> =
    LazyLock::new(|| Arc::new(RwLock::new(HashMap::new())));

pub async fn get_rho_con_for_user(user_id: i64) -> Option<Arc<RhoConnection>> {
    let connections = RHO_CONNECTIONS.read().await;
    line(
        PrintType::ClientIn,
        &format!("Checking user ID: {:?}", user_id),
    );
    for rho_connection in connections.values() {
        line(
            PrintType::ClientIn,
            &format!(
                "Comparing user IDs: {:?}",
                rho_connection.get_user_ids().to_vec()
            ),
        );
        if rho_connection.get_user_ids().contains(&user_id) {
            return Some(Arc::clone(rho_connection));
        }
    }
    None
}

pub async fn contains_iota(iota_id: i64) -> bool {
    let connections = RHO_CONNECTIONS.read().await;
    connections.contains_key(&iota_id)
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
    connections.insert(iota_id, rho_connection);
}

/// Get a RhoConnection by Iota ID directly
pub async fn get_rho_by_iota(iota_id: i64) -> Option<Arc<RhoConnection>> {
    let connections = RHO_CONNECTIONS.read().await;
    connections.get(&iota_id).map(Arc::clone)
}

/// Get all active RhoConnections
pub async fn get_all_connections() -> Vec<Arc<RhoConnection>> {
    let connections = RHO_CONNECTIONS.read().await;
    connections.values().map(Arc::clone).collect()
}

/// Get the count of active connections
pub async fn connection_count() -> usize {
    let connections = RHO_CONNECTIONS.read().await;
    connections.len()
}
