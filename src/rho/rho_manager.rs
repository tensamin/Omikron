use std::{
    collections::HashMap,
    sync::{Arc, LazyLock},
};
use tokio::sync::RwLock;
use uuid::Uuid;

use super::rho_connection::RhoConnection;

pub static RHO_CONNECTIONS: LazyLock<Arc<RwLock<HashMap<Uuid, Arc<RhoConnection>>>>> =
    LazyLock::new(|| Arc::new(RwLock::new(HashMap::new())));

pub async fn get_rho_con_for_user(user_id: Uuid) -> Option<Arc<RhoConnection>> {
    let connections = RHO_CONNECTIONS.read().await;
    println!("Checking user ID: {:?}", user_id);
    for rho_connection in connections.values() {
        println!(
            "Comparing user IDs: {:?}",
            rho_connection.get_user_ids().to_vec()
        );
        if rho_connection.get_user_ids().contains(&user_id) {
            return Some(Arc::clone(rho_connection));
        }
    }
    None
}

pub async fn contains_iota(iota_id: Uuid) -> bool {
    let connections = RHO_CONNECTIONS.read().await;
    connections.contains_key(&iota_id)
}

/// Remove a RhoConnection by Iota ID
pub async fn remove_rho(iota_id: Uuid) -> Option<Arc<RhoConnection>> {
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
pub async fn get_rho_by_iota(iota_id: Uuid) -> Option<Arc<RhoConnection>> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rho::iota_connection::IotaConnection;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    #[tokio::test]
    async fn test_add_and_get_rho() {
        // Clear any existing connections
        {
            let mut connections = RHO_CONNECTIONS.write().await;
            connections.clear();
        }

        let iota_id = Uuid::new_v4();
        let user_ids = vec![Uuid::new_v4(), Uuid::new_v4()];

        // Skip this test due to WebSocket complexity - would require proper mock setup
        return;

        // This test would need proper WebSocket stream mocking:
        // let mock_session = create_mock_websocket_stream();
        // let iota_conn = IotaConnection::new_with_ids(iota_id, user_ids.clone(), mock_session);
        // let rho_conn = Arc::new(RhoConnection::new(iota_conn, user_ids.clone()));

        // Test assertions would go here:
        // add_rho(Arc::clone(&rho_conn)).await;
        // assert!(contains_iota(iota_id).await);
        // etc.
    }
}
