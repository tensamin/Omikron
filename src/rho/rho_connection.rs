use std::collections::{self, HashMap};
use std::sync::{Arc, Weak};
use tokio::sync::RwLock;
use uuid::Uuid;

use super::{client_connection::ClientConnection, iota_connection::IotaConnection, rho_manager};
use crate::data::{
    communication::{CommunicationType, CommunicationValue, DataTypes},
    user::UserStatus,
};
use crate::omega::omega_connection::OmegaConnection;

pub struct RhoConnection {
    iota_connection: Arc<IotaConnection>,
    user_ids: Vec<Uuid>,
    client_connections: Arc<RwLock<Vec<Arc<ClientConnection>>>>,
}

impl RhoConnection {
    /// Create a new RhoConnection
    pub async fn new(iota_connection: Arc<IotaConnection>, user_ids: Vec<Uuid>) -> Self {
        let rho_connection = Self {
            iota_connection,
            user_ids: user_ids.clone(),
            client_connections: Arc::new(RwLock::new(Vec::new())),
        };

        // Notify OmegaConnection about the new Iota
        OmegaConnection::connect_iota(rho_connection.get_iota_id().await, user_ids);

        rho_connection
    }

    /// Get the Iota ID
    pub async fn get_iota_id(&self) -> Uuid {
        self.iota_connection.get_iota_id().await
    }

    /// Get the user IDs associated with this Rho connection
    pub fn get_user_ids(&self) -> &Vec<Uuid> {
        &self.user_ids
    }

    /// Get reference to the IotaConnection
    pub fn get_iota_connection(&self) -> &Arc<IotaConnection> {
        &self.iota_connection
    }

    /// Get all client connections
    pub async fn get_client_connections(&self) -> Vec<Arc<ClientConnection>> {
        let connections = self.client_connections.read().await;
        connections.clone()
    }

    /// Get client connections for a specific user
    pub async fn get_client_connections_for_user(
        &self,
        user_id: Uuid,
    ) -> Vec<Arc<ClientConnection>> {
        let connections = self.client_connections.read().await;
        let mut collections = Vec::new();
        for con in connections.iter() {
            if con.get_user_id().await.unwrap() == user_id {
                collections.push(con.clone());
            }
        }
        collections
    }

    /// Add a client connection
    pub async fn add_client_connection(&self, connection: Arc<ClientConnection>) {
        // Notify Iota about new client
        let notification = CommunicationValue::new(CommunicationType::client_connected)
            .add_data_str(
                DataTypes::user_id,
                connection
                    .get_user_id()
                    .await
                    .unwrap_or(Uuid::nil())
                    .to_string(),
            );

        self.iota_connection.send_message(notification).await;

        // Add to our list
        {
            let mut connections = self.client_connections.write().await;
            connections.push(Arc::clone(&connection));
        }

        // Notify OmegaConnection
        OmegaConnection::client_changed(
            self.get_iota_id().await,
            connection.get_user_id().await.unwrap_or(Uuid::nil()),
            UserStatus::online,
        );
    }

    /// Remove a client connection
    pub async fn close_client_connection(&self, connection: Arc<ClientConnection>) {
        {
            let mut connections = self.client_connections.write().await;

            let target_user_id = connection.get_user_id().await.unwrap();

            connections.retain(|con| {
                futures::executor::block_on(async {
                    con.get_user_id().await.unwrap() != target_user_id
                })
            });

            // Push the new connection
            connections.push(Arc::clone(&connection));
        }

        // Notify OmegaConnection
        OmegaConnection::client_changed(
            self.get_iota_id().await,
            connection.get_user_id().await.unwrap_or(Uuid::nil()),
            UserStatus::user_offline,
        );
    }

    /// Close the Iota connection and all associated client connections
    pub async fn close_iota_connection(&self) {
        // Close all client connections
        let connections = self.get_client_connections().await;
        for connection in connections {
            connection.close().await;
        }

        // Remove from manager
        rho_manager::remove_rho(self.get_iota_id().await).await;

        // Notify OmegaConnection
        OmegaConnection::close_iota(self.get_iota_id().await);
    }

    /// Send message from Iota to specific client by user ID
    pub async fn message_iota_to_client_by_user(&self, user_id: Uuid, message: &str) {
        let connections = self.client_connections.read().await;
        for connection in connections.iter() {
            if let Some(conn_user_id) = connection.get_user_id().await {
                if conn_user_id == user_id {
                    connection.send_message_str(message).await;
                }
            }
        }
    }

    /// Send message from Iota to specific client
    pub async fn message_iota_to_client(&self, cv: CommunicationValue) {
        if let Some(receiver_id) = Some(cv.get_receiver()) {
            let connections = self.client_connections.read().await;
            for connection in connections.iter() {
                if let Some(conn_user_id) = connection.get_user_id().await {
                    if conn_user_id == receiver_id {
                        connection.send_message(&cv).await;
                    }
                }
            }
        }
    }

    /// Send message to Iota as string
    pub async fn message_to_iota_str(&self, message: &str) {
        self.iota_connection.send_message_str(message).await;
    }

    /// Send message to Iota
    pub async fn message_to_iota(&self, cv: CommunicationValue) {
        self.iota_connection.send_message(cv).await;
    }

    /// Set interested users for a specific client
    pub async fn set_interested(&self, user_id: Uuid, interested_ids: Vec<Uuid>) {
        let connections = self.client_connections.read().await;
        for connection in connections.iter() {
            if let Some(conn_user_id) = connection.get_user_id().await {
                if conn_user_id == user_id {
                    connection
                        .set_interested_users(interested_ids.clone())
                        .await;
                    break;
                }
            }
        }
    }

    /// Check if clients are interested in a user
    pub async fn are_they_interested(&self, user: &crate::data::user::User) {
        let connections = self.client_connections.read().await;
        for connection in connections.iter() {
            connection.are_you_interested(user).await;
        }
    }

    /// Get ping information for all clients
    pub async fn get_client_pings(&self) -> HashMap<String, i64> {
        let connections = self.client_connections.read().await;
        let mut pings = HashMap::new();

        for connection in connections.iter() {
            if let Some(user_id) = connection.get_user_id().await {
                pings.insert(user_id.to_string(), connection.get_ping().await);
            }
        }

        pings
    }

    /// Check if this RhoConnection contains a specific user ID
    pub fn contains_user(&self, user_id: &Uuid) -> bool {
        self.user_ids.contains(user_id)
    }

    /// Get count of active client connections
    pub async fn client_count(&self) -> usize {
        let connections = self.client_connections.read().await;
        connections.len()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::Mutex;

    #[tokio::test]
    async fn test_rho_connection_creation() {
        let iota_id = Uuid::new_v4();
        let user_ids = vec![Uuid::new_v4(), Uuid::new_v4()];

        // Mock session
        // Create a mock WebSocket stream (this would fail in practice but shows the API)
        // In real implementation, this would be a proper WebSocketStream
        let mock_stream =
            std::ptr::null_mut() as *mut tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>;
        let mock_stream = unsafe { std::ptr::read(mock_stream) };
        let iota_conn = IotaConnection::new_with_ids(
            iota_id,
            user_ids.clone(),
            Arc::new(tokio::sync::Mutex::new(mock_stream)),
        );

        let rho_conn = RhoConnection::new(iota_conn, user_ids.clone()).await;

        assert_eq!(rho_conn.get_iota_id().await, iota_id);
        assert_eq!(rho_conn.get_user_ids(), &user_ids);
        assert_eq!(rho_conn.client_count().await, 0);
    }
}
