use super::{client_connection::ClientConnection, iota_connection::IotaConnection, rho_manager};
use crate::data::{
    communication::{CommunicationType, CommunicationValue, DataTypes},
    user::UserStatus,
};
use crate::omega::omega_connection::OmegaConnection;
use json::{JsonValue, number::Number};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct RhoConnection {
    iota_connection: Arc<IotaConnection>,
    user_ids: Vec<i64>,
    client_connections: Arc<RwLock<Vec<Arc<ClientConnection>>>>,
}

impl RhoConnection {
    /// Create a new RhoConnection
    pub async fn new(iota_connection: Arc<IotaConnection>, user_ids: Vec<i64>) -> Self {
        let rho_connection = Self {
            iota_connection,
            user_ids: user_ids.clone(),
            client_connections: Arc::new(RwLock::new(Vec::new())),
        };

        rho_connection
    }

    pub async fn get_iota_id(&self) -> i64 {
        self.iota_connection.get_iota_id().await
    }

    pub fn get_user_ids(&self) -> &Vec<i64> {
        &self.user_ids
    }

    pub fn get_iota_connection(&self) -> &Arc<IotaConnection> {
        &self.iota_connection
    }

    pub async fn get_client_connections(&self) -> Vec<Arc<ClientConnection>> {
        let connections = self.client_connections.read().await;
        connections.clone()
    }

    /// Get client connections for a specific user
    pub async fn get_client_connections_for_user(
        &self,
        user_id: i64,
    ) -> Vec<Arc<ClientConnection>> {
        let connections = self.client_connections.read().await;
        let mut collections = Vec::new();
        for con in connections.iter() {
            if con.get_user_id().await == user_id {
                collections.push(con.clone());
            }
        }
        collections
    }

    /// Add a client connection
    pub async fn add_client_connection(&self, connection: Arc<ClientConnection>) {
        let notification = CommunicationValue::new(CommunicationType::client_connected).add_data(
            DataTypes::user_id,
            JsonValue::Number(Number::from(connection.get_user_id().await)),
        );

        self.iota_connection.send_message(&notification).await;

        {
            let mut connections = self.client_connections.write().await;
            connections.push(Arc::clone(&connection));
        }

        OmegaConnection::client_changed(
            self.get_iota_id().await,
            connection.get_user_id().await,
            UserStatus::online,
        )
        .await;
    }

    /// Remove a client connection
    pub async fn close_client_connection(&self, connection: Arc<ClientConnection>) {
        {
            let mut connections = self.client_connections.write().await;

            let target_user_id = connection.get_user_id().await;

            connections.retain(|con| {
                futures::executor::block_on(async { con.get_user_id().await != target_user_id })
            });

            connections.push(Arc::clone(&connection));
        }

        // Notify OmegaConnection
        OmegaConnection::client_changed(
            self.get_iota_id().await,
            connection.get_user_id().await,
            UserStatus::user_offline,
        )
        .await;
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
        OmegaConnection::close_iota(self.get_iota_id().await).await;
    }

    /// Send message from Iota to specific client
    pub async fn message_to_client(&self, cv: CommunicationValue) {
        let connections = self.client_connections.read().await;
        for connection in connections.iter() {
            if connection.get_user_id().await == cv.get_receiver() {
                connection.send_message(&cv).await;
            }
        }
    }

    /// Send message to Iota
    pub async fn message_to_iota(&self, cv: CommunicationValue) {
        self.iota_connection.send_message(&cv).await;
    }

    /// Set interested users for a specific client
    pub async fn set_interested(&self, user_id: i64, interested_ids: Vec<i64>) {
        let connections = self.client_connections.read().await;
        for connection in connections.iter() {
            let conn_user_id = connection.get_user_id().await;
            if conn_user_id == user_id {
                connection
                    .set_interested_users(interested_ids.clone())
                    .await;
                break;
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
            let user_id = connection.get_user_id().await;
            pings.insert(user_id.to_string(), connection.get_ping().await);
        }

        pings
    }

    /// Check if this RhoConnection contains a specific user ID
    pub fn contains_user(&self, user_id: &i64) -> bool {
        self.user_ids.contains(user_id)
    }

    /// Get count of active client connections
    pub async fn client_count(&self) -> usize {
        let connections = self.client_connections.read().await;
        connections.len()
    }
}
