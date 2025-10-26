use super::{client_connection::ClientConnection, iota_connection::IotaConnection, rho_manager};
use crate::data::{
    communication::{CommunicationType, CommunicationValue, DataTypes},
    user::UserStatus,
};
use crate::omega::omega_connection::OmegaConnection;
use crate::util::print::PrintType;
use crate::util::print::line;
use crate::util::print::line_err;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

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
        OmegaConnection::connect_iota(rho_connection.get_iota_id().await, user_ids).await;

        rho_connection
    }

    pub async fn get_iota_id(&self) -> Uuid {
        self.iota_connection.get_iota_id().await
    }

    pub fn get_user_ids(&self) -> &Vec<Uuid> {
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

        {
            let mut connections = self.client_connections.write().await;
            connections.push(Arc::clone(&connection));
        }

        OmegaConnection::client_changed(
            self.get_iota_id().await,
            connection.get_user_id().await.unwrap_or(Uuid::nil()),
            UserStatus::online,
        )
        .await;
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

            connections.push(Arc::clone(&connection));
        }

        // Notify OmegaConnection
        OmegaConnection::client_changed(
            self.get_iota_id().await,
            connection.get_user_id().await.unwrap_or(Uuid::nil()),
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
