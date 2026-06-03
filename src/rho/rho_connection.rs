use super::{client_connection::ClientConnection, iota_connection::IotaConnection, rho_manager};

use crate::omega::omega_connection::OmegaConnection;
use crate::{data::user::UserStatus, rho::app_connection::AppConnection};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use ttp_core::{CommunicationType, CommunicationValue, DataTypes, DataValue};
use uuid::Uuid;

pub struct RhoConnection {
    iota_connection: Arc<IotaConnection>,
    user_ids: Arc<RwLock<Vec<i64>>>,
    client_connections: Arc<RwLock<Vec<Arc<ClientConnection>>>>,
    app_connections: Arc<RwLock<Vec<Arc<AppConnection>>>>,
}

impl RhoConnection {
    /// Create a new RhoConnection
    pub async fn new(iota_connection: Arc<IotaConnection>, user_ids: Vec<i64>) -> Self {
        let rho_connection = Self {
            iota_connection,
            user_ids: Arc::new(RwLock::new(user_ids.clone())),
            client_connections: Arc::new(RwLock::new(Vec::new())),
            app_connections: Arc::new(RwLock::new(Vec::new())),
        };

        rho_connection
    }

    pub async fn get_iota_id(&self) -> u64 {
        self.iota_connection.iota_id
    }

    pub async fn get_user_ids(&self) -> Vec<i64> {
        self.user_ids.read().await.clone()
    }

    pub async fn set_user_ids(&self, user_ids: Vec<i64>) {
        let mut guard = self.user_ids.write().await;
        *guard = user_ids;
    }

    pub async fn add_user_id(&self, user_id: i64) {
        let mut guard = self.user_ids.write().await;
        if !guard.contains(&user_id) {
            guard.push(user_id);
        }
    }

    pub async fn bind_user_id(&self, user_id: i64) {
        self.add_user_id(user_id).await;
        self.iota_connection.add_user_id(user_id as u64).await;
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
            if con.get_user_id().await == user_id as u64 {
                collections.push(con.clone());
            }
        }
        collections
    }

    #[allow(unused)]
    pub async fn get_app_connections(
        &self,
        userid: Option<i64>,
        app_identifier: Option<String>,
        app_session: Option<Uuid>,
    ) -> Vec<Arc<AppConnection>> {
        let connections = self.app_connections.read().await;
        connections
            .iter()
            .filter(|conn| {
                if let Some(uid) = userid {
                    if conn.user_id != uid as u64 {
                        return false;
                    }
                }
                if let Some(ref identifier) = app_identifier {
                    if conn.app_identifier != *identifier {
                        return false;
                    }
                }
                if let Some(ref session) = app_session {
                    if conn.app_session != *session {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect()
    }

    pub async fn add_app_connection(&self, connection: Arc<AppConnection>) {
        let mut connections = self.app_connections.write().await;
        connections.push(connection);
    }

    pub async fn close_app_connection(&self, connection: Arc<AppConnection>) {
        let mut connections = self.app_connections.write().await;
        connections.retain(|c| c.app_session != connection.app_session);
    }

    /// Add a client connection
    #[allow(dead_code)]
    pub async fn add_client_connection(&self, connection: Arc<ClientConnection>) {
        let user_id = connection.user_id as i64;
        let session_id = connection.session_id as i64;

        let notification = CommunicationValue::new(CommunicationType::client_connected)
            .add_data(DataTypes::user_id, DataValue::Number(user_id));

        self.iota_connection.send_message(&notification).await;

        let mut should_notify_online = false;
        {
            let mut connections = self.client_connections.write().await;
            let mut keep = Vec::new();
            let mut had_user = false;

            for con in connections.drain(..) {
                if con.user_id as i64 == user_id {
                    had_user = true;
                    if con.session_id as i64 == session_id {
                        continue;
                    }
                }
                keep.push(con);
            }

            if !had_user {
                should_notify_online = true;
            }

            keep.push(Arc::clone(&connection));
            *connections = keep;
        }

        if should_notify_online {
            OmegaConnection::client_changed(
                self.get_iota_id().await as i64,
                user_id,
                UserStatus::user_online,
            )
            .await;
        }
    }

    /// Remove a client connection
    pub async fn close_client_connection(&self, connection: Arc<ClientConnection>) {
        let target_user_id = connection.user_id as i64;
        let target_session_id = connection.session_id as i64;
        let mut remaining_for_user = false;

        {
            let mut connections = self.client_connections.write().await;
            let mut keep = Vec::new();
            for con in connections.drain(..) {
                if con.user_id as i64 == target_user_id
                    && con.session_id as i64 == target_session_id
                {
                    continue;
                }
                if con.user_id as i64 == target_user_id {
                    remaining_for_user = true;
                }
                keep.push(con);
            }
            *connections = keep;
        }

        if !remaining_for_user {
            OmegaConnection::client_changed(
                self.get_iota_id().await as i64,
                target_user_id,
                UserStatus::user_offline,
            )
            .await;
        }
    }

    /// Close the Iota connection and all associated client connections
    pub async fn close_iota_connection(&self) {
        // Close all client connections
        let connections = self.get_client_connections().await;
        for connection in connections {
            connection.close().await;
        }

        // Remove from manager
        rho_manager::remove_rho(self.get_iota_id().await as i64).await;

        // Notify OmegaConnection
        OmegaConnection::close_iota(self.get_iota_id().await as i64).await;
    }

    /// Send message from Iota to specific client
    pub async fn message_to_client(&self, cv: CommunicationValue) {
        let connections = self.client_connections.read().await;
        let receiver_id = cv.get_receiver();
        let session_id = cv.get_data(DataTypes::session_id).as_number();

        for connection in connections.iter() {
            if connection.user_id != receiver_id {
                continue;
            }
            if let Some(session_id) = session_id {
                if connection.session_id as i64 != session_id {
                    continue;
                }
            }
            connection.clone().send_message(&cv).await;
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
            if conn_user_id == user_id as u64 {
                connection
                    .clone()
                    .set_interested_users(interested_ids.clone())
                    .await;
                break;
            }
        }
    }

    /// Check if clients are interested in a user
    #[allow(dead_code)]
    pub async fn are_they_interested(&self, user_id: i64, user_status: &str) {
        let connections = self.client_connections.read().await;
        for connection in connections.iter() {
            connection
                .clone()
                .are_you_interested(user_id, user_status)
                .await;
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
    #[allow(dead_code)]
    pub async fn contains_user(&self, user_id: &i64) -> bool {
        self.user_ids.read().await.contains(user_id)
    }

    /// Get count of active client connections
    #[allow(dead_code)]
    pub async fn client_count(&self) -> usize {
        let connections = self.client_connections.read().await;
        connections.len()
    }
}
