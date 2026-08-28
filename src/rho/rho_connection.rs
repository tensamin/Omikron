use super::{client_connection::ClientConnection, iota_connection::IotaConnection};

use super::relay_router::RouteTarget;
use crate::{
    log_err,
    rho::{app_connection::AppConnection, connection::OptionalDataValueCompat},
};
use dashmap::DashMap;
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

pub struct RhoConnection {
    iota_connection: Arc<IotaConnection>,
    user_ids: Arc<RwLock<Vec<i64>>>,
    client_connections: DashMap<(u64, u64), Arc<ClientConnection>>,
    app_connections: DashMap<(u64, String, Uuid), Arc<AppConnection>>,
}

impl RhoConnection {
    /// Create a new RhoConnection
    pub async fn new(iota_connection: Arc<IotaConnection>, user_ids: Vec<i64>) -> Self {
        let rho_connection = Self {
            iota_connection,
            user_ids: Arc::new(RwLock::new(user_ids.clone())),
            client_connections: DashMap::new(),
            app_connections: DashMap::new(),
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
        self.client_connections
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    pub fn drain_client_connections(&self) -> Vec<Arc<ClientConnection>> {
        let keys: Vec<_> = self
            .client_connections
            .iter()
            .map(|entry| *entry.key())
            .collect();
        keys.into_iter()
            .filter_map(|key| self.client_connections.remove(&key).map(|(_, value)| value))
            .collect()
    }

    /// Get client connections for a specific user
    pub async fn get_client_connections_for_user(
        &self,
        user_id: i64,
    ) -> Vec<Arc<ClientConnection>> {
        self.client_connections
            .iter()
            .filter(|entry| entry.key().0 == user_id as u64)
            .map(|entry| entry.value().clone())
            .collect()
    }

    pub async fn detach_user_clients(&self, user_id: i64) {
        let clients = self.get_client_connections_for_user(user_id).await;
        for client in clients {
            client.clear_rho_connection().await;
        }
        self.client_connections
            .retain(|(id, _), _| *id != user_id as u64);
    }

    #[allow(unused)]
    pub async fn get_app_connections(
        &self,
        userid: Option<i64>,
        app_identifier: Option<String>,
        app_session: Option<Uuid>,
    ) -> Vec<Arc<AppConnection>> {
        self.app_connections
            .iter()
            .filter(|entry| {
                let conn = entry.value();
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
            .map(|entry| entry.value().clone())
            .collect()
    }

    pub async fn add_app_connection(&self, connection: Arc<AppConnection>) {
        let key = (
            connection.user_id,
            connection.app_identifier.clone(),
            connection.app_session,
        );
        self.app_connections.insert(key, connection);
    }

    pub async fn close_app_connection(&self, connection: Arc<AppConnection>) {
        self.app_connections
            .retain(|_, c| c.app_session != connection.app_session);
    }

    /// Add a client connection
    #[allow(dead_code)]
    pub async fn add_client_connection(&self, connection: Arc<ClientConnection>) {
        let user_id = connection.user_id as i64;
        let session_id = connection.session_id as i64;

        if let Some((_, old_connection)) = self
            .client_connections
            .remove(&(user_id as u64, session_id as u64))
        {
            // A reconnect for a persistent device replaces the old transport;
            // do this before publishing the new route.
            old_connection.close().await;
        }
        self.client_connections
            .insert((user_id as u64, session_id as u64), Arc::clone(&connection));
    }

    pub async fn get_client_connection(
        &self,
        user_id: i64,
        session_id: i64,
    ) -> Option<Arc<ClientConnection>> {
        if user_id < 0 || session_id <= 0 {
            return None;
        }
        self.client_connections
            .get(&(user_id as u64, session_id as u64))
            .map(|entry| entry.value().clone())
    }

    /// Remove a client connection
    pub async fn close_client_connection(&self, connection: Arc<ClientConnection>) {
        let target_user_id = connection.user_id as i64;
        let target_session_id = connection.session_id as i64;
        // Do not let a stale transport tear down the replacement for the same
        // persistent session.
        let key = (target_user_id as u64, target_session_id as u64);
        if self
            .client_connections
            .get(&key)
            .is_some_and(|current| !Arc::ptr_eq(current.value(), &connection))
        {
            return;
        }
        self.client_connections.remove(&key);
        if let Err(error) = self
            .iota_connection
            .state
            .omega
            .client_disconnected(target_user_id, target_session_id)
            .await
        {
            log_err!(
                target_user_id,
                crate::util::logger::PrintType::Client,
                "UserDisconnected acknowledgement failed for session {}: {}",
                target_session_id,
                error
            );
        }
        let remaining_for_user = self
            .client_connections
            .iter()
            .any(|entry| entry.key().0 == target_user_id as u64);

        if !remaining_for_user {
            self.iota_connection
                .state
                .rho
                .remove_user_binding(target_user_id, self.get_iota_id().await as i64)
                .await;
        }
    }

    /// Close the Iota connection and all associated client connections
    pub async fn close_iota_connection(&self) {
        let iota_id = self.get_iota_id().await as i64;
        if self
            .iota_connection
            .state
            .rho
            .remove_if_current(iota_id, self)
            .await
            .is_none()
        {
            return;
        }

        // Close all client connections
        let connections = self.get_client_connections().await;
        for connection in connections {
            connection.close().await;
        }

        // Notify OmegaConnection
        if let Err(error) = self.iota_connection.state.omega.close_iota(iota_id).await {
            log_err!(
                iota_id,
                crate::util::logger::PrintType::Iota,
                "IotaDisconnected acknowledgement failed: {}",
                error
            );
        }
    }

    /// Send message from Iota to specific client
    pub async fn message_to_client(&self, cv: CommunicationValue) {
        let connections = self.get_client_connections().await;
        let Some(receiver_id) = cv.receiver() else {
            log_err!(
                0,
                crate::util::logger::PrintType::General,
                "Discarded message without an MTP receiver"
            );
            return;
        };
        let session_id = cv.get_data(DataType::SessionId).as_number();

        for connection in connections.iter() {
            if connection.user_id != receiver_id {
                continue;
            }
            if let Some(session_id) = session_id {
                if connection.session_id as i128 != session_id {
                    continue;
                }
            }
            connection.clone().send_message(&cv).await;
        }
    }

    #[allow(dead_code)]
    pub async fn message_to_iota(&self, cv: CommunicationValue) {
        self.iota_connection.send_message(&cv).await;
    }

    pub async fn has_local_client(&self, user_id: u64) -> bool {
        self.client_connections
            .iter()
            .any(|entry| entry.key().0 == user_id)
    }

    pub async fn send_relay_to_client(&self, cv: &CommunicationValue) -> Result<(), String> {
        let receiver_id = cv
            .receiver()
            .and_then(RouteTarget::from_wire_id)
            .and_then(|target| match target {
                RouteTarget::User(user_id) => Some(user_id),
                RouteTarget::Iota(_) => None,
            })
            .ok_or_else(|| "client offline".to_string())?;
        let connections = self
            .get_client_connections_for_user(receiver_id as i64)
            .await;
        if connections.is_empty() {
            return Err("client offline".to_string());
        }

        let mut send_error = None;
        for connection in connections {
            if let Err(error) = connection.send_relay(cv).await {
                send_error = Some(error);
            }
        }
        send_error.map_or(Ok(()), Err)
    }

    #[allow(dead_code)]
    pub async fn send_relay_to_iota(&self, cv: &CommunicationValue) -> Result<(), String> {
        self.iota_connection.send_relay(cv).await
    }

    pub async fn await_relay_to_iota(
        &self,
        cv: &CommunicationValue,
    ) -> Result<CommunicationValue, String> {
        self.iota_connection
            .clone()
            .await_response(cv, Some(std::time::Duration::from_secs(20)))
            .await
    }

    pub async fn await_peer_control(
        &self,
        cv: &CommunicationValue,
    ) -> Result<CommunicationValue, String> {
        self.iota_connection
            .clone()
            .await_response(cv, Some(std::time::Duration::from_secs(20)))
            .await
    }

    pub async fn forward_relay_ack(&self, user_id: u64, frame_id: u32) {
        let acknowledgement = CommunicationValue::new(CommunicationType::Success)
            .with_id(frame_id)
            .add_typed_default(DataType::UserId, DataValue::UnsignedNumber(user_id.into()));
        self.iota_connection.send_message(&acknowledgement).await;
    }

    /// Check if this RhoConnection contains a specific user ID
    #[allow(dead_code)]
    pub async fn contains_user(&self, user_id: &i64) -> bool {
        self.user_ids.read().await.contains(user_id)
    }

    /// Get count of active client connections
    #[allow(dead_code)]
    pub async fn client_count(&self) -> usize {
        self.client_connections.len()
    }
}
