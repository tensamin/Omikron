use super::{
    client_connection::{ClientConnection, DeviceClass},
    iota_connection::IotaConnection,
};

use super::relay_router::RouteTarget;
use crate::{log_err, rho::connection::OptionalDataValueCompat};
use dashmap::DashMap;
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, OnceCell, RwLock};

pub struct RhoConnection {
    iota_connection: Arc<IotaConnection>,
    user_ids: Arc<RwLock<Vec<i64>>>,
    client_connections: DashMap<(u64, u64), Arc<ClientConnection>>,
    foreground_queries: Mutex<HashMap<u64, Arc<OnceCell<bool>>>>,
}

fn message_targets_client(cv: &CommunicationValue, user_id: u64, session_id: u64) -> bool {
    if cv.receiver() != Some(user_id) {
        return false;
    }
    let Some(target_session_id) = cv.get_data(DataType::SessionId).as_number() else {
        return true;
    };
    target_session_id == i128::from(session_id)
}

fn must_follow_initial_state(cv: &CommunicationValue) -> bool {
    matches!(
        cv.get_comm_type_enum(),
        Some(
            CommunicationType::MessageLive
                | CommunicationType::MessageState
                | CommunicationType::MessageEditLive
                | CommunicationType::MessageReactionLive
                | CommunicationType::MessageDeleteLive
                | CommunicationType::ClientChanged
                | CommunicationType::SyncedSettingChanged
                | CommunicationType::UserBlobChanged
                | CommunicationType::UserAssetChanged
                | CommunicationType::BlockedUsersChanged
                | CommunicationType::ReceiptPolicyChanged
                | CommunicationType::MessageStoragePolicyChanged
                | CommunicationType::PushNotification
                | CommunicationType::ChatSecretForward
        )
    )
}

fn local_delivery_result(attempted: usize, sent: usize) -> Result<usize, String> {
    if attempted == 0 {
        Err("client offline".to_string())
    } else if sent == 0 {
        Err("all local client sends failed".to_string())
    } else {
        Ok(sent)
    }
}

impl RhoConnection {
    /// Create a new RhoConnection
    pub async fn new(iota_connection: Arc<IotaConnection>, user_ids: Vec<i64>) -> Self {
        Self {
            iota_connection,
            user_ids: Arc::new(RwLock::new(user_ids.clone())),
            client_connections: DashMap::new(),
            foreground_queries: Mutex::new(HashMap::new()),
        }
    }

    pub fn iota_id(&self) -> u64 {
        self.iota_connection.iota_id
    }

    pub async fn get_iota_id(&self) -> u64 {
        self.iota_id()
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

    pub async fn close_user_clients(&self, user_id: i64) {
        let clients = self.get_client_connections_for_user(user_id).await;
        self.client_connections
            .retain(|(id, _), _| *id != user_id as u64);
        for client in clients {
            client.close().await;
        }
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

    pub async fn close_deleted_iota_connection(&self) {
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
        for connection in self.get_client_connections().await {
            connection.close().await;
        }
        self.iota_connection.close().await;
    }

    /// Send message from Iota to specific client
    pub async fn message_to_client(&self, cv: CommunicationValue) {
        let connections = self.get_client_connections().await;
        if cv.receiver().is_none() {
            log_err!(
                0,
                crate::util::logger::PrintType::General,
                "Discarded message without an MTP receiver"
            );
            return;
        }

        let target_connections: Vec<_> = connections
            .iter()
            .filter(|connection| {
                message_targets_client(&cv, connection.user_id, connection.session_id)
            })
            .cloned()
            .collect();
        let mut mobile_sessions = Vec::new();
        let mut desktop_sessions = Vec::new();
        if cv.is_type(CommunicationType::MessageLive) {
            for connection in &connections {
                if connection.user_id != cv.receiver().unwrap_or_default() {
                    continue;
                }
                let activity = connection.session_activity().await;
                if !activity.reported {
                    continue;
                }
                if activity.device_class == DeviceClass::Mobile
                    && target_connections
                        .iter()
                        .any(|target| target.session_id == connection.session_id)
                {
                    mobile_sessions.push(connection.session_id);
                } else if activity.notification_capable
                    && matches!(
                        activity.device_class,
                        DeviceClass::Desktop | DeviceClass::Web
                    )
                {
                    desktop_sessions.push(connection.clone());
                }
            }
        }
        let suppress_mobile = if !mobile_sessions.is_empty() && !desktop_sessions.is_empty() {
            let user_id = cv.receiver().unwrap_or_default();
            let query = {
                let mut queries = self.foreground_queries.lock().await;
                queries
                    .entry(user_id)
                    .or_insert_with(|| Arc::new(OnceCell::new()))
                    .clone()
            };
            let focused = *query
                .get_or_init(|| async {
                    let mut pending = tokio::task::JoinSet::new();
                    for connection in desktop_sessions {
                        pending.spawn(async move { connection.foreground().await });
                    }
                    while let Some(result) = pending.join_next().await {
                        if matches!(result, Ok(true)) {
                            pending.detach_all();
                            return true;
                        }
                    }
                    false
                })
                .await;
            let mut queries = self.foreground_queries.lock().await;
            if queries
                .get(&user_id)
                .is_some_and(|current| Arc::ptr_eq(current, &query))
            {
                queries.remove(&user_id);
            }
            focused
        } else {
            false
        };

        for connection in target_connections {
            let client_cv = if mobile_sessions.contains(&connection.session_id) {
                cv.clone().add_typed_default(
                    DataType::SuppressNotification,
                    DataValue::Bool(suppress_mobile),
                )
            } else {
                cv.clone()
            };
            if must_follow_initial_state(&client_cv) {
                let _ = connection
                    .clone()
                    .send_or_buffer_post_initial_state(client_cv)
                    .await;
            } else {
                connection.clone().send_message(&client_cv).await;
            }
        }
    }

    #[allow(dead_code)]
    pub async fn message_to_iota(&self, cv: CommunicationValue) {
        self.iota_connection.send_message(&cv).await;
    }

    pub async fn send_to_local_user(
        &self,
        user_id: u64,
        cv: &CommunicationValue,
    ) -> Result<usize, String> {
        let connections = self.get_client_connections_for_user(user_id as i64).await;
        let attempted = connections.len();
        let mut sent = 0;
        for connection in connections {
            match connection.send_relay(cv).await {
                Ok(()) => sent += 1,
                Err(error) => log_err!(
                    user_id as i64,
                    crate::util::logger::PrintType::Client,
                    "Relay send failed for session {}: {}",
                    connection.session_id,
                    error
                ),
            }
        }
        local_delivery_result(attempted, sent)
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
        self.send_to_local_user(receiver_id, cv).await.map(|_| ())
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

#[cfg(test)]
mod tests {
    use super::{local_delivery_result, message_targets_client, must_follow_initial_state};
    use mtp::codec::{CommunicationType, CommunicationValue, DataType};

    #[test]
    fn sessionless_setting_change_targets_all_devices_for_one_user() {
        let event =
            CommunicationValue::new(CommunicationType::SyncedSettingChanged).with_receiver(7);

        assert!(message_targets_client(&event, 7, 1));
        assert!(message_targets_client(&event, 7, 2));
        assert!(!message_targets_client(&event, 8, 1));
        assert!(event.get_data(DataType::SessionId).is_none());
    }

    #[test]
    fn one_successful_session_makes_local_delivery_successful() {
        assert_eq!(local_delivery_result(2, 1), Ok(1));
        assert!(local_delivery_result(2, 0).is_err());
        assert!(local_delivery_result(0, 0).is_err());
    }

    #[test]
    fn message_state_is_buffered_with_other_message_mutations() {
        assert!(must_follow_initial_state(&CommunicationValue::new(
            CommunicationType::MessageState
        )));
    }
}
