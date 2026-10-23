use super::*;

pub(super) fn client_changed_target(value: &CommunicationValue) -> Option<(i64, i64)> {
    if !value.is_type(CommunicationType::ClientChanged) {
        return None;
    }
    let receiver = i64::try_from(value.receiver()?).ok().filter(|id| *id > 0)?;
    let session_id = value
        .get_data(DataType::SessionId)
        .as_signed_number()
        .and_then(|id| i64::try_from(id).ok())
        .filter(|id| *id > 0)?;
    value
        .get_data(DataType::UserId)
        .as_signed_number()
        .and_then(|id| i64::try_from(id).ok())
        .filter(|id| *id > 0)?;
    value.get_data(DataType::UserState).as_str()?;
    Some((receiver, session_id))
}

pub(super) fn signed_positive_iota_id(value: &CommunicationValue) -> Option<i64> {
    value
        .get_data(DataType::IotaId)
        .as_signed_number()
        .and_then(|id| i64::try_from(id).ok())
        .filter(|id| *id > 0)
}

pub(super) fn deleted_user_id(value: &CommunicationValue) -> Option<i64> {
    value
        .is_type(CommunicationType::DeleteUser)
        .then(|| value.get_data(DataType::UserId).as_signed_number())
        .flatten()
        .and_then(|id| i64::try_from(id).ok())
        .filter(|id| *id > 0)
}

pub(super) fn iota_user_snapshot(value: &CommunicationValue) -> Option<(i64, Vec<i64>)> {
    if !value.is_type(CommunicationType::IotaUserData) {
        return None;
    }
    iota_snapshot_data(value)
}

pub(super) fn iota_activation_snapshot(value: &CommunicationValue) -> Option<(i64, Vec<i64>)> {
    if !value.is_type(CommunicationType::Success) {
        return None;
    }
    iota_snapshot_data(value)
}

pub(super) fn iota_snapshot_data(value: &CommunicationValue) -> Option<(i64, Vec<i64>)> {
    let iota_id = value
        .get_data(DataType::IotaId)
        .as_signed_number()
        .and_then(|id| i64::try_from(id).ok())
        .filter(|id| *id > 0)?;
    let Some(DataValue::Array(values)) = value.get_data(DataType::UserIds) else {
        return None;
    };
    let mut user_ids = Vec::with_capacity(values.len());
    for value in values {
        let DataValue::SignedNumber(user_id) = value else {
            return None;
        };
        let user_id = i64::try_from(*user_id)
            .ok()
            .filter(|user_id| *user_id > 0)?;
        user_ids.push(user_id);
    }
    user_ids.sort_unstable();
    user_ids.dedup();
    Some((iota_id, user_ids))
}

impl OmegaConnection {
    pub(super) async fn apply_route_update(self: &Arc<Self>, value: &CommunicationValue) -> bool {
        let user = deleted_user_id(value);
        let iota = value
            .is_type(CommunicationType::DeleteIota)
            .then(|| signed_positive_iota_id(value))
            .flatten();
        let membership = iota_user_snapshot(value);
        if user.is_none() && iota.is_none() && membership.is_none() {
            return false;
        }
        if self.draining.load(std::sync::atomic::Ordering::Acquire) {
            return true;
        }
        // Authority mutations survive cancellation of the transport read loop.
        let omega = self.clone();
        let mut tasks = tokio::task::JoinSet::new();
        tasks.spawn(async move {
            if let Some(user_id) = user {
                omega.rho.invalidate_user(user_id).await;
                omega.invalidate_authenticated_key(AuthIdentity {
                    kind: AuthIdentityKind::Client,
                    id: user_id as u64,
                });
            } else if let Some(iota_id) = iota {
                if let Some(rho) = omega.rho.get_by_iota(iota_id).await {
                    rho.close_deleted_iota_connection().await;
                }
                omega.invalidate_authenticated_key(AuthIdentity {
                    kind: AuthIdentityKind::Iota,
                    id: iota_id as u64,
                });
            } else if let Some((iota_id, users)) = membership {
                omega.rho.replace_users_for_iota(iota_id, users).await;
            }
        });
        let _ = crate::rho::tasks::supervise(tasks).await;
        true
    }

    #[allow(dead_code)]
    pub async fn close_iota(&self, iota_id: i64) -> Result<(), String> {
        let cv = CommunicationValue::new(CommunicationType::IotaDisconnected)
            .add_typed_default(DataType::IotaId, DataValue::SignedNumber(iota_id.into()));
        let request_id = cv.require_id().map_err(|error| error.to_string())?;
        let result = self.lifecycle_request(&cv).await;
        if let Err(error) = &result {
            self.log_lifecycle_failure("IotaDisconnected", iota_id, None, request_id, error);
            self.sync_client_iota_status().await;
        }
        result
    }

    pub(crate) fn invalidate_client_presence(&self, user_id: i64, session_id: i64) {
        self.session_presence.remove(&(user_id, session_id));
        self.presence_delivery_locks.remove(&(user_id, session_id));
        self.initial_presence_barriers
            .remove(&(user_id, session_id));
    }

    pub async fn client_disconnected(&self, user_id: i64, session_id: i64) -> Result<(), String> {
        let cv = CommunicationValue::new(CommunicationType::UserDisconnected)
            .add_typed_default(DataType::UserId, DataValue::SignedNumber(user_id.into()))
            .add_typed_default(
                DataType::SessionId,
                DataValue::SignedNumber(session_id.into()),
            );
        let request_id = cv.require_id().map_err(|error| error.to_string())?;
        let result = self.lifecycle_request(&cv).await;
        if let Err(error) = &result {
            self.log_lifecycle_failure(
                "UserDisconnected",
                user_id,
                Some(session_id),
                request_id,
                error,
            );
            self.sync_client_iota_status().await;
        }
        result
    }

    pub async fn user_connected(
        &self,
        user_id: i64,
        session_id: i64,
        iota_id: i64,
    ) -> Result<(), String> {
        let request = CommunicationValue::new(CommunicationType::UserConnected)
            .add_typed_default(DataType::UserId, DataValue::SignedNumber(user_id.into()))
            .add_typed_default(
                DataType::SessionId,
                DataValue::SignedNumber(session_id.into()),
            )
            .add_typed_default(DataType::IotaId, DataValue::SignedNumber(iota_id.into()))
            .add_typed_default(
                DataType::UserState,
                DataValue::Str("user_online".to_string()),
            )
            .add_typed_default(
                DataType::UpdatedAt,
                DataValue::SignedNumber(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as i128,
                ),
            );
        let request_id = request.require_id().map_err(|error| error.to_string())?;
        let result = self.lifecycle_request(&request).await;
        if let Err(error) = &result {
            self.log_lifecycle_failure(
                "UserConnected",
                user_id,
                Some(session_id),
                request_id,
                error,
            );
            self.sync_client_iota_status().await;
        }
        result
    }

    pub async fn iota_connected(&self, iota_id: i64) -> Result<Vec<i64>, String> {
        let request = CommunicationValue::new(CommunicationType::IotaConnected)
            .add_typed_default(DataType::IotaId, DataValue::SignedNumber(iota_id.into()));
        let request_id = request.require_id().map_err(|error| error.to_string())?;
        if !self.is_ready().await {
            return Err("Omega is not synchronized".to_string());
        }
        let result = self
            .await_response(&request, Some(Duration::from_secs(20)))
            .await
            .and_then(|response| {
                iota_activation_snapshot(&response)
                    .filter(|(response_iota_id, _)| *response_iota_id == iota_id)
                    .map(|(_, user_ids)| user_ids)
                    .ok_or_else(|| format!("Omega rejected {}", response.get_type()))
            });
        if let Err(error) = &result {
            self.log_lifecycle_failure("IotaConnected", iota_id, None, request_id, error);
            self.sync_client_iota_status().await;
        }
        result
    }

    #[allow(dead_code)]
    pub async fn reconcile_routes(&self) {
        self.sync_client_iota_status().await;
    }

    pub(super) async fn lifecycle_request(
        &self,
        request: &CommunicationValue,
    ) -> Result<(), String> {
        if !self.is_ready().await {
            return Err("Omega is not synchronized".to_string());
        }
        if !self.peer_capabilities.read().await.session_snapshot_v1 {
            // Legacy Omega handles lifecycle messages as notifications and
            // never returns Success. A transport-level send result is the
            // only acknowledgement available under that contract.
            return self.send_message_result(request).await;
        }
        let response = self
            .await_response(request, Some(Duration::from_secs(20)))
            .await?;
        if response.is_type(CommunicationType::Success) {
            Ok(())
        } else {
            Err(format!("Omega rejected {}", response.get_type()))
        }
    }

    pub(super) fn log_lifecycle_failure(
        &self,
        operation: &str,
        entity_id: i64,
        session_id: Option<i64>,
        request_id: u32,
        error: &str,
    ) {
        log_err!(
            0,
            PrintType::Omega,
            "Lifecycle operation={} entity_id={} session_id={:?} request_id={} failed: {}",
            operation,
            entity_id,
            session_id,
            request_id,
            error
        );
    }
}
