use super::*;

pub(super) fn normalize_presence_user_ids(mut user_ids: Vec<i64>) -> Result<Vec<i64>, String> {
    if user_ids.iter().any(|id| *id <= 0) {
        return Err("presence subscription contains invalid user id".into());
    }
    user_ids.sort_unstable();
    user_ids.dedup();
    Ok(user_ids)
}

impl OmegaConnection {
    pub async fn replace_state_subscription(
        &self,
        user_id: i64,
        session_id: i64,
        user_ids: Vec<i64>,
    ) -> Result<(), String> {
        if user_id <= 0 || session_id <= 0 {
            return Err("invalid user or session id".to_string());
        }

        let user_ids = normalize_presence_user_ids(user_ids)?;

        let key = (user_id, session_id);
        // Store the latest authoritative snapshot before checking readiness.
        // A client can synchronize while the transport is reconnecting.
        let generation = self.replace_desired_presence_state(key, user_ids.clone());

        if !self.is_ready().await {
            return Err("Omega is not synchronized".to_string());
        }

        self.deliver_state_subscription(key, user_ids, generation)
            .await
            .map_err(|error| error.to_string())
    }

    /// Installs the subscription before retrieving the snapshot so no presence
    /// transition is missed between those operations.  The caller composes the
    /// returned snapshot into its initial state response.
    pub async fn initial_presence_snapshot(
        &self,
        user_id: i64,
        session_id: i64,
        user_ids: Vec<i64>,
    ) -> Result<CommunicationValue, InitialPresenceError> {
        let key = (user_id, session_id);
        let user_ids =
            normalize_presence_user_ids(user_ids).map_err(InitialPresenceError::InvalidSnapshot)?;
        let generation = self.replace_desired_presence_state(key, user_ids.clone());
        if !self.is_ready().await {
            return Err(InitialPresenceError::OmegaUnavailable(
                "Omega is not synchronized".into(),
            ));
        }
        if self.initial_presence_barriers.contains_key(&key) {
            return Err(InitialPresenceError::AlreadyInProgress);
        }
        self.initial_presence_barriers
            .insert(key, Arc::new(Mutex::new(InitialPresenceBarrier::default())));
        let subscription = CommunicationValue::new(CommunicationType::StateSubscribe)
            .with_sender(user_id as u64)
            .add_typed_default(
                DataType::SessionId,
                DataValue::SignedNumber(session_id.into()),
            )
            .add_typed_default(
                DataType::UserIds,
                DataValue::Array(
                    user_ids
                        .iter()
                        .map(|id| DataValue::SignedNumber((*id).into()))
                        .collect(),
                ),
            );
        if self.peer_capabilities.read().await.state_subscribe_v1 {
            let subscribed = self
                .await_response(&subscription, Some(Duration::from_secs(20)))
                .await
                .map_err(InitialPresenceError::OmegaUnavailable)?;
            if !subscribed.is_type(CommunicationType::Success) {
                self.abort_initial_presence_sync(user_id, session_id);
                return Err(InitialPresenceError::SubscriptionRejected(
                    subscribed.get_type().to_string(),
                ));
            }
        }
        let response = self
            .fetch_user_states_snapshot(user_id, session_id, &user_ids)
            .await?;
        if let Some(barrier) = self
            .initial_presence_barriers
            .get(&key)
            .map(|entry| entry.clone())
            && barrier.lock().await.overflowed
        {
            self.abort_initial_presence_sync(user_id, session_id);
            return Err(InitialPresenceError::OrderingLost);
        }
        if !self.is_current_presence_generation(key, generation) {
            self.abort_initial_presence_sync(user_id, session_id);
            return Err(InitialPresenceError::InvalidSnapshot(
                "presence subscription changed while the snapshot was fetched".into(),
            ));
        }
        self.mark_presence_delivered(key, generation).await;
        Ok(response)
    }

    pub(super) fn replace_desired_presence_state(
        &self,
        key: (i64, i64),
        user_ids: Vec<i64>,
    ) -> u64 {
        self.session_presence
            .entry(key)
            .and_modify(|entry| {
                entry.subscribed_user_ids = user_ids.clone();
                entry.pending = true;
                entry.generation = entry.generation.saturating_add(1);
            })
            .or_insert_with(|| SessionPresenceState {
                subscribed_user_ids: user_ids,
                pending: true,
                generation: 1,
            })
            .generation
    }

    pub(super) async fn buffer_initial_presence_event(
        &self,
        key: (i64, i64),
        event: CommunicationValue,
    ) -> PresenceBufferResult {
        let Some(barrier) = self
            .initial_presence_barriers
            .get(&key)
            .map(|entry| entry.clone())
        else {
            return PresenceBufferResult::NotBuffered;
        };
        let mut barrier = barrier.lock().await;
        if barrier.live {
            return PresenceBufferResult::NotBuffered;
        }
        if barrier.overflowed {
            return PresenceBufferResult::OrderingLost;
        }
        if barrier.queued.len() >= MAX_INITIAL_PRESENCE_BUFFERED_EVENTS {
            barrier.overflowed = true;
            return PresenceBufferResult::OrderingLost;
        }
        barrier.queued.push_back(event);
        PresenceBufferResult::Buffered
    }

    pub(super) async fn forward_client_changed(
        &self,
        user_id: i64,
        session_id: i64,
        event: &CommunicationValue,
    ) {
        if let Some(client) = self.rho.get_client_connection(user_id, session_id).await {
            let _ = client
                .send_or_buffer_post_initial_state(event.clone())
                .await;
        }
    }

    pub async fn finish_initial_presence_sync(
        &self,
        user_id: i64,
        session_id: i64,
    ) -> Result<(), InitialPresenceError> {
        let key = (user_id, session_id);
        let Some(barrier) = self
            .initial_presence_barriers
            .get(&key)
            .map(|entry| entry.clone())
        else {
            return Ok(());
        };
        loop {
            let next = {
                let mut state = barrier.lock().await;
                if state.overflowed {
                    drop(state);
                    self.abort_initial_presence_sync(user_id, session_id);
                    return Err(InitialPresenceError::OrderingLost);
                }
                match state.queued.pop_front() {
                    Some(event) => Some(event),
                    None => {
                        state.live = true;
                        None
                    }
                }
            };
            let Some(event) = next else {
                self.initial_presence_barriers.remove(&key);
                return Ok(());
            };
            self.forward_client_changed(user_id, session_id, &event)
                .await;
        }
    }

    pub fn abort_initial_presence_sync(&self, user_id: i64, session_id: i64) {
        self.initial_presence_barriers
            .remove(&(user_id, session_id));
    }

    pub(super) async fn deliver_state_subscription(
        &self,
        key: (i64, i64),
        user_ids: Vec<i64>,
        generation: u64,
    ) -> Result<(), InitialPresenceError> {
        let (user_id, session_id) = key;
        let delivery_lock = self
            .presence_delivery_locks
            .entry(key)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone();
        let _delivery_guard = delivery_lock.lock().await;

        // Replacements can be requested concurrently.  Serializing transport
        // side effects ensures that the current generation is installed last.
        if !self.is_current_presence_generation(key, generation) {
            return Ok(());
        }

        if !self.peer_capabilities.read().await.state_subscribe_v1 {
            let result = self
                .request_user_states(user_id, session_id, user_ids, generation)
                .await;
            if result.is_ok() {
                self.mark_presence_delivered(key, generation).await;
            }
            return result;
        }

        let subscription = CommunicationValue::new(CommunicationType::StateSubscribe)
            .with_sender(user_id as u64)
            .add_typed_default(
                DataType::SessionId,
                DataValue::SignedNumber(session_id.into()),
            )
            .add_typed_default(
                DataType::UserIds,
                DataValue::Array(
                    user_ids
                        .iter()
                        .map(|user_id| DataValue::SignedNumber((*user_id).into()))
                        .collect(),
                ),
            );
        log_out!(
            user_id,
            PrintType::Omega,
            "PresenceSync user={} session={} stage=subscribe",
            user_id,
            session_id
        );
        let response = self
            .await_response(&subscription, Some(Duration::from_secs(20)))
            .await
            .map_err(InitialPresenceError::OmegaUnavailable)?;
        if !response.is_type(CommunicationType::Success) {
            return Err(InitialPresenceError::SubscriptionRejected(format!(
                "StateSubscribe rejected with {}",
                response.get_type()
            )));
        }

        self.request_user_states(user_id, session_id, user_ids, generation)
            .await?;
        self.mark_presence_delivered(key, generation).await;
        Ok(())
    }

    pub(super) async fn restore_presence_subscriptions(&self) -> Result<(), String> {
        let mut active = Vec::new();
        for rho in self.rho.connections().await {
            active.extend(rho.get_client_connections().await);
        }
        let active_keys: std::collections::HashSet<_> = active
            .iter()
            .map(|client| (client.user_id as i64, client.session_id as i64))
            .collect();

        // Do not replay subscriptions for sessions that disappeared while the
        // transport was down.
        self.session_presence
            .retain(|key, _| active_keys.contains(key));

        // A fresh Omega transport has no connection-local subscription state.
        // Every desired subscription must be installed again, even one that was
        // delivered successfully on the previous transport.
        for mut entry in self.session_presence.iter_mut() {
            entry.pending = true;
        }

        loop {
            let pending: Vec<_> = active_keys
                .iter()
                .filter_map(|key| {
                    self.session_presence.get(key).and_then(|entry| {
                        entry
                            .pending
                            .then(|| (*key, entry.subscribed_user_ids.clone(), entry.generation))
                    })
                })
                .collect();
            if pending.is_empty() {
                break;
            }
            for (key, user_ids, generation) in pending {
                self.deliver_state_subscription(key, user_ids, generation)
                    .await
                    .map_err(|error| error.to_string())?;
            }
        }
        Ok(())
    }

    pub(super) async fn mark_presence_delivered(&self, key: (i64, i64), generation: u64) {
        if let Some(mut entry) = self.session_presence.get_mut(&key)
            && entry.generation == generation
        {
            entry.pending = false;
        }
    }

    pub(super) async fn fetch_user_states_snapshot(
        &self,
        user_id: i64,
        session_id: i64,
        user_ids: &[i64],
    ) -> Result<CommunicationValue, InitialPresenceError> {
        let request = CommunicationValue::new(CommunicationType::GetStates)
            .add_typed_default(
                DataType::SessionId,
                DataValue::SignedNumber(session_id.into()),
            )
            .add_typed_default(
                DataType::UserIds,
                DataValue::Array(
                    user_ids
                        .iter()
                        .map(|user_id| DataValue::SignedNumber((*user_id).into()))
                        .collect(),
                ),
            );
        log_out!(
            user_id,
            PrintType::Omega,
            "PresenceSync user={} session={} stage=get_states",
            user_id,
            session_id
        );
        let mut response = self
            .await_response(&request, Some(Duration::from_secs(20)))
            .await
            .map_err(InitialPresenceError::OmegaUnavailable)?;
        if !response.is_type(CommunicationType::GetStates) {
            return Err(InitialPresenceError::InvalidSnapshot(
                "expected GetStates response".into(),
            ));
        }
        let legacy_peer = !self.peer_capabilities.read().await.client_state_push_v1;
        match response.get_data(DataType::SessionId).as_number() {
            Some(id) if id == session_id as i128 => {}
            None if legacy_peer => {
                response = response.add_typed_default(
                    DataType::SessionId,
                    DataValue::SignedNumber(session_id.into()),
                );
            }
            _ => {
                return Err(InitialPresenceError::InvalidSnapshot(
                    "GetStates response had the wrong session".into(),
                ));
            }
        }
        if !matches!(
            response.get_data(DataType::UserStates),
            Some(DataValue::Array(_))
        ) {
            return Err(InitialPresenceError::InvalidSnapshot(
                "GetStates response is missing UserStates".into(),
            ));
        }
        if !matches!(
            response.get_data(DataType::MissingUserIds),
            Some(DataValue::Array(_))
        ) {
            if legacy_peer && response.get_data(DataType::MissingUserIds).is_none() {
                response = response
                    .add_typed_default(DataType::MissingUserIds, DataValue::Array(Vec::new()));
            } else {
                return Err(InitialPresenceError::InvalidSnapshot(
                    "GetStates response is missing or has invalid MissingUserIds".into(),
                ));
            }
        }
        Ok(response)
    }

    pub(super) async fn request_user_states(
        &self,
        user_id: i64,
        session_id: i64,
        user_ids: Vec<i64>,
        generation: u64,
    ) -> Result<(), InitialPresenceError> {
        let response = self
            .fetch_user_states_snapshot(user_id, session_id, &user_ids)
            .await?;

        if self.is_current_presence_generation((user_id, session_id), generation)
            && let Some(client) = self.rho.get_client_connection(user_id, session_id).await
        {
            client
                .send_or_buffer_post_initial_state(response)
                .await
                .map_err(|_| InitialPresenceError::OrderingLost)?;
            log_out!(
                user_id,
                PrintType::Client,
                "PresenceSync user={} session={} stage=get_states_forwarded",
                user_id,
                session_id
            );
        }
        Ok(())
    }

    pub(super) fn is_current_presence_generation(&self, key: (i64, i64), generation: u64) -> bool {
        self.session_presence
            .get(&key)
            .is_some_and(|entry| entry.generation == generation)
    }
}
