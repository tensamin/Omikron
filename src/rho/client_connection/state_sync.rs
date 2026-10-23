use super::*;

pub(super) fn merge_initial_presence_snapshot(
    response: CommunicationValue,
    snapshot: CommunicationValue,
) -> CommunicationValue {
    let user_states = snapshot
        .get_data(DataType::UserStates)
        .cloned()
        .unwrap_or(DataValue::Array(Vec::new()));
    let missing_user_ids = snapshot
        .get_data(DataType::MissingUserIds)
        .cloned()
        .unwrap_or(DataValue::Array(Vec::new()));
    let complete = matches!(&missing_user_ids, DataValue::Array(ids) if ids.is_empty());

    response
        .add_typed_default(DataType::UserStates, user_states)
        .add_typed_default(DataType::MissingUserIds, missing_user_ids)
        .add_typed_default(
            DataType::PresenceSnapshotComplete,
            DataValue::Bool(complete),
        )
}

impl ClientConnection {
    /// Produces the one client-facing initial state response.  The Iota
    /// response is an internal input: presence is subscribed and fetched
    /// before this value is sent to the client.
    pub(super) async fn compose_initial_client_state(
        &self,
        iota: Arc<crate::rho::iota_connection::IotaConnection>,
        response: CommunicationValue,
    ) -> Result<CommunicationValue, InitialPresenceError> {
        let response = iota.augment_client_state_sync(response).await;
        let Some((response_user_id, _, contacts)) =
            crate::rho::iota_connection::contact_snapshot(&response)
        else {
            return Err(InitialPresenceError::InvalidSnapshot(
                "ClientStateSync is missing a valid contact snapshot".into(),
            ));
        };
        if response_user_id != self.user_id as i64 {
            return Err(InitialPresenceError::InvalidSnapshot(
                "ClientStateSync does not belong to the authenticated session".into(),
            ));
        }

        match self
            .state
            .omega
            .initial_presence_snapshot(
                self.user_id as i64,
                self.session_id as i64,
                contacts.clone(),
            )
            .await
        {
            Ok(snapshot) => Ok(merge_initial_presence_snapshot(response, snapshot)),
            Err(error) => {
                self.state
                    .omega
                    .abort_initial_presence_sync(self.user_id as i64, self.session_id as i64);
                if matches!(
                    error,
                    InitialPresenceError::OrderingLost
                        | InitialPresenceError::AlreadyInProgress
                        | InitialPresenceError::InvalidSnapshot(_)
                        | InitialPresenceError::SubscriptionRejected(_)
                ) {
                    Err(error)
                } else {
                    // Omega can be unavailable without withholding the Iota
                    // state.  The response explicitly describes that its
                    // presence section is incomplete.
                    Ok(response
                        .add_typed_default(DataType::UserStates, DataValue::Array(Vec::new()))
                        .add_typed_default(
                            DataType::MissingUserIds,
                            DataValue::Array(
                                contacts
                                    .into_iter()
                                    .map(|id| DataValue::SignedNumber(id.into()))
                                    .collect(),
                            ),
                        )
                        .add_typed_default(
                            DataType::PresenceSnapshotComplete,
                            DataValue::Bool(false),
                        ))
                }
            }
        }
    }

    /// Routes all post-initial-state messages behind the ClientStateAck barrier.
    /// The state response itself deliberately uses `send_message` directly.
    pub async fn send_or_buffer_post_initial_state(
        self: Arc<Self>,
        value: CommunicationValue,
    ) -> Result<(), ()> {
        let mut state = self.client_state_sync.lock().await;
        if matches!(state.phase, ClientStateSyncPhase::Idle) {
            drop(state);
            self.send_message(&value).await;
            return Ok(());
        }
        if state.overflowed || state.buffered_events.len() >= MAX_CLIENT_STATE_SYNC_BUFFERED_EVENTS
        {
            state.overflowed = true;
            return Err(());
        }
        state.buffered_events.push_back(value);
        Ok(())
    }

    pub(super) async fn reset_client_state_sync(&self) {
        let mut state = self.client_state_sync.lock().await;
        *state = ClientStateSyncState::default();
    }

    /// Rolls back an ACK attempt that did not receive a successful response
    /// from Iota. Iota cannot have committed the acknowledgement in these
    /// paths, so the client may safely retry it.
    pub(super) async fn restore_client_state_ack(&self) {
        let mut state = self.client_state_sync.lock().await;
        let ClientStateSyncPhase::Committing { device_id, version } = &state.phase else {
            return;
        };
        state.phase = ClientStateSyncPhase::AwaitingAck {
            device_id: device_id.clone(),
            version: *version,
        };
    }

    pub(super) async fn drain_buffered_live_events(self: Arc<Self>) {
        loop {
            let next = {
                let mut state = self.client_state_sync.lock().await;
                match state.buffered_events.pop_front() {
                    Some(event) => Some(event),
                    None => {
                        state.phase = ClientStateSyncPhase::Idle;
                        state.overflowed = false;
                        None
                    }
                }
            };
            let Some(event) = next else {
                return;
            };
            self.clone().send_message(&event).await;
        }
    }
}
