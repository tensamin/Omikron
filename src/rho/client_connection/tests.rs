use super::{
    authenticated_peer_control_request, is_client_omega_operation, merge_initial_presence_snapshot,
};
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};

#[tokio::test]
async fn local_cleanup_outlives_notification_budget_without_omega() {
    use crate::{
        provisioning::session::{ProvisioningMethod, ProvisioningParticipant, ProvisioningRole},
        rho::{
            connection::{GeneralConnection, admission_engine},
            iota_connection::IotaConnection,
            rho_connection::RhoConnection,
            test_support,
        },
    };
    use std::{sync::Arc, time::Duration};

    let mut state = test_support::state();
    Arc::get_mut(&mut state).unwrap().config.cleanup_timeout = Duration::from_millis(10);
    assert!(!state.omega.is_ready().await);
    let (host, peer, transport) = test_support::guest("anonymous").await;
    let general = GeneralConnection::admit(transport, state.clone(), &admission_engine()).unwrap();
    *general.session_id.write().await = 42;
    let rho = Arc::new(
        RhoConnection::new(
            IotaConnection::from_general(general.clone(), 2).await,
            vec![7],
        )
        .await,
    );
    state.rho.add(rho.clone()).await;
    *general.rho_connection.write().await = Some(rho.clone());
    let client = super::ClientConnection::from_general(general, 7).await;
    rho.add_client_connection(client.clone()).await;
    state
        .provisioning
        .create(
            ProvisioningMethod::QrOwnerCreated,
            ProvisioningParticipant {
                id: client.session_id,
                role: ProvisioningRole::Owner,
                temporary_public_key: mtp::crypto::Keyring::generate().public_key_bundle(),
                sender: Arc::downgrade(&client.sender),
            },
        )
        .unwrap();

    let mutation = state.rho.mutation_guard().await;
    let cleanup = tokio::spawn(client.clone().handle_close());
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!cleanup.is_finished());
    assert!(state.provisioning.for_participant(42).is_ok());
    drop(mutation);
    tokio::time::timeout(Duration::from_secs(2), cleanup)
        .await
        .unwrap()
        .unwrap();
    assert!(rho.get_client_connection(7, 42).await.is_none());
    assert!(state.provisioning.for_participant(42).is_err());
    // Disconnecting a device must preserve its account's Iota assignment.
    assert!(state.rho.get_for_user(7).await.is_some());
    peer.sender.close().await;
    host.shutdown().await;
}

#[tokio::test]
async fn disconnected_client_bounds_drain_and_preserves_pending_mutations() {
    use crate::rho::{
        connection::{GeneralConnection, admission_engine},
        test_support,
    };
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };
    for finish_during_drain in [false, true] {
        let state = test_support::state();
        let (host, peer, accepted) = test_support::guest("anonymous").await;
        let general =
            GeneralConnection::admit(accepted, state.clone(), &admission_engine()).unwrap();
        let connection = super::ClientConnection::from_general(general.clone(), 7).await;
        let writes = Arc::new(AtomicUsize::new(0));
        let (started, ready) = tokio::sync::oneshot::channel();
        let (finish, blocked) = tokio::sync::oneshot::channel();
        let (alive, mut cancelled) = tokio::sync::oneshot::channel::<()>();
        let (completed, completion) = tokio::sync::oneshot::channel();
        connection
            .tasks
            .spawn({
                let writes = writes.clone();
                async move {
                    let _alive = alive;
                    started.send(()).unwrap();
                    let _ = blocked.await;
                    writes.fetch_add(1, Ordering::SeqCst);
                    completed.send(()).unwrap();
                }
            })
            .unwrap();
        let global = state
            .rho_connection_limits
            .all
            .clone()
            .try_acquire_owned()
            .unwrap();
        let guest = state
            .rho_connection_limits
            .anonymous
            .clone()
            .try_acquire_owned()
            .unwrap();
        let handlers = connection.tasks.clone();
        let task = tokio::spawn(async move {
            let _permits = (global, guest);
            connection.run().await;
        });
        ready.await.unwrap();
        peer.sender.close().await;
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(!task.is_finished());
        assert_eq!(state.rho_connection_limits.all.available_permits(), 1);
        assert_eq!(state.rho_connection_limits.anonymous.available_permits(), 0);
        let pending_mutation = if finish_during_drain {
            finish.send(()).unwrap();
            None
        } else {
            handlers.drain_expired.notified().await;
            Some(finish)
        };
        tokio::time::timeout(Duration::from_secs(4), task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(state.rho_connection_limits.all.available_permits(), 2);
        assert_eq!(state.rho_connection_limits.anonymous.available_permits(), 1);
        if let Some(finish) = pending_mutation {
            assert!(matches!(
                cancelled.try_recv(),
                Err(tokio::sync::oneshot::error::TryRecvError::Empty)
            ));
            assert_eq!(writes.load(Ordering::SeqCst), 0);
            finish.send(()).unwrap();
        }
        tokio::time::timeout(Duration::from_secs(4), completion)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(writes.load(Ordering::SeqCst), 1);
        host.shutdown().await;
    }
}

#[test]
fn peer_control_requests_replace_a_client_supplied_sender() {
    let request = CommunicationValue::new(CommunicationType::SyncedSettingSet)
        .with_sender(99)
        .add_typed_default(DataType::UserId, DataValue::SignedNumber(99));

    let authenticated = authenticated_peer_control_request(&request, 7);

    assert_eq!(authenticated.sender(), Some(7));
    assert_eq!(
        authenticated
            .get_data(DataType::UserId)
            .and_then(|value| value.as_number()),
        Some(99)
    );
}

#[test]
fn normal_clients_cannot_manage_invitations() {
    for operation in [
        CommunicationType::CreateUserInvitation,
        CommunicationType::ListUserInvitations,
        CommunicationType::RevokeUserInvitation,
    ] {
        assert!(!is_client_omega_operation(&CommunicationValue::new(
            operation
        )));
    }
}

#[test]
fn initial_state_composition_preserves_iota_state_and_marks_missing_presence_incomplete() {
    let iota_state = CommunicationValue::new(CommunicationType::AccountStateSnapshot)
        .add_typed_default(DataType::VersionNumber, DataValue::SignedNumber(12));
    let presence = CommunicationValue::new(CommunicationType::GetStates)
        .add_typed_default(
            DataType::UserStates,
            DataValue::Array(vec![DataValue::Str("online".into())]),
        )
        .add_typed_default(
            DataType::MissingUserIds,
            DataValue::Array(vec![DataValue::SignedNumber(44)]),
        );

    let result = merge_initial_presence_snapshot(iota_state, presence);

    assert!(result.is_type(CommunicationType::AccountStateSnapshot));
    assert_eq!(
        result
            .get_data(DataType::VersionNumber)
            .and_then(DataValue::as_number),
        Some(12)
    );
    assert!(matches!(
        result.get_data(DataType::UserStates),
        Some(DataValue::Array(states)) if states.len() == 1
    ));
    assert_eq!(
        result.get_data(DataType::PresenceSnapshotComplete),
        Some(&DataValue::Bool(false))
    );
}
