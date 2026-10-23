#[tokio::test]
async fn iota_registration_retries_reuse_the_same_durable_attempt_for_exact_key() {
    let state = crate::rho::test_support::state();
    let mut requests = state.omega.test_requests();
    let request =
        mtp::codec::CommunicationValue::new(mtp::codec::CommunicationType::CompleteRegisterIota)
            .add_typed_default(
                mtp::codec::DataType::PublicKey,
                mtp::codec::DataValue::Str(
                    mtp::crypto::Keyring::generate()
                        .public_key_bundle()
                        .try_to_base64()
                        .unwrap(),
                ),
            );
    // Retry both an uncertain reply and a recorded reply lost to the caller.
    for (attempt, success) in [false, true, true].into_iter().enumerate() {
        let task = tokio::spawn({
            let omega = state.omega.clone();
            let request = request.clone().with_id(100 + attempt as u32);
            async move {
                omega
                    .await_response(&request, Some(std::time::Duration::from_secs(2)))
                    .await
            }
        });
        let (outbound, response) = requests.recv().await.unwrap();
        assert_eq!(
            outbound.get_data(mtp::codec::DataType::PublicKey),
            request.get_data(mtp::codec::DataType::PublicKey)
        );
        if success {
            response
                .send(Ok(outbound.add_typed_default(
                    mtp::codec::DataType::IotaId,
                    mtp::codec::DataValue::SignedNumber(2),
                )))
                .unwrap();
            assert!(task.await.unwrap().is_ok());
        } else {
            response
                .send(Err("reply lost after get-or-create".into()))
                .unwrap();
            assert!(task.await.unwrap().is_err());
        }
    }
    let db = rusqlite::Connection::open(&state.omega.mutation_journal_path).unwrap();
    let count: usize = db
        .query_row("SELECT count(*) FROM omega_mutations", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1);
    let journal = crate::omega::MutationJournal::open(&state.omega.mutation_journal_path).unwrap();
    assert_eq!(journal.unresolved().unwrap(), 0);
}

#[tokio::test]
async fn total_request_budget_includes_a_full_request_queue() {
    let state = crate::rho::test_support::state();
    let _slots = state
        .omega
        .request_slots
        .acquire_many(super::MAX_CONCURRENT_REQUESTS as u32)
        .await
        .unwrap();
    let request = mtp::codec::CommunicationValue::new(mtp::codec::CommunicationType::GetUserData);
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        state
            .omega
            .await_response(&request, Some(std::time::Duration::from_millis(5))),
    )
    .await
    .unwrap();
    assert!(result.unwrap_err().contains("total request budget"));
}
use super::{
    AuthIdentity, AuthIdentityKind, CachedAuthenticatedKey, ConnectionOutcome, MAX_RECONNECT_DELAY,
    PeerCapabilities, RECONNECT_DELAY, authenticated_key_path, cached_at_is_fresh,
    client_changed_target, iota_activation_snapshot, iota_user_snapshot, omega_transport_policy,
    parse_omega_capability_response, reconnect_base_after_outcome, reconnect_delay_with_jitter,
    signed_positive_iota_id,
};
use crate::config::TransportConfig;
use dashmap::DashMap;
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use mtp::crypto::Keyring;
use std::time::{Duration, SystemTime};

#[test]
fn omega_transport_policy_uses_configured_message_limits() {
    let policy = omega_transport_policy(&TransportConfig {
        max_message_size: 123,
        handshake_max_message_size: 45,
    });

    assert_eq!(policy.max_message_size, 123);
    assert_eq!(policy.handshake_max_message_size, 45);
}

#[tokio::test]
async fn transport_ids_keep_matching_local_request_ids_separate() {
    let waiting_tasks = tau::ResponseCorrelator::new();
    let respond = |sender: tokio::sync::oneshot::Sender<CommunicationValue>| {
        move |response: CommunicationValue| {
            let _ = sender.send(response);
            true
        }
    };
    let (first_tx, first_rx) = tokio::sync::oneshot::channel();
    let first_omega_id = waiting_tasks
        .reserve(respond(first_tx))
        .expect("first correlation id");
    let (second_tx, second_rx) = tokio::sync::oneshot::channel();
    let second_omega_id = waiting_tasks
        .reserve(respond(second_tx))
        .expect("second correlation id");

    assert_ne!(first_omega_id.id(), second_omega_id.id());
    assert_ne!(first_omega_id.id(), 0);
    assert!(waiting_tasks.complete(
        second_omega_id.id(),
        CommunicationValue::new(CommunicationType::Success),
    ));
    assert!(waiting_tasks.complete(
        first_omega_id.id(),
        CommunicationValue::new(CommunicationType::ErrorInternal),
    ));
    assert!(!waiting_tasks.complete(
        first_omega_id.id(),
        CommunicationValue::new(CommunicationType::Success)
    ));

    let Ok(first) = first_rx.await else {
        panic!("first response channel closed");
    };
    let Ok(second) = second_rx.await else {
        panic!("second response channel closed");
    };
    assert!(first.is_type(CommunicationType::ErrorInternal));
    assert!(second.is_type(CommunicationType::Success));
}

#[test]
fn authenticated_key_cache_separates_clients_and_iotas_with_the_same_id() {
    let cache = DashMap::<AuthIdentity, CachedAuthenticatedKey>::new();
    let client = AuthIdentity {
        kind: AuthIdentityKind::Client,
        id: 42,
    };
    let iota = AuthIdentity {
        kind: AuthIdentityKind::Iota,
        id: 42,
    };
    let client_key = Keyring::generate().public_key_bundle();
    let iota_key = Keyring::generate().public_key_bundle();

    cache.insert(
        client,
        CachedAuthenticatedKey {
            public_key: client_key.clone(),
            cached_at: SystemTime::now(),
        },
    );
    cache.insert(
        iota,
        CachedAuthenticatedKey {
            public_key: iota_key.clone(),
            cached_at: SystemTime::now(),
        },
    );

    assert_eq!(cache.len(), 2);
    assert_eq!(
        cache
            .get(&client)
            .unwrap()
            .public_key
            .try_as_bytes()
            .unwrap(),
        client_key.try_as_bytes().unwrap()
    );
    assert_eq!(
        cache.get(&iota).unwrap().public_key.try_as_bytes().unwrap(),
        iota_key.try_as_bytes().unwrap()
    );
}

#[test]
fn authenticated_key_cache_rejects_expired_and_future_timestamps() {
    let now = SystemTime::now();
    let max_age = Duration::from_secs(24 * 60 * 60);
    assert!(cached_at_is_fresh(now, now, max_age));
    assert!(!cached_at_is_fresh(
        now,
        now - max_age - Duration::from_secs(1),
        max_age
    ));
    assert!(!cached_at_is_fresh(
        now,
        now + Duration::from_secs(1),
        max_age
    ));
}

#[test]
fn authenticated_key_paths_use_separate_namespaces() {
    let client_path = authenticated_key_path(AuthIdentity {
        kind: AuthIdentityKind::Client,
        id: 42,
    });
    let iota_path = authenticated_key_path(AuthIdentity {
        kind: AuthIdentityKind::Iota,
        id: 42,
    });

    assert_ne!(client_path, iota_path);
    assert!(client_path.ends_with("authenticated-public-keys/client/42.mpkb"));
    assert!(iota_path.ends_with("authenticated-public-keys/iota/42.mpkb"));
}

fn notification() -> CommunicationValue {
    CommunicationValue::new(CommunicationType::ClientChanged)
        .with_receiver(7)
        .add_typed_default(DataType::SessionId, DataValue::SignedNumber(11))
        .add_typed_default(DataType::UserId, DataValue::SignedNumber(20))
        .add_typed_default(DataType::UserState, DataValue::Str("user_online".into()))
}

#[test]
fn client_changed_target_requires_all_routing_fields() {
    assert_eq!(client_changed_target(&notification()), Some((7, 11)));

    let mut missing_session = notification();
    missing_session.remove_data(DataType::SessionId);
    assert_eq!(client_changed_target(&missing_session), None);

    let mut missing_state = notification();
    missing_state.remove_data(DataType::UserState);
    assert_eq!(client_changed_target(&missing_state), None);

    let missing_receiver = notification().without_receiver();
    assert_eq!(client_changed_target(&missing_receiver), None);
}

#[test]
fn client_changed_target_rejects_non_positive_ids() {
    let invalid = CommunicationValue::new(CommunicationType::ClientChanged)
        .with_receiver(0)
        .add_typed_default(DataType::SessionId, DataValue::SignedNumber(11))
        .add_typed_default(DataType::UserId, DataValue::SignedNumber(20))
        .add_typed_default(DataType::UserState, DataValue::Str("user_online".into()));
    assert_eq!(client_changed_target(&invalid), None);
}

#[test]
fn iota_user_snapshot_requires_its_iota_and_valid_user_ids() {
    let snapshot = CommunicationValue::new(CommunicationType::IotaUserData)
        .add_typed_default(DataType::IotaId, DataValue::SignedNumber(8))
        .add_typed_default(
            DataType::UserIds,
            DataValue::Array(vec![
                DataValue::SignedNumber(20),
                DataValue::SignedNumber(19),
                DataValue::SignedNumber(20),
            ]),
        );
    assert_eq!(iota_user_snapshot(&snapshot), Some((8, vec![19, 20])));

    let activation = CommunicationValue::new(CommunicationType::Success)
        .add_typed_default(DataType::IotaId, DataValue::SignedNumber(8))
        .add_typed_default(
            DataType::UserIds,
            DataValue::Array(vec![DataValue::SignedNumber(20)]),
        );
    assert_eq!(iota_activation_snapshot(&activation), Some((8, vec![20])));

    let missing_iota = CommunicationValue::new(CommunicationType::IotaUserData)
        .add_typed_default(DataType::UserIds, DataValue::Array(Vec::new()));
    assert_eq!(iota_user_snapshot(&missing_iota), None);

    let malformed_user = CommunicationValue::new(CommunicationType::IotaUserData)
        .add_typed_default(DataType::IotaId, DataValue::SignedNumber(8))
        .add_typed_default(
            DataType::UserIds,
            DataValue::Array(vec![DataValue::Str("not-a-user".into())]),
        );
    assert_eq!(iota_user_snapshot(&malformed_user), None);
}

#[test]
fn erasure_route_reads_omega_signed_iota_id() {
    let frame = CommunicationValue::new(CommunicationType::EraseHostedUserData)
        .add_typed_default(DataType::IotaId, DataValue::SignedNumber(8));
    assert_eq!(signed_positive_iota_id(&frame), Some(8));

    let unsigned = CommunicationValue::new(CommunicationType::EraseHostedUserData)
        .add_typed_default(DataType::IotaId, DataValue::UnsignedNumber(8));
    assert_eq!(signed_positive_iota_id(&unsigned), None);
}

#[test]
fn reconnect_jitter_is_bounded_without_changing_the_base_delay() {
    for _ in 0..32 {
        let delay = reconnect_delay_with_jitter(RECONNECT_DELAY);
        assert!(delay >= RECONNECT_DELAY);
        assert!(delay <= RECONNECT_DELAY + std::time::Duration::from_secs(1));
    }

    assert!(MAX_RECONNECT_DELAY > RECONNECT_DELAY);
}

#[test]
fn healthy_session_resets_accumulated_reconnect_backoff() {
    let mut delay = RECONNECT_DELAY;
    for _ in 0..4 {
        delay = std::cmp::min(delay * 2, MAX_RECONNECT_DELAY);
    }
    assert!(delay > RECONNECT_DELAY);

    assert_eq!(
        reconnect_base_after_outcome(delay, ConnectionOutcome::FailedBeforeHealthy),
        delay
    );
    assert_eq!(
        reconnect_base_after_outcome(delay, ConnectionOutcome::HealthySessionEnded),
        RECONNECT_DELAY
    );
}

#[test]
fn capability_response_negotiates_new_omega() {
    let response = CommunicationValue::new(CommunicationType::IdentificationResponse)
            .add_typed_default(
                DataType::Description,
                DataValue::Str(
                    "omega;caps=set_user_state_v1,state_subscribe_v1,session_snapshot_v1,client_state_push_v1"
                        .into(),
                ),
            );
    let capabilities = parse_omega_capability_response(&response).unwrap();
    assert!(capabilities.state_subscribe_v1);
    assert!(capabilities.client_state_push_v1);
}

#[test]
fn missing_capability_response_is_legacy() {
    let response = CommunicationValue::new(CommunicationType::IdentificationResponse);
    let capabilities = parse_omega_capability_response(&response).unwrap();
    assert_eq!(capabilities, PeerCapabilities::default());
}

#[test]
fn unsupported_capability_response_is_rejected() {
    let response = CommunicationValue::new(CommunicationType::IdentificationResponse)
        .add_typed_default(
            DataType::Description,
            DataValue::Str("omega;caps=unsupported_v9".into()),
        );
    assert!(parse_omega_capability_response(&response).is_err());
}
