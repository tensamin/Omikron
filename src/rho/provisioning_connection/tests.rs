use super::*;
use crate::provisioning::session::{
    ProvisioningMethod, ProvisioningParticipant, ProvisioningRole, ProvisioningState,
    ResolvedAccount,
};
use crate::rho::connection::OptionalDataValueExt;
use mtp::crypto::Keyring;
use mtp::{codec::ProtectedMessageBuilder, crypto::DualSigner};
use std::{sync::Weak, time::Instant};

#[tokio::test]
async fn join_and_bind_send_peer_first_and_attempt_only_one_requester_response() {
    for (kind, request_id) in [
        (CommunicationType::ProvisioningPeerJoined, 42),
        (CommunicationType::ProvisioningAccountBound, 73),
    ] {
        for failure in [
            None,
            Some(DeliveryFailure::Peer),
            Some(DeliveryFailure::Requester),
        ] {
            let attempts = Arc::new(std::sync::Mutex::new(Vec::new()));
            let event = CommunicationValue::new(kind);
            let event_id = event.id();
            let response = CommunicationValue::new(kind).with_id(request_id);
            let peer_attempts = attempts.clone();
            let requester_attempts = attempts.clone();
            let fail_peer = failure == Some(DeliveryFailure::Peer);
            let fail_requester = failure == Some(DeliveryFailure::Requester);
            let result = deliver_peer_then_reply(
                event,
                response,
                move |message| async move {
                    peer_attempts.lock().unwrap().push(("peer", message.id()));
                    !fail_peer
                },
                move |message| async move {
                    requester_attempts
                        .lock()
                        .unwrap()
                        .push(("requester", message.id()));
                    !fail_requester
                },
            )
            .await;
            assert_eq!(result.err(), failure);
            let attempts = attempts.lock().unwrap();
            assert_eq!(attempts[0], ("peer", event_id));
            assert_eq!(attempts.len(), if fail_peer { 1 } else { 2 });
            if !fail_peer {
                assert_eq!(attempts[1], ("requester", Some(request_id)));
            }
        }
    }
}

#[test]
fn join_and_bind_replies_use_request_ids() {
    let id = Uuid::new_v4();
    let participant = ProvisioningParticipant {
        id: 2,
        role: ProvisioningRole::Contact,
        temporary_public_key: Keyring::generate().public_key_bundle(),
        sender: Weak::new(),
    };
    let event = peer_joined_message(id, &participant, None).unwrap();
    let response = peer_joined_message(id, &participant, Some(42)).unwrap();
    assert!(event.id().is_some());
    assert_eq!(response.id(), Some(42));
    assert!(event.is_type(CommunicationType::ProvisioningPeerJoined));

    let account = ResolvedAccount {
        user_id: 7,
        username: "alice".into(),
        iota_id: 11,
        principal: "principal".into(),
        public_key: Keyring::generate().public_key_bundle(),
    };
    let encoded = account.public_key.try_to_base64().unwrap();
    let event = account_bound_message(id, &account, &encoded, None);
    let response = account_bound_message(id, &account, &encoded, Some(73));
    assert!(event.id().is_some());
    assert_eq!(response.id(), Some(73));
    assert!(event.is_type(CommunicationType::ProvisioningAccountBound));
}

#[test]
fn terminated_join_or_bind_releases_both_participant_mappings() {
    for bound in [false, true] {
        let manager = ProvisioningManager::new(Duration::from_secs(60), 2);
        let participant = |id, role| ProvisioningParticipant {
            id,
            role,
            temporary_public_key: Keyring::generate().public_key_bundle(),
            sender: Weak::new(),
        };
        let id = manager
            .create(
                ProvisioningMethod::QrOwnerCreated,
                participant(1, ProvisioningRole::Owner),
            )
            .unwrap();
        manager
            .join(id, participant(2, ProvisioningRole::Contact))
            .unwrap();
        if bound {
            manager
                .bind(
                    id,
                    1,
                    ResolvedAccount {
                        user_id: 7,
                        username: "alice".into(),
                        iota_id: 11,
                        principal: "principal".into(),
                        public_key: Keyring::generate().public_key_bundle(),
                    },
                )
                .unwrap();
        }
        manager
            .fail_forward(id, 2, ProvisioningFailure::DeliveryFailed)
            .unwrap();
        assert!(manager.for_participant(1).is_err());
        assert!(manager.for_participant(2).is_err());
        assert!(manager.snapshot(id, 1).is_err());
        assert!(
            manager
                .create(
                    ProvisioningMethod::QrOwnerCreated,
                    participant(1, ProvisioningRole::Owner)
                )
                .is_ok()
        );
    }
}

#[test]
fn forged_client_metadata_does_not_override_session() {
    let contact_key = Keyring::generate().public_key_bundle();
    let session = ProvisioningSession {
        id: Uuid::new_v4(),
        method: ProvisioningMethod::Password,
        contact: Some(ProvisioningParticipant {
            id: 300,
            role: ProvisioningRole::Contact,
            temporary_public_key: contact_key.clone(),
            sender: Weak::new(),
        }),
        owner: None,
        account: Some(ResolvedAccount {
            user_id: 100,
            username: "user".into(),
            principal: "principal".into(),
            iota_id: 200,
            public_key: Keyring::generate().public_key_bundle(),
        }),
        state: ProvisioningState::AccountBound,
        owner_confirmed: false,
        created_at: Instant::now(),
    };
    let request = CommunicationValue::new(CommunicationType::PasswordProvisioningStart)
        .with_id(42)
        .add_typed_default(DataType::UserId, DataValue::SignedNumber(999))
        .add_typed_default(DataType::IotaId, DataValue::SignedNumber(999))
        .add_typed_default(
            DataType::ProvisioningParticipantId,
            DataValue::UnsignedNumber(999),
        )
        .add_typed_default(
            DataType::PublicKey,
            DataValue::Str(
                Keyring::generate()
                    .public_key_bundle()
                    .try_to_base64()
                    .unwrap(),
            ),
        );
    let forwarded = build_password_iota_request(&request, &session, vec![1, 2]).unwrap();
    assert_eq!(forwarded.get_data(DataType::UserId).as_number(), Some(100));
    assert_eq!(forwarded.get_data(DataType::IotaId).as_number(), Some(200));
    assert_eq!(
        forwarded
            .get_data(DataType::ProvisioningParticipantId)
            .as_number(),
        Some(300)
    );
    assert_eq!(
        forwarded.get_data(DataType::PublicKey).as_str(),
        Some(contact_key.try_to_base64().unwrap().as_str())
    );
}

#[test]
fn qr_credential_relay_requires_protection_recipient_and_owner_confirmation() {
    let owner = Keyring::generate();
    let contact = Keyring::generate();
    let signer = DualSigner::new(
        &owner.sig_cl_secret_key,
        &owner.sig_pq_secret_key,
        &owner.sig_pq_public_key,
    )
    .unwrap();
    for method in [
        ProvisioningMethod::QrContactCreated,
        ProvisioningMethod::QrOwnerCreated,
    ] {
        let manager = ProvisioningManager::new(Duration::from_secs(60), 2);
        let participant = |id, role, key: &Keyring| ProvisioningParticipant {
            id,
            role,
            temporary_public_key: key.public_key_bundle(),
            sender: Weak::new(),
        };
        let id = match method {
            ProvisioningMethod::QrContactCreated => {
                let id = manager
                    .create(method, participant(2, ProvisioningRole::Contact, &contact))
                    .unwrap();
                manager
                    .join(id, participant(1, ProvisioningRole::Owner, &owner))
                    .unwrap();
                id
            }
            ProvisioningMethod::QrOwnerCreated => {
                let id = manager
                    .create(method, participant(1, ProvisioningRole::Owner, &owner))
                    .unwrap();
                manager
                    .join(id, participant(2, ProvisioningRole::Contact, &contact))
                    .unwrap();
                id
            }
            ProvisioningMethod::Password => unreachable!(),
        };
        manager
            .bind(
                id,
                1,
                ResolvedAccount {
                    user_id: 100,
                    username: "owner".into(),
                    principal: "omega-key:example#100".into(),
                    iota_id: 200,
                    public_key: owner.public_key_bundle(),
                },
            )
            .unwrap();

        let clear = CommunicationValue::new(CommunicationType::ProvisioningCredential)
            .with_id(42)
            .with_receiver(2);
        assert!(authorize_qr_credential(&manager, 1, &clear).is_err());

        let protected = ProtectedMessageBuilder::new(
            CommunicationType::ProvisioningCredential,
            DataValue::Bytes(vec![1, 2, 3]),
            1,
            2,
            &signer,
            crate::app_protection::purpose(
                crate::app_protection::PROVISIONING_CREDENTIAL_SIGNATURE,
            ),
            crate::app_protection::purpose(
                crate::app_protection::PROVISIONING_CREDENTIAL_ENCRYPTION,
            ),
        )
        .message_id(u128::from(id.as_u128() as u64))
        .created_at(1)
        .recipients(vec![contact.public_key_bundle()])
        .frame_id(42)
        .build()
        .unwrap();
        let original_payload = protected.payload().clone();
        assert!(protected.payload().as_encrypted().is_some());
        assert!(authorize_qr_credential(&manager, 1, &protected.clone().with_receiver(3)).is_err());
        assert!(authorize_qr_credential(&manager, 1, &protected).is_err());
        if method == ProvisioningMethod::QrContactCreated {
            manager.confirm(id, 2).unwrap();
        }
        manager.confirm(id, 1).unwrap();
        authorize_qr_credential(&manager, 1, &protected).unwrap();
        assert_eq!(protected.payload(), &original_payload);
        manager.delivered(id, 1).unwrap();
    }
}

#[test]
fn provisioning_frames_reject_bootstrap_and_repeated_account_fields() {
    let create = CommunicationValue::new(CommunicationType::ProvisioningCreate)
        .add_typed_default(
            DataType::ProvisioningMethod,
            DataValue::Str("qr-contact-created".into()),
        )
        .add_typed_default(DataType::ProvisioningRole, DataValue::Str("contact".into()))
        .add_typed_default(DataType::PublicKey, DataValue::Str("key".into()));
    assert!(ProvisioningConnection::valid_fields(&create));
    assert!(!ProvisioningConnection::valid_fields(
        &create.add_typed_default(
            DataType::Payload,
            DataValue::Bytes(b"bootstrap secret".to_vec())
        )
    ));
    let ke1 = CommunicationValue::new(CommunicationType::PasswordProvisioningStart)
        .add_typed_default(DataType::Uuid, DataValue::Str(Uuid::new_v4().to_string()))
        .add_typed_default(DataType::OpaqueMessage, DataValue::Bytes(vec![1]));
    assert!(ProvisioningConnection::valid_fields(&ke1));
    assert!(!ProvisioningConnection::valid_fields(
        &ke1.add_typed_default(DataType::UserId, DataValue::SignedNumber(7))
    ));
    assert!(!ProvisioningConnection::valid_fields(
        &CommunicationValue::new(CommunicationType::SettingsSave)
    ));
}
