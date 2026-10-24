use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue, TypeMap};
use std::time::Duration;
use tau::calls::{CallClock, CallRepository, SystemCallClock};

use crate::{calls::call_manager::CallManager, util::data_type_id};

/*
 * Correlation ids for Omikron-to-Iota call lookups. Timestamps truncate badly
 * to u32 and collide across concurrent snapshots, which silently drops one
 * side's envelope lookup, so ids come from a dedicated counter instead.
 */
static NEXT_CALL_LOOKUP_ID: AtomicU32 = AtomicU32::new(1);

pub(crate) fn next_call_lookup_id() -> u32 {
    let mut current = NEXT_CALL_LOOKUP_ID.load(Ordering::Relaxed);
    loop {
        let next = current.checked_add(1).unwrap_or(1);
        match NEXT_CALL_LOOKUP_ID.compare_exchange_weak(
            current,
            next,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return next,
            Err(observed) => current = observed,
        }
    }
}

pub struct CallStateAggregator {
    call_manager: Arc<CallManager>,
    rho: Option<Arc<crate::rho::rho_manager::RhoManager>>,
}

impl CallStateAggregator {
    pub fn new(call_manager: Arc<CallManager>) -> Self {
        Self {
            call_manager,
            rho: None,
        }
    }

    pub fn with_rho(mut self, rho: Arc<crate::rho::rho_manager::RhoManager>) -> Self {
        self.rho = Some(rho);
        self
    }

    async fn authorized_legacy_snapshot(
        &self,
        user_id: u64,
        id: uuid::Uuid,
    ) -> Result<tau::calls::CallSnapshot, tau::calls::CallError> {
        let repository = self
            .call_manager
            .repository
            .as_ref()
            .ok_or(tau::calls::CallError::StorageUnavailable)?;
        let call = repository.read(self.call_manager.call_id(id)?).await?;
        let actor = self.call_manager.actor(user_id)?;
        let now = SystemCallClock.now_ms()?;
        call.authorize_envelope_read(actor.principal(), 0, now)?;
        call.snapshot(&actor, now)
    }

    pub async fn augment_contacts(
        &self,
        user_id: u64,
        contacts: Vec<DataValue>,
    ) -> (Vec<DataValue>, Vec<DataValue>) {
        let tm = TypeMap::latest();
        let mut invites = std::collections::HashMap::new();
        let mut global_calls = Vec::new();

        for call in self.call_manager.get_call_groups(user_id).await {
            if self.rho.is_some()
                && self
                    .authorized_legacy_snapshot(user_id, call.call_id)
                    .await
                    .is_err()
            {
                continue;
            }
            let secret = if let Some(rho_manager) = &self.rho {
                let Some(rho) = rho_manager.get_for_user(user_id as i64).await else {
                    continue;
                };
                let request = CommunicationValue::new(CommunicationType::CallEnvelopeGet)
                    .with_id(crate::services::call_state::next_call_lookup_id())
                    .add_typed_default(
                        DataType::ReceiverId,
                        DataValue::SignedNumber(user_id.into()),
                    )
                    .add_typed_default(DataType::CallId, DataValue::Str(call.call_id.to_string()));
                match rho
                    .get_iota_connection()
                    .clone()
                    .await_response(&request, Some(Duration::from_secs(8)))
                    .await
                {
                    Ok(response) if response.is_type(CommunicationType::CallEnvelopeGet) => {
                        response.get_data(DataType::CallSecret).cloned()
                    }
                    _ => None,
                }
            } else {
                None
            };
            if self.rho.is_some() && secret.is_none() {
                continue;
            }
            let scoped = if self.rho.is_some() {
                match self.authorized_legacy_snapshot(user_id, call.call_id).await {
                    Ok(snapshot) => Some(snapshot),
                    Err(_) => continue,
                }
            } else {
                None
            };

            // Envelope lookup can await a remote Iota. Refresh the committed
            // projection afterwards so a kick during lookup cannot expose it.
            let Some(call) = self.call_manager.get_call(call.call_id).await else {
                continue;
            };
            let revision = scoped.as_ref().map(|snapshot| snapshot.revision);
            let (call_self, pending, members, pending_invitees) = if let Some(snapshot) = scoped {
                let authority = self
                    .call_manager
                    .principal(user_id)
                    .ok()
                    .map(|p| p.authority);
                let members = snapshot
                    .members
                    .iter()
                    .filter(|m| Some(&m.principal.authority) == authority.as_ref())
                    .map(|m| m.principal.user_id)
                    .collect::<Vec<_>>();
                let pending_invitees = snapshot
                    .invitations
                    .iter()
                    .filter(|i| {
                        i.delivery_ready && Some(&i.recipient.authority) == authority.as_ref()
                    })
                    .map(|i| i.recipient.user_id)
                    .collect::<Vec<_>>();
                let own = snapshot
                    .member
                    .map(|m| crate::calls::call_group::CallMember {
                        user_id: m.principal.user_id,
                        role: match m.role {
                            tau::calls::CallRole::Member => {
                                crate::calls::call_group::CallRole::Member
                            }
                            _ => crate::calls::call_group::CallRole::Admin,
                        },
                        timeout_until_ms: m.timeout_until_ms,
                        participating: false,
                    });
                let pending =
                    snapshot
                        .invitation
                        .map(|i| crate::calls::call_group::PendingCallInvite {
                            inviter_id: i.inviter.user_id,
                            created_at_ms: i
                                .expires_at_ms
                                .saturating_sub(snapshot.policy.invite_ttl_ms),
                        });
                (own, pending, members, pending_invitees)
            } else {
                let state = call.state.read().await;
                (
                    state.members.get(&user_id).cloned(),
                    state.pending_invites.get(&user_id).cloned(),
                    state.members.keys().copied().collect::<Vec<_>>(),
                    state.pending_invites.keys().copied().collect::<Vec<_>>(),
                )
            };
            if call_self.is_none() && pending.is_none() {
                continue;
            }

            let mut call_map = BTreeMap::new();
            if let Some(revision) = revision {
                call_map.insert(
                    data_type_id(DataType::VersionNumber, &tm),
                    DataValue::UnsignedNumber(revision.into()),
                );
            }
            call_map.insert(
                data_type_id(DataType::CallId, &tm),
                DataValue::Str(call.call_id.to_string()),
            );
            call_map.insert(
                data_type_id(DataType::OmikronId, &tm),
                DataValue::SignedNumber((call.owner_omikron_id as i64).into()),
            );
            call_map.insert(
                data_type_id(DataType::CallMembers, &tm),
                // The wire list includes pending invitees so clients can
                // recognize joinable calls for a contact before joining.
                DataValue::Array(
                    members
                        .iter()
                        .chain(pending_invitees.iter())
                        .map(|member| DataValue::SignedNumber((*member).into()))
                        .collect(),
                ),
            );

            if let Some(timeout) = call_self
                .as_ref()
                .and_then(|member| member.timeout_until_ms)
            {
                call_map.insert(
                    data_type_id(DataType::Timeout, &tm),
                    DataValue::SignedNumber(timeout.into()),
                );
            }
            if call_self
                .as_ref()
                .is_some_and(|member| member.role == crate::calls::call_group::CallRole::Admin)
            {
                call_map.insert(data_type_id(DataType::HasAdmin, &tm), DataValue::Bool(true));
            }
            if let Some(secret) = secret {
                call_map.insert(data_type_id(DataType::CallSecret, &tm), secret);
            }
            call_map.insert(
                data_type_id(DataType::CreatedAt, &tm),
                DataValue::SignedNumber(call.created_at_ms.into()),
            );
            if let Some(pending) = pending {
                call_map.insert(
                    data_type_id(DataType::CallInvited, &tm),
                    DataValue::Bool(true),
                );
                call_map.insert(
                    data_type_id(DataType::SenderId, &tm),
                    DataValue::SignedNumber(pending.inviter_id.into()),
                );
            }

            let call_value = DataValue::container_from_map(&call_map);
            global_calls.push(call_value.clone());
            for member in members.into_iter().filter(|member| *member != user_id) {
                invites
                    .entry(member as i64)
                    .or_insert_with(Vec::new)
                    .push(call_value.clone());
            }
        }

        let user_id_type = data_type_id(DataType::UserId, &tm);
        let calls_type = data_type_id(DataType::Calls, &tm);
        let augmented_contacts = contacts
            .into_iter()
            .map(|contact| {
                let Some(mut contact_map) = contact.as_map() else {
                    return contact;
                };
                let Some(DataValue::SignedNumber(contact_id)) = contact_map.get(&user_id_type)
                else {
                    return DataValue::container_from_map(&contact_map);
                };
                if let Some(calls) = invites.get(&(*contact_id as i64)) {
                    contact_map.insert(calls_type, DataValue::Array(calls.clone()));
                }
                DataValue::container_from_map(&contact_map)
            })
            .collect();

        (augmented_contacts, global_calls)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::calls::call_group::CallGroup;
    use uuid::Uuid;

    #[tokio::test]
    async fn state_sync_key_gate_is_stricter_than_snapshot_visibility() {
        use tau::calls::*;
        for case in 0..4 {
            let mut call = crate::calls::repository::tests::call();
            let now = SystemCallClock.now_ms().unwrap();
            let expected = match case {
                0 => {
                    call.members
                        .iter_mut()
                        .find(|m| m.principal.user_id == 4)
                        .unwrap()
                        .timeout_until_ms = Some(now + 60_000);
                    CallError::TimedOut {
                        until_ms: now + 60_000,
                    }
                }
                1 => {
                    call.policy.join_policy = JoinPolicy::Approved;
                    call.members
                        .iter_mut()
                        .find(|m| m.principal.user_id == 4)
                        .unwrap()
                        .approved = false;
                    CallError::NotAuthorized
                }
                2 => {
                    call.lifecycle = CallLifecycle::Ending;
                    CallError::AlreadyEnded
                }
                _ => {
                    call.key_epoch = 1;
                    CallError::KeyEpochPending
                }
            };
            let repository = Arc::new(
                crate::calls::repository::SqliteCallRepository::open(std::path::Path::new(
                    ":memory:",
                ))
                .unwrap(),
            );
            repository.insert(call.clone()).await.unwrap();
            let livekit = Arc::new(crate::calls::call_util::LiveKitService::new(None));
            let runtime = Arc::new(crate::calls::runtime::CallRuntime {
                repository: repository.clone(),
                rho: Arc::new(crate::rho::rho_manager::RhoManager::new()),
                principal_authority: call.owner.authority.clone(),
            });
            let engine = Arc::new(CallEngine::new(
                repository.clone(),
                livekit.clone(),
                runtime.clone(),
                runtime,
                Arc::new(SystemCallClock),
            ));
            let manager = Arc::new(CallManager::new_with_owner(livekit, 42).with_runtime(
                repository,
                engine,
                call.id.owner_authority.clone(),
                call.owner.authority.clone(),
            ));
            assert!(manager.snapshot(4, call.id.clone()).await.is_ok());
            assert_eq!(
                CallStateAggregator::new(manager)
                    .authorized_legacy_snapshot(4, call.id.id)
                    .await,
                Err(expected)
            );
        }
    }

    #[tokio::test]
    async fn augment_contacts_preserves_contacts_without_call_invites() {
        let aggregator = CallStateAggregator::new(Arc::new(CallManager::default()));
        let contacts = vec![DataValue::Str("unchanged".to_string())];

        let (augmented, global_calls) = aggregator.augment_contacts(7, contacts.clone()).await;

        assert_eq!(augmented, contacts);
        assert!(global_calls.is_empty());
    }

    #[tokio::test]
    async fn augment_contacts_adds_call_to_member_contact() {
        let call_id = Uuid::new_v4();
        let manager = Arc::new(CallManager::default());
        let group = Arc::new(CallGroup::new_with_service(
            call_id,
            42,
            1,
            Arc::new(crate::calls::call_util::LiveKitService::new(None)),
            crate::config::CallLimits::default(),
        ));
        group.invite(1, 2).await.unwrap();
        group.accept_invite(2).await.unwrap();
        manager.groups.insert(call_id, group);

        let tm = TypeMap::latest();
        let user_id_type = data_type_id(DataType::UserId, &tm);
        let calls_type = data_type_id(DataType::Calls, &tm);
        let omikron_id_type = data_type_id(DataType::OmikronId, &tm);
        let mut contact = BTreeMap::new();
        contact.insert(user_id_type, DataValue::SignedNumber(2.into()));

        let (contacts, global_calls) = CallStateAggregator::new(manager)
            .augment_contacts(1, vec![DataValue::container_from_map(&contact)])
            .await;

        assert_eq!(global_calls.len(), 1);
        let Some(call) = global_calls[0].as_map() else {
            panic!("expected call map");
        };
        assert!(matches!(
            call.get(&omikron_id_type),
            Some(DataValue::SignedNumber(id)) if *id == 42
        ));
        let Some(contact) = contacts[0].as_map() else {
            panic!("expected contact map");
        };
        assert!(matches!(
            contact.get(&calls_type),
            Some(DataValue::Array(_))
        ));
    }
}
