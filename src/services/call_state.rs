use std::collections::BTreeMap;
use std::sync::Arc;

use mtp::codec::{DataType, DataValue, TypeMap};

use crate::{calls::call_manager::CallManager, util::data_type_id};

pub struct CallStateAggregator {
    call_manager: Arc<CallManager>,
}

impl CallStateAggregator {
    pub fn new(call_manager: Arc<CallManager>) -> Self {
        Self { call_manager }
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
            let members = call.members.read().await;
            let Some(call_self) = members.iter().find(|member| member.user_id == user_id) else {
                continue;
            };

            let mut call_map = BTreeMap::new();
            call_map.insert(
                data_type_id(DataType::CallId, &tm),
                DataValue::Str(call.call_id.to_string()),
            );
            call_map.insert(
                data_type_id(DataType::CallMembers, &tm),
                DataValue::Array(
                    members
                        .iter()
                        .map(|member| DataValue::SignedNumber(member.user_id.into()))
                        .collect(),
                ),
            );

            let timeout = *call_self.timeout.read().await;
            if timeout > 0 {
                call_map.insert(
                    data_type_id(DataType::Timeout, &tm),
                    DataValue::SignedNumber((timeout as i64).into()),
                );
            }
            if call_self.has_admin() {
                call_map.insert(data_type_id(DataType::HasAdmin, &tm), DataValue::Bool(true));
            }
            if let Some(secret) = call.get_secret_for_user(user_id).await {
                call_map.insert(
                    data_type_id(DataType::CallSecret, &tm),
                    secret.to_data_value(),
                );
            }

            let call_value = DataValue::container_from_map(&call_map);
            global_calls.push(call_value.clone());
            for member in members.iter().filter(|member| member.user_id != user_id) {
                invites
                    .entry(member.user_id as i64)
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
    use crate::calls::{call_group::CallGroup, caller::Caller};
    use uuid::Uuid;

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
        let group = Arc::new(CallGroup::new(
            call_id,
            Arc::new(Caller::new(1, call_id, true)),
        ));
        group
            .members
            .write()
            .await
            .push(Arc::new(Caller::new(2, call_id, false)));
        manager.groups.insert(call_id, group);

        let tm = TypeMap::latest();
        let user_id_type = data_type_id(DataType::UserId, &tm);
        let calls_type = data_type_id(DataType::Calls, &tm);
        let mut contact = BTreeMap::new();
        contact.insert(user_id_type, DataValue::SignedNumber(2.into()));

        let (contacts, global_calls) = CallStateAggregator::new(manager)
            .augment_contacts(1, vec![DataValue::container_from_map(&contact)])
            .await;

        assert_eq!(global_calls.len(), 1);
        let Some(contact) = contacts[0].as_map() else {
            panic!("expected contact map");
        };
        assert!(matches!(
            contact.get(&calls_type),
            Some(DataValue::Array(_))
        ));
    }
}
