use dashmap::DashMap;
use once_cell::sync::Lazy;
use std::sync::Arc;
use uuid::Uuid;

use crate::calls::{call_group::CallGroup, call_util, caller::Caller};

pub static CALL_GROUPS: Lazy<DashMap<Uuid, Arc<CallGroup>>> = Lazy::new(|| DashMap::new());
#[allow(dead_code)]
pub async fn get_call_invites(user_id: u64) -> Vec<Arc<Caller>> {
    let mut callers = Vec::new();
    for (_, cg) in CALL_GROUPS.clone().into_iter() {
        let members = cg.members.read().await;
        for member in members.iter() {
            if member.user_id == user_id {
                callers.push(member.clone());
            }
        }
    }
    callers
}

pub async fn get_call(call_id: Uuid) -> Option<Arc<CallGroup>> {
    if let Some(b) = CALL_GROUPS.get(&call_id) {
        Some(b.clone())
    } else {
        None
    }
}

pub async fn get_call_groups(user_id: u64) -> Vec<Arc<CallGroup>> {
    let mut call_groups = Vec::new();
    for (_, cg) in CALL_GROUPS.clone().into_iter() {
        let is_member = {
            let members = cg.members.read().await;
            members.iter().any(|m| m.user_id == user_id)
        };

        if is_member {
            call_groups.push(cg.clone());
        }
    }
    call_groups
}

pub async fn get_call_token(user_id: u64, call_id: Uuid) -> Option<String> {
    if let Some(cg) = CALL_GROUPS.get(&call_id) {
        let mut members = cg.members.write().await;

        if let Some(member) = members.iter().find(|m| m.user_id == user_id) {
            return Some(member.create_token());
        }

        let new_caller = Arc::new(Caller::new(user_id, call_id, false));
        let token = new_caller.create_token();

        members.push(new_caller);

        return Some(token);
    }

    let caller = Arc::new(Caller::new(user_id, call_id, true));
    let call_group = Arc::new(CallGroup::new(call_id, caller.clone()));

    CALL_GROUPS.insert(call_id, call_group.clone());

    let _ = call_util::create_room(call_id).await;
    call_group.update_admins().await;

    Some(caller.create_token())
}

pub async fn add_invite(
    call_id: Uuid,
    inviter_id: u64,
    invitee_id: u64,
    secret: Option<String>,
) -> bool {
    if let Some(cg) = CALL_GROUPS.get(&call_id) {
        let mut members = cg.members.write().await;

        let is_inviter_member = members.iter().any(|m| m.user_id == inviter_id);

        if is_inviter_member {
            if !members.iter().any(|m| m.user_id == invitee_id) {
                members.push(Arc::new(Caller::new(invitee_id, call_id, false)));
            }

            if let Some(secret) = secret {
                let mut secrets = cg.secrets.write().await;
                secrets.insert((inviter_id, invitee_id), secret.clone());
                secrets.insert((invitee_id, inviter_id), secret);
            }

            return true;
        }
    }
    false
}
