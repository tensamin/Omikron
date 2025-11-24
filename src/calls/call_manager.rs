use std::sync::Arc;

use once_cell::sync::Lazy;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::calls::{call_group::CallGroup, caller::Caller};

static CALL_GROUPS: Lazy<RwLock<Vec<Arc<CallGroup>>>> = Lazy::new(|| RwLock::new(Vec::new()));

pub async fn get_call_invites(user_id: Uuid) -> Vec<Arc<Caller>> {
    let mut callers = Vec::new();
    for cg in CALL_GROUPS.read().await.iter() {
        for member in cg.members.read().await.iter() {
            if member.user_id == user_id {
                callers.push(member.clone());
            }
        }
    }
    callers
}

pub async fn get_call_groups(user_id: Uuid) -> Vec<Arc<CallGroup>> {
    let mut call_groups = Vec::new();
    for cg in CALL_GROUPS.read().await.iter() {
        for member in cg.members.read().await.iter() {
            if member.user_id == user_id {
                call_groups.push(cg.clone());
            }
        }
    }
    call_groups
}

pub async fn get_call_token(user_id: Uuid, call_id: Uuid) -> Option<String> {
    let call_groups = CALL_GROUPS.read().await;
    for cg in call_groups.iter() {
        if cg.call_id == call_id {
            for member in cg.members.read().await.iter() {
                if member.user_id == user_id {
                    return Some(member.create_token());
                }
            }
            return None;
        }
    }
    let caller = Arc::new(Caller::new(user_id, user_id, call_id));
    let call_group = CallGroup::new(call_id, caller.clone());
    {
        CALL_GROUPS.write().await.push(Arc::new(call_group));
    }
    Some(caller.create_token())
}

pub async fn add_invite(call_id: Uuid, inviter_id: Uuid, invitee_id: Uuid) -> bool {
    let call_groups = CALL_GROUPS.read().await;
    for cg in call_groups.iter() {
        if cg.call_id == call_id {
            for member in cg.members.read().await.iter() {
                if member.user_id == inviter_id {
                    cg.clone().add_member(inviter_id, invitee_id).await;
                    return true;
                }
            }
            return false;
        }
    }
    false
}

pub async fn get_call_group_by_user(user_id: Uuid) -> Option<Arc<CallGroup>> {
    let call_groups = CALL_GROUPS.read().await;
    for cg in call_groups.iter() {
        for member in cg.members.read().await.iter() {
            if member.user_id == user_id {
                return Some(cg.clone());
            }
        }
    }
    None
}
