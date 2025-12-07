use livekit_api::services::room::RoomClient;
use once_cell::sync::Lazy;
use std::{str::FromStr, sync::Arc, time::Duration};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::{
    calls::{call_group::CallGroup, caller::Caller},
    util::print::{PrintType, line},
};

static CALL_GROUPS: Lazy<RwLock<Vec<Arc<CallGroup>>>> = Lazy::new(|| RwLock::new(Vec::new()));

pub async fn get_call_invites(user_id: i64) -> Vec<Arc<Caller>> {
    let mut callers = Vec::new();
    for cg in CALL_GROUPS.read().await.iter() {
        let members = cg.members.read().await;
        for member in members.iter() {
            if member.user_id == user_id {
                callers.push(member.clone());
            }
        }
    }
    callers
}

pub async fn get_call_groups(user_id: i64) -> Vec<Arc<CallGroup>> {
    let mut call_groups = Vec::new();
    for cg in CALL_GROUPS.read().await.iter() {
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

pub async fn get_call_token(user_id: i64, call_id: Uuid) -> Option<String> {
    let existing_group = {
        let call_groups = CALL_GROUPS.read().await;
        call_groups.iter().find(|g| g.call_id == call_id).cloned()
    };

    if let Some(cg) = existing_group {
        let mut members = cg.members.write().await;

        if let Some(member) = members.iter().find(|m| m.user_id == user_id) {
            return Some(member.create_token());
        }

        let new_caller = Arc::new(Caller::new(user_id, call_id, user_id));
        let token = new_caller.create_token();

        members.push(new_caller);

        return Some(token);
    }

    let mut call_groups = CALL_GROUPS.write().await;

    if let Some(cg) = call_groups.iter().find(|g| g.call_id == call_id) {
        let cg_clone = cg.clone();
        drop(call_groups);

        let mut members = cg_clone.members.write().await;
        if let Some(member) = members.iter().find(|m| m.user_id == user_id) {
            return Some(member.create_token());
        }
        let new_caller = Arc::new(Caller::new(user_id, call_id, user_id));
        let token = new_caller.create_token();
        members.push(new_caller);
        return Some(token);
    }

    let caller = Arc::new(Caller::new(user_id, call_id, user_id));
    let call_group = CallGroup::new(call_id, caller.clone());

    call_groups.push(Arc::new(call_group));

    Some(caller.create_token())
}

pub async fn add_invite(call_id: Uuid, inviter_id: i64, invitee_id: i64) -> bool {
    let target_group: Option<Arc<CallGroup>> = CALL_GROUPS
        .read()
        .await
        .iter()
        .find(|g| g.call_id == call_id)
        .cloned();

    if let Some(cg) = target_group {
        let mut members = cg.members.write().await;

        let is_inviter_member = members.iter().any(|m| m.user_id == inviter_id);

        if is_inviter_member {
            if !members.iter().any(|m| m.user_id == invitee_id) {
                members.push(Arc::new(Caller::new(invitee_id, call_id, inviter_id)));
            }
            return true;
        }
    }
    false
}
pub fn garbage_collect_calls() {
    tokio::spawn(async move {
        loop {
            clean_calls().await;
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });
}
pub async fn clean_calls() {
    let room_service = RoomClient::new("https://call.tensamin.net").unwrap();
    let rooms = room_service.list_rooms(Vec::new()).await.unwrap();
    let mut call_ids: Vec<Uuid> = Vec::new();
    let mut no_users: Vec<Uuid> = Vec::new();
    for room in rooms {
        if let Ok(id) = Uuid::from_str(&room.name) {
            if room.num_participants == 0 {
                no_users.push(id);
            }
            call_ids.push(id);
        }
    }
    let mut call_groups = CALL_GROUPS.write().await;
    let size_pre = call_groups.len();
    call_groups.retain(|cg| call_ids.contains(&cg.call_id));

    for cg in call_groups.iter() {
        *cg.show.write().await = !no_users.contains(&cg.call_id);
    }

    let size_post = call_groups.len();
    drop(call_groups);
    if size_pre - size_post != 0 {
        line(
            PrintType::CallIn,
            &format!(
                "Cleaned {} calls, {} remaining",
                size_pre - size_post,
                size_post
            ),
        );
    }
}
