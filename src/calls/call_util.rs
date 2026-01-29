use livekit_api::{
    access_token::{self},
    services::room::RoomClient,
};
use livekit_protocol::Room;
use std::env;
use std::str::FromStr;
use std::time::Duration;
use uuid::Uuid;

use crate::{calls::call_manager::CALL_GROUPS, log, log_err, util::logger::PrintType};

pub fn get_livekit() -> Result<(String, String, String), ()> {
    let hostname = match env::var("LIVEKI_HOSTNAME") {
        Ok(secret) => secret,
        Err(_) => {
            log_err!(PrintType::General, "LIVEKI_HOSTNAME not set!");
            return Err(());
        }
    };
    let api_key = match env::var("LIVEKIT_API_KEY") {
        Ok(key) => key,
        Err(_) => {
            log_err!(PrintType::General, "LIVEKIT_API_KEY not set!");
            return Err(());
        }
    };
    let api_secret = match env::var("LIVEKIT_API_SECRET") {
        Ok(secret) => secret,
        Err(_) => {
            log_err!(PrintType::General, "LIVEKIT_API_SECRET not set!");
            return Err(());
        }
    };
    Ok((hostname, api_key, api_secret))
}

pub fn create_token(user_id: i64, call_id: Uuid, has_admin: bool) -> Result<String, ()> {
    let (_, api_key, api_secret) = get_livekit()?;

    let token = access_token::AccessToken::with_api_key(&api_key, &api_secret)
        .with_identity(&user_id.to_string())
        .with_grants(access_token::VideoGrants {
            room_join: true,
            room_admin: has_admin,
            room: call_id.to_string(),
            ..Default::default()
        })
        .with_metadata(&format!("{{\"isAdmin\":{}}}", has_admin))
        .to_jwt();
    if let Ok(token) = token {
        Ok(token)
    } else {
        Err(())
    }
}
pub async fn get_room(call_id: Uuid) -> Result<(RoomClient, Room), ()> {
    if let Ok((hostname, api_key, api_secret)) = get_livekit() {
        let room_service = RoomClient::with_api_key(&hostname, &api_key, &api_secret);
        let rooms = room_service.list_rooms(Vec::new()).await;
        if let Ok(rooms) = rooms {
            for room in rooms {
                if room.name == call_id.to_string() {
                    return Ok((room_service, room));
                }
            }
        }
    }
    return Err(());
}

pub async fn remove_participant(call_id: Uuid, user_id: i64) -> Result<(), ()> {
    if let Ok((hostname, api_key, api_secret)) = get_livekit() {
        let room_service = RoomClient::with_api_key(&hostname, &api_key, &api_secret);
        if let Ok(_) = room_service
            .remove_participant(&call_id.to_string(), &user_id.to_string())
            .await
        {
            return Ok(());
        }
    }
    return Err(());
}

pub async fn get_room_metadata(call_id: Uuid) -> Result<String, ()> {
    if let Ok((_, room)) = get_room(call_id).await {
        Ok(room.metadata)
    } else {
        Err(())
    }
}

pub async fn set_room_metadata(call_id: Uuid, metadata: String) -> Result<(), ()> {
    if let Ok((hostname, api_key, api_secret)) = get_livekit() {
        let room_service = RoomClient::with_api_key(&hostname, &api_key, &api_secret);
        if let Ok(_) = room_service
            .update_room_metadata(&call_id.to_string(), &metadata)
            .await
        {
            return Ok(());
        }
    }
    return Err(());
}

pub fn garbage_collect_calls() {
    tokio::spawn(async move {
        loop {
            if let Ok((hostname, api_key, api_secret)) = get_livekit() {
                let room_service = RoomClient::with_api_key(&hostname, &api_key, &api_secret);
                clean_calls(room_service).await;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });
}
pub async fn clean_calls(room_service: RoomClient) {
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
    let size_pre = CALL_GROUPS.len();
    for (id, _) in CALL_GROUPS.clone().into_iter() {
        if !call_ids.contains(&id) {
            CALL_GROUPS.remove(&id);
        }
    }
    for (_, cg) in CALL_GROUPS.clone().into_iter() {
        *cg.show.write().await = !no_users.contains(&cg.call_id);
    }

    let size_post = CALL_GROUPS.len();
    if size_pre - size_post != 0 {
        log!(
            PrintType::Call,
            "Cleaned {} calls, {} remaining",
            size_pre - size_post,
            size_post
        );
    }
}
