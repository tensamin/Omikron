use livekit_api::{
    access_token::{self},
    services::room::RoomClient,
};
use std::env;
use std::str::FromStr;
use std::time::Duration;
use uuid::Uuid;

use crate::{calls::call_manager::CALL_GROUPS, log, log_err, util::logger::PrintType};

pub fn create_token(user_id: i64, call_id: Uuid, has_admin: bool) -> Result<String, ()> {
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

    let token = access_token::AccessToken::with_api_key(&api_key, &api_secret)
        .with_identity(&user_id.to_string())
        .with_grants(access_token::VideoGrants {
            can_update_own_metadata: true,
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

pub fn garbage_collect_calls() {
    tokio::spawn(async move {
        let api_key = match env::var("LIVEKIT_API_KEY") {
            Ok(key) => key,
            Err(_) => {
                log_err!(PrintType::General, "LIVEKIT_API_KEY not set!");
                return;
            }
        };
        let api_secret = match env::var("LIVEKIT_API_SECRET") {
            Ok(secret) => secret,
            Err(_) => {
                log_err!(PrintType::General, "LIVEKIT_API_SECRET not set!");
                return;
            }
        };
        let hostname = match env::var("LIVEKI_HOSTNAME") {
            Ok(secret) => secret,
            Err(_) => {
                log_err!(PrintType::General, "LIVEKI_HOSTNAME not set!");
                return;
            }
        };
        loop {
            let room_service = RoomClient::with_api_key(&hostname, &api_key, &api_secret);
            clean_calls(room_service).await;
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
