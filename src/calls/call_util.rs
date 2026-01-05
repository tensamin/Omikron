use livekit_api::access_token;
use std::env;
use uuid::Uuid;

pub fn create_token(
    user_id: i64,
    call_id: Uuid,
    has_admin: bool,
) -> Result<String, access_token::AccessTokenError> {
    let api_key = env::var("LIVEKIT_API_KEY").expect("LIVEKIT_API_KEY is not set");
    let api_secret = env::var("LIVEKIT_API_SECRET").expect("LIVEKIT_API_SECRET is not set");

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
    return token;
}
