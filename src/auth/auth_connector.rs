use crate::data::communication::{CommunicationType, CommunicationValue, DataTypes};
use crate::util::config_util::CONFIG;
use reqwest::{Client, Response};
use std::time::Duration;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct AuthUser {
    pub created_at: i64,
    pub username: String,
    pub display: String,
    pub avatar: String,
    pub about: String,
    pub status: String,
    pub public_key: String,
    pub sub_level: i32,
    pub sub_end: i32,
}

fn client() -> Client {
    Client::builder()
        .connect_timeout(Duration::from_secs(100))
        .timeout(Duration::from_secs(150))
        .build()
        .unwrap()
}

pub async fn get_user(user_id: Uuid) -> Option<AuthUser> {
    let url = format!("https://auth.tensamin.methanium.net/api/get/{}", user_id);
    let client = client();
    let res = client.get(&url).send().await.ok()?;
    let json = res.text().await.ok()?;

    let cv = CommunicationValue::from_json(&json);
    if cv.comm_type != CommunicationType::success {
        return None;
    }

    Some(AuthUser {
        created_at: cv
            .get_data(DataTypes::created_at)
            .unwrap()
            .to_string()
            .parse::<i64>()
            .unwrap_or(-1),
        username: cv.get_data(DataTypes::username).unwrap().to_string(),
        display: cv.get_data(DataTypes::display).unwrap().to_string(),
        avatar: cv.get_data(DataTypes::avatar).unwrap().to_string(),
        about: cv.get_data(DataTypes::about).unwrap().to_string(),
        status: cv.get_data(DataTypes::status).unwrap().to_string(),
        public_key: cv.get_data(DataTypes::public_key).unwrap().to_string(),
        sub_level: cv
            .get_data(DataTypes::sub_level)
            .unwrap()
            .to_string()
            .parse::<i32>()
            .unwrap_or(-1),
        sub_end: cv
            .get_data(DataTypes::sub_end)
            .unwrap()
            .to_string()
            .parse::<i32>()
            .unwrap_or(-1),
    })
}

pub async fn get_iota_id(user_id: Uuid) -> Option<Uuid> {
    let url = format!(
        "https://auth.tensamin.methanium.net/api/get/iota-id/{}",
        user_id
    );

    let client = client();
    let res = client
        .get(&url)
        .header("Authorization", CONFIG.lock().await.omikron_id.to_string())
        .header("Content-Type", "application/json")
        .send()
        .await
        .ok()?;

    let json = res.text().await.ok()?;
    let json = json.replace("iota_uuid", "iota_id");

    let cv = CommunicationValue::from_json(&json);
    if cv.comm_type != CommunicationType::success {
        return None;
    }

    let iota_id_str = cv.get_data(DataTypes::iota_id)?.to_string();
    Uuid::parse_str(&iota_id_str).ok()
}
pub async fn is_private_key_valid(user_id: Uuid, pk_hash: &str) -> bool {
    let url = format!(
        "https://auth.tensamin.methanium.net/api/get/private-key-hash/{}/",
        user_id
    );

    let client = client();
    println!("Auth: {}", CONFIG.lock().await.omikron_id);
    let res = client
        .get(&url)
        .header("Authorization", CONFIG.lock().await.omikron_id.to_string())
        .header("PrivateKeyHash", pk_hash)
        .header("Accept", "application/json")
        .send()
        .await;

    let Ok(response) = res else {
        return false;
    };

    let Ok(body) = response.text().await else {
        return false;
    };

    let cv = CommunicationValue::from_json(&body);
    println!("Auth: {}", &body);
    if cv.comm_type != CommunicationType::success {
        return false;
    }

    match cv.get_data(DataTypes::matches) {
        Some(val) => val.as_bool().unwrap_or(false),
        None => false,
    }
}
pub async fn get_public_key(user_id: Uuid) -> Option<String> {
    let url = format!(
        "https://auth.tensamin.methanium.net/api/{}/public-key",
        user_id
    );

    let client = client();
    let res = client
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .await
        .ok()?;

    let body = res.text().await.ok()?;
    let mut cv = CommunicationValue::from_json(&body);

    if cv.comm_type != CommunicationType::message_send {
        return None;
    }

    Some(cv.get_data(DataTypes::ping_clients)?.to_string())
}

pub async fn get_register() -> Option<Uuid> {
    let url = "https://auth.tensamin.methanium.net/api/register/init".to_string();
    let client = client();
    let res = client.get(&url).send().await.ok()?;
    let json = res.text().await.ok()?;

    let cv = CommunicationValue::from_json(&json);
    Uuid::parse_str(&*cv.get_data(DataTypes::user_id).unwrap().to_string()).ok()
}

async fn handle_response(resp: Response) -> bool {
    match resp.text().await {
        Ok(text) => {
            let cv = CommunicationValue::from_json(&text.to_string());
            cv.comm_type == CommunicationType::success
        }
        Err(_) => false,
    }
}
