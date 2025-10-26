use crate::util::file_util::load_file;
use crate::util::print::PrintType;
use crate::util::print::line;
use crate::util::print::line_err;
use futures::lock::Mutex;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub omega_server: String,
    pub auth_server: String,
    pub omikron_id: Uuid,
    pub keep_people_stored_for: i32,
    pub max_data: u64,
    pub ip: String,
    pub port: u16,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            omega_server: "omega.tensamin.methanium.net".into(),
            auth_server: "auth.tensamin.methanium.net".into(),
            omikron_id: Uuid::parse_str("a9e92dd6-08a6-4765-abf1-9fa39d0a99f9").unwrap_or_default(),
            keep_people_stored_for: 90,
            max_data: 1000 * 1000 * 1000 * 8,
            ip: "0.0.0.0".into(),
            port: 959,
        }
    }
}

pub static CONFIG: Lazy<Mutex<Config>> = Lazy::new(|| Mutex::new(Config::load()));

impl Config {
    pub fn load() -> Self {
        let content = load_file("", "config.json");
        if content.trim().is_empty() {
            return Config::default();
        }

        let json = json::parse(&content).unwrap();
        line(PrintType::ClientIn, &format!("{:?}", json));
        line(PrintType::ClientIn, &format!("{:?}", json["omikron_id"]));
        Self {
            omega_server: json["omega_server"].as_str().unwrap_or_default().into(),
            auth_server: json["auth_server"].as_str().unwrap_or_default().into(),
            omikron_id: Uuid::parse_str(json["omikron_id"].as_str().unwrap_or_default())
                .unwrap_or_default(),
            keep_people_stored_for: json["keep_people_stored_for"].as_i64().unwrap_or_default()
                as i32,
            max_data: json["max_data"].as_u64().unwrap_or_default(),
            ip: json["ip"].as_str().unwrap_or_default().into(),
            port: json["port"].as_u64().unwrap_or_default() as u16,
        }
    }
}
