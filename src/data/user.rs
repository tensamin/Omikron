#[derive(Clone, Copy)]
#[allow(non_camel_case_types)]
pub enum UserStatus {
    online,
    do_not_disturb,
    wc,
    away,
    user_offline,
    iota_offline,
}
impl UserStatus {
    pub fn to_string(self) -> String {
        match self {
            UserStatus::online => "online".to_string(),
            UserStatus::do_not_disturb => "do_not_disturb".to_string(),
            UserStatus::wc => "wc".to_string(),
            UserStatus::away => "away".to_string(),
            UserStatus::user_offline => "user_offline".to_string(),
            UserStatus::iota_offline => "iota_offline".to_string(),
        }
    }
    pub fn from_string(status_str: &str) -> Result<Self, String> {
        match status_str.to_lowercase().as_str() {
            "online" => Ok(UserStatus::online),
            "do_not_disturb" => Ok(UserStatus::do_not_disturb),
            "wc" => Ok(UserStatus::wc),
            "away" => Ok(UserStatus::away),
            "user_offline" => Ok(UserStatus::user_offline),
            "iota_offline" => Ok(UserStatus::iota_offline),
            _ => Err(format!("Invalid user status: {}", status_str)),
        }
    }
}
