use strum::IntoEnumIterator;
use strum_macros::EnumIter;

#[derive(Debug, Clone, PartialEq, EnumIter, Eq)]
#[allow(unused, non_camel_case_types)]
pub enum UserStatus {
    online,
    phone_online,
    away,
    do_not_disturb,
    user_offline,
    iota_offline,
}
#[allow(unused)]
impl UserStatus {
    pub fn to_string(&self) -> String {
        format!("{:?}", self)
    }
    pub fn from_str(s: &str) -> Option<UserStatus> {
        for sel in UserStatus::iter() {
            if &sel.to_string() == s {
                return Some(sel);
            }
        }
        None
    }
}
