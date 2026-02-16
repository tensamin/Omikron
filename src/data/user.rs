use strum::IntoEnumIterator;
use strum_macros::EnumIter;

#[derive(Debug, Clone, PartialEq, EnumIter, Eq)]
#[allow(unused, non_camel_case_types)]
pub enum UserStatus {
    user_offline,
    user_online,
    user_dnd,
    user_idle,
    user_wc,
    user_borked,
    iota_offline,
    iota_online,
    iota_borked,
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
