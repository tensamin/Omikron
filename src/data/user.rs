use strum::IntoEnumIterator;
use strum_macros::EnumIter;

#[derive(Debug, Clone, PartialEq, EnumIter, Eq)]
#[allow(unused)]
pub enum UserStatus {
    Online,
    PhoneOnline,
    Away,
    DoNotDisturb,
    UserOffline,
    IotaOffline,
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
