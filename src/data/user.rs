#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(unused, non_camel_case_types)]
pub enum UserStatus {
    user_offline,
    user_online,
    user_dnd,
    user_idle,
    user_wc,
    user_borked,
    user_invisible,
    iota_offline,
    iota_online,
    iota_borked,
}
#[allow(unused)]
impl UserStatus {
    pub fn to_string(&self) -> String {
        format!("{:?}", self)
    }
    pub fn from_client_preference(s: &str) -> Option<Self> {
        match s {
            "user_online" => Some(Self::user_online),
            "user_idle" => Some(Self::user_idle),
            "user_dnd" => Some(Self::user_dnd),
            "user_wc" => Some(Self::user_wc),
            "user_invisible" => Some(Self::user_invisible),
            _ => None,
        }
    }

    pub fn public_value(&self) -> Self {
        match self {
            Self::user_invisible => Self::user_offline,
            value => value.clone(),
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        Self::from_client_preference(s)
    }
}

#[cfg(test)]
mod tests {
    use super::UserStatus;

    #[test]
    fn network_parser_rejects_derived_states() {
        assert_eq!(UserStatus::from_str("user_offline"), None);
        assert_eq!(UserStatus::from_str("iota_offline"), None);
        assert_eq!(
            UserStatus::from_str("user_online"),
            Some(UserStatus::user_online)
        );
    }
}
