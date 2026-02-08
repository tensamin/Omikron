use json::number::Number;
use json::{Array, JsonValue, object, parse};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use strum::IntoEnumIterator;
use strum_macros::EnumIter;
use uuid::Uuid;

#[derive(Eq, Hash, PartialEq, EnumIter, Clone, Debug)]
#[allow(non_camel_case_types, dead_code)]
pub enum DataTypes {
    error_type,
    accepted_ids,
    uuid,
    register_id,

    link,

    settings,
    settings_name,
    chat_partner_id,
    chat_partner_name,
    iota_id,
    user_id,
    user_ids,
    iota_ids,
    user_state,
    user_states,
    user_pings,
    call_state,
    screen_share,
    private_key_hash,
    accepted,
    accepted_profiles,
    denied_profiles,
    content,
    messages,
    notifications,
    send_time,
    get_time,
    get_variant,
    shared_secret_own,
    shared_secret_other,
    shared_secret_sign,
    shared_secret,
    call_id,
    call_token,
    untill,
    enabled,
    start_date,
    end_date,
    receiver_id,
    sender_id,
    signature,
    signed,
    message,
    message_state,
    last_ping,
    ping_iota,
    ping_clients,
    matches,
    omikron,
    offset,
    amount,
    position,
    name,
    path,
    codec,
    function,
    payload,
    result,
    interactables,
    want_to_watch,
    watcher,
    created_at,
    username,
    display,
    avatar,
    about,
    status,
    public_key,
    sub_level,
    sub_end,
    community_address,
    challenge,
    community_title,
    communities,
    rho_connections,
    user,
    online_status,
    omikron_id,
    omikron_connections,
    reset_token,
    new_token,
}

impl DataTypes {
    pub fn parse(p0: String) -> DataTypes {
        for datatype in DataTypes::iter() {
            if datatype.to_string().to_lowercase().replace('_', "")
                == p0.to_lowercase().replace('_', "")
            {
                return datatype;
            }
        }
        DataTypes::error_type
    }
    pub fn to_string(&self) -> String {
        return format!("{:?}", self);
    }
}

#[derive(PartialEq, Clone, EnumIter, Debug)]
#[allow(non_camel_case_types, dead_code)]
pub enum CommunicationType {
    error,
    error_anonymous,
    error_internal,
    error_invalid_data,
    error_invalid_user_id,
    error_invalid_omikron_id,
    error_not_found,
    error_not_authenticated,
    error_no_iota,
    error_invalid_challenge,
    error_invalid_secret,
    error_invalid_private_key,
    error_invalid_public_key,
    error_no_user_id,
    error_no_call_id,
    error_invalid_call_id,
    success,

    shorten_link,

    settings_save,
    settings_load,
    settings_list,
    message,
    message_state,
    message_send,
    message_live,
    message_other_iota,
    message_chunk,
    messages_get,

    push_notification,
    read_notification,
    get_notifications,

    change_confirm,
    confirm_receive,
    confirm_read,
    get_chats,
    get_states,
    add_community,
    remove_community,
    get_communities,
    challenge,
    challenge_response,
    register,
    register_response,
    identification,
    identification_response,
    register_iota,
    register_iota_success,
    ping,
    pong,
    add_conversation,
    send_chat,
    client_changed,
    client_connected,
    client_disconnected,
    client_closed,
    public_key,
    private_key,
    webrtc_sdp,
    webrtc_ice,
    start_stream,
    end_stream,
    watch_stream,
    call_token,
    call_invite,
    call_disconnect_user,
    call_timeout_user,
    call_set_anonymous_joining,
    end_call,
    function,
    update,
    create_user,
    rho_update,

    user_connected,
    user_disconnected,
    iota_connected,
    iota_disconnected,
    sync_client_iota_status,

    get_user_data,
    get_iota_data,
    iota_user_data,

    change_user_data,
    change_iota_data,

    get_register,
    complete_register_user,
    complete_register_iota,
    delete_user,
    delete_iota,

    start_register,
    complete_register,
}
impl CommunicationType {
    pub fn parse(p0: String) -> CommunicationType {
        for datatype in CommunicationType::iter() {
            if datatype.to_string().to_lowercase().replace('_', "")
                == p0.to_lowercase().replace('_', "")
            {
                return datatype;
            }
        }
        CommunicationType::error
    }
    pub fn to_string(&self) -> String {
        return format!("{:?}", self);
    }
}

#[derive(Debug, Clone)]
pub struct CommunicationValue {
    id: Uuid,
    comm_type: CommunicationType,
    sender: i64,
    receiver: i64,
    data: HashMap<DataTypes, JsonValue>,
}

#[allow(dead_code)]
impl CommunicationValue {
    pub fn new(comm_type: CommunicationType) -> Self {
        Self {
            id: Uuid::new_v4(),
            comm_type,
            sender: 0,
            receiver: 0,
            data: HashMap::new(),
        }
    }
    pub fn with_id(mut self, p0: Uuid) -> Self {
        self.id = p0;
        self
    }
    pub fn get_id(&self) -> Uuid {
        self.id.clone()
    }
    pub fn with_sender(mut self, sender: i64) -> Self {
        self.sender = sender;
        self
    }
    pub fn get_sender(&self) -> i64 {
        self.sender.clone()
    }
    pub fn with_receiver(mut self, receiver: i64) -> Self {
        self.receiver = receiver;
        self
    }
    pub fn get_receiver(&self) -> i64 {
        self.receiver.clone()
    }
    pub fn add_data_num(mut self, key: DataTypes, value: Number) -> Self {
        self.data.insert(key, JsonValue::Number(value));
        self
    }
    pub fn add_data_str(mut self, key: DataTypes, value: String) -> Self {
        self.data.insert(key, JsonValue::String(value));
        self
    }
    pub fn add_data(mut self, key: DataTypes, value: JsonValue) -> Self {
        self.data.insert(key, value);
        self
    }
    pub fn add_array(mut self, key: DataTypes, value: Array) -> Self {
        self.data.insert(key, JsonValue::Array(value));
        self
    }
    pub fn get_data(&self, key: DataTypes) -> Option<&JsonValue> {
        self.data.get(&key)
    }

    pub fn get_type(&self) -> CommunicationType {
        self.comm_type.clone()
    }
    pub fn is_type(&self, p0: CommunicationType) -> bool {
        self.comm_type == p0
    }
    pub fn to_json(&self) -> JsonValue {
        let mut jdata = object! {};
        for (k, v) in &self.data {
            jdata[&format!("{:?}", k)] = JsonValue::from(v.clone());
        }
        if self.sender > 0 && self.receiver > 0 {
            object! {
                id: self.id.to_string(),
                type: format!("{:?}", self.comm_type),
                sender: self.sender,
                receiver: self.receiver,
                data: jdata
            }
        } else if self.sender > 0 {
            object! {
                id: self.id.to_string(),
                type: format!("{:?}", self.comm_type),
                sender: self.sender,
                data: jdata
            }
        } else if self.receiver > 0 {
            object! {
                id: self.id.to_string(),
                type: format!("{:?}", self.comm_type),
                receiver: self.receiver,
                data: jdata
            }
        } else {
            object! {
                id: self.id.to_string(),
                type: format!("{:?}", self.comm_type),
                data: jdata
            }
        }
    }

    pub fn from_json(json_str: &str) -> Self {
        if let Ok(parsed) = parse(json_str) {
            let comm_type = CommunicationType::parse(parsed["type"].to_string());
            let mut sender: i64 = 0;
            if parsed.has_key("sender") {
                sender = parsed["sender"].as_i64().unwrap_or(0);
            }
            let mut receiver: i64 = 0;
            if parsed.has_key("receiver") {
                receiver = parsed["receiver"].as_i64().unwrap_or(0);
            }

            let uuid =
                Uuid::parse_str(parsed["id"].as_str().unwrap_or("")).unwrap_or(Uuid::new_v4());
            let mut data = HashMap::new();
            if parsed["data"].is_object() {
                for (k, v) in parsed["data"].entries() {
                    data.insert(DataTypes::parse(k.to_string()), v.clone());
                }
            }

            Self {
                id: uuid,
                comm_type,
                sender,
                receiver,
                data,
            }
        } else {
            Self {
                id: Uuid::new_v4(),
                comm_type: CommunicationType::error,
                sender: 0,
                receiver: 0,
                data: HashMap::new(),
            }
        }
    }
    pub fn forward_to_other_iota(original: &mut CommunicationValue) -> CommunicationValue {
        let receiver = original
            .get_data(DataTypes::receiver_id)
            .unwrap_or(&JsonValue::Number(Number::from(0)))
            .as_i64()
            .unwrap_or(0);

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        let sender = original.get_sender();
        CommunicationValue::new(CommunicationType::message_other_iota)
            .with_id(original.get_id())
            .with_receiver(receiver)
            .add_data(
                DataTypes::receiver_id,
                JsonValue::Number(Number::from(receiver)),
            )
            .with_sender(sender)
            .add_data(DataTypes::send_time, JsonValue::String(now_ms.to_string()))
            .add_data(
                DataTypes::sender_id,
                JsonValue::Number(Number::from(sender)),
            )
            .add_data(
                DataTypes::content,
                JsonValue::String(original.get_data(DataTypes::content).unwrap().to_string()),
            )
    }
}
