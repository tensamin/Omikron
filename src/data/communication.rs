use json::number::Number;
use json::{Array, JsonValue, object, parse};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Eq, Hash, PartialEq, Clone, Debug)]
#[allow(non_camel_case_types, dead_code)]
pub enum DataTypes {
    error_type,
    accepted_ids,
    uuid,
    register_id,
    settings,
    settings_name,
    chat_partner_id,
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
    enable,
    start_date,
    end_date,
    receiver_id,
    sender_id,
    signature,
    signed,
    message,
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
        let normalized = p0.to_lowercase().replace('_', "");

        match normalized.as_str() {
            "errortype" => DataTypes::error_type,
            "chatpartnerid" => DataTypes::chat_partner_id,
            "registerid" => DataTypes::register_id,
            "uuid" => DataTypes::uuid,
            "settings" => DataTypes::settings,
            "settingsname" => DataTypes::settings_name,
            "iotaid" => DataTypes::iota_id,
            "userid" => DataTypes::user_id,
            "userids" => DataTypes::user_ids,
            "iotaids" => DataTypes::iota_ids,
            "userstate" => DataTypes::user_state,
            "userstates" => DataTypes::user_states,
            "userpings" => DataTypes::user_pings,
            "callstate" => DataTypes::call_state,
            "screenshare" => DataTypes::screen_share,
            "privatekeyhash" => DataTypes::private_key_hash,
            "accepted" => DataTypes::accepted,
            "acceptedprofiles" => DataTypes::accepted_profiles,
            "deniedprofiles" => DataTypes::denied_profiles,
            "content" => DataTypes::content,
            "messages" => DataTypes::messages,
            "sendtime" => DataTypes::send_time,
            "gettime" => DataTypes::get_time,
            "getvariant" => DataTypes::get_variant,
            "sharedsecretown" => DataTypes::shared_secret_own,
            "sharedsecretother" => DataTypes::shared_secret_other,
            "sharedsecretsign" => DataTypes::shared_secret_sign,
            "sharedsecret" => DataTypes::shared_secret,
            "callid" => DataTypes::call_id,
            "calltoken" => DataTypes::call_token,
            "untill" => DataTypes::untill,
            "enable" => DataTypes::enable,
            "startdate" => DataTypes::start_date,
            "enddate" => DataTypes::end_date,
            "receiverid" => DataTypes::receiver_id,
            "senderid" => DataTypes::sender_id,
            "signature" => DataTypes::signature,
            "signed" => DataTypes::signed,
            "message" => DataTypes::message,
            "lastping" => DataTypes::last_ping,
            "pingiota" => DataTypes::ping_iota,
            "pingclients" => DataTypes::ping_clients,
            "matches" => DataTypes::matches,
            "omikron" => DataTypes::omikron,
            "offset" => DataTypes::offset,
            "amount" => DataTypes::amount,
            "position" => DataTypes::position,
            "name" => DataTypes::name,
            "path" => DataTypes::path,
            "codec" => DataTypes::codec,
            "function" => DataTypes::function,
            "payload" => DataTypes::payload,
            "result" => DataTypes::result,
            "interactables" => DataTypes::interactables,
            "wanttowatch" => DataTypes::want_to_watch,
            "watcher" => DataTypes::watcher,
            "createdat" => DataTypes::created_at,
            "username" => DataTypes::username,
            "display" => DataTypes::display,
            "avatar" => DataTypes::avatar,
            "about" => DataTypes::about,
            "status" => DataTypes::status,
            "publickey" => DataTypes::public_key,
            "sublevel" => DataTypes::sub_level,
            "subend" => DataTypes::sub_end,
            "communityaddress" => DataTypes::community_address,
            "challenge" => DataTypes::challenge,
            "communitytitle" => DataTypes::community_title,
            "communities" => DataTypes::communities,
            "rhoconnections" => DataTypes::rho_connections,
            "user" => DataTypes::user,
            "onlinestatus" => DataTypes::online_status,
            "omikronid" => DataTypes::omikron_id,
            "omikronconnections" => DataTypes::omikron_connections,
            "resettoken" => DataTypes::reset_token,
            "newtoken" => DataTypes::new_token,
            _ => DataTypes::error_type, // fallback if unknown
        }
    }
}

#[derive(PartialEq, Clone, Debug)]
#[allow(non_camel_case_types, dead_code)]
pub enum CommunicationType {
    error,
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
    settings_save,
    settings_load,
    settings_list,
    message,
    message_send,
    message_live,
    message_other_iota,
    message_chunk,
    messages_get,
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
    add_chat,
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
        let normalized = p0.to_lowercase().replace('_', "");

        match normalized.as_str() {
            "watchstream" => CommunicationType::watch_stream,
            "calltoken" => CommunicationType::call_token,
            "callinvite" => CommunicationType::call_invite,
            "calldisconnectuser" => CommunicationType::call_disconnect_user,
            "calltimeoutuser" => CommunicationType::call_timeout_user,
            "callsetanonymousjoining" => CommunicationType::call_set_anonymous_joining,
            "endcall" => CommunicationType::end_call,
            "function" => CommunicationType::function,
            "update" => CommunicationType::update,
            "createuser" => CommunicationType::create_user,
            "errorinternal" => CommunicationType::error_internal,
            "errorinvaliddata" => CommunicationType::error_invalid_data,
            "errorinvaliduserid" => CommunicationType::error_invalid_user_id,
            "errorinvalidomikronid" => CommunicationType::error_invalid_omikron_id,
            "errornotfound" => CommunicationType::error_not_found,
            "errornotauthenticated" => CommunicationType::error_not_authenticated,
            "errornoiota" => CommunicationType::error_no_iota,
            "errorinvalidchallenge" => CommunicationType::error_invalid_challenge,
            "errorinvalidpublickey" => CommunicationType::error_invalid_public_key,
            "errorinvalidsecret" => CommunicationType::error_invalid_secret,
            "errorinvalidprivatekey" => CommunicationType::error_invalid_private_key,
            "errornouserid" => CommunicationType::error_no_user_id,
            "errornocallid" => CommunicationType::error_no_call_id,
            "errorinvalidcallid" => CommunicationType::error_invalid_call_id,
            "success" => CommunicationType::success,
            "settingssave" => CommunicationType::settings_save,
            "settingsload" => CommunicationType::settings_load,
            "settingslist" => CommunicationType::settings_list,
            "message" => CommunicationType::message,
            "messagesend" => CommunicationType::message_send,
            "messagelive" => CommunicationType::message_live,
            "messageotheriota" => CommunicationType::message_other_iota,
            "messagechunk" => CommunicationType::message_chunk,
            "messagesget" => CommunicationType::messages_get,
            "changeconfirm" => CommunicationType::change_confirm,
            "confirmreceive" => CommunicationType::confirm_receive,
            "confirmread" => CommunicationType::confirm_read,
            "getchats" => CommunicationType::get_chats,
            "getstates" => CommunicationType::get_states,
            "addcommunity" => CommunicationType::add_community,
            "removecommunity" => CommunicationType::remove_community,
            "getcommunities" => CommunicationType::get_communities,
            "challenge" => CommunicationType::challenge,
            "challengeresponse" => CommunicationType::challenge_response,
            "register" => CommunicationType::register,
            "registerresponse" => CommunicationType::register_response,
            "identification" => CommunicationType::identification,
            "identificationresponse" => CommunicationType::identification_response,
            "registeriota" => CommunicationType::register_iota,
            "registeriotasuccess" => CommunicationType::register_iota_success,
            "ping" => CommunicationType::ping,
            "pong" => CommunicationType::pong,
            "addchat" => CommunicationType::add_chat,
            "sendchat" => CommunicationType::send_chat,
            "clientchanged" => CommunicationType::client_changed,
            "clientconnected" => CommunicationType::client_connected,
            "clientdisconnected" => CommunicationType::client_disconnected,
            "clientclosed" => CommunicationType::client_closed,
            "publickey" => CommunicationType::public_key,
            "privatekey" => CommunicationType::private_key,
            "webrtcsdp" => CommunicationType::webrtc_sdp,
            "webrtcice" => CommunicationType::webrtc_ice,
            "startstream" => CommunicationType::start_stream,
            "endstream" => CommunicationType::end_stream,
            "rhoupdate" => CommunicationType::rho_update,

            "iotaconnected" => CommunicationType::iota_connected,
            "iotadisconnected" => CommunicationType::iota_disconnected,
            "userconnected" => CommunicationType::user_connected,
            "userdisconnected" => CommunicationType::user_disconnected,
            "syncclientiotastatus" => CommunicationType::sync_client_iota_status,

            "getuserdata" => CommunicationType::get_user_data,
            "getiotadata" => CommunicationType::get_iota_data,

            "changeuserdata" => CommunicationType::change_user_data,
            "changeiotadata" => CommunicationType::change_iota_data,

            "getregister" => CommunicationType::get_register,
            "completeregisteruser" => CommunicationType::complete_register_user,
            "completeregisteriota" => CommunicationType::complete_register_iota,
            "deleteuser" => CommunicationType::delete_user,
            "deleteiota" => CommunicationType::delete_iota,

            "startregister" => CommunicationType::start_register,
            "completeregister" => CommunicationType::complete_register,

            _ => CommunicationType::error,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CommunicationValue {
    pub id: Uuid,
    pub comm_type: CommunicationType,
    pub sender: i64,
    pub receiver: i64,
    pub data: HashMap<DataTypes, JsonValue>,
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

    pub(crate) fn is_type(&self, p0: CommunicationType) -> bool {
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
