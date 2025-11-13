use json::number::Number;
use json::{Array, JsonValue, object, parse};
use std::collections::HashMap;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Eq, Hash, PartialEq, Clone, Debug)]
#[allow(non_camel_case_types, dead_code)]
pub enum DataTypes {
    error_type,
    accepted_ids,
    uuid,
    chat_partner_id,
    iota_id,
    user_id,
    user_ids,
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
    call_name,
    call_secret_sha,
    call_secret,
    shared_call_secret,
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
}

impl DataTypes {
    pub fn parse(p0: String) -> DataTypes {
        // normalize: lowercase + remove underscores
        let normalized = p0.to_lowercase().replace('_', "");

        match normalized.as_str() {
            "errortype" => DataTypes::error_type,
            "chatpartnerid" => DataTypes::chat_partner_id,
            "iotaid" => DataTypes::iota_id,
            "userid" => DataTypes::user_id,
            "userids" => DataTypes::user_ids,
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
            "callname" => DataTypes::call_name,
            "callsecretsha" => DataTypes::call_secret_sha,
            "callsecret" => DataTypes::call_secret,
            "sharedcallsecret" => DataTypes::shared_call_secret,
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
            _ => DataTypes::error_type, // fallback if unknown
        }
    }
}

#[derive(PartialEq, Clone, Debug)]
#[allow(non_camel_case_types, dead_code)]
pub enum CommunicationType {
    error,
    error_invalid_user_id,
    error_not_found,
    error_no_iota,
    error_invalid_challenge,
    error_invalid_secret,
    error_invalid_private_key,
    success,
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
    ping,
    pong,
    add_chat,
    send_chat,
    iota_connected,
    iota_closed,
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
    get_call,
    new_call,
    call_invite,
    end_call,
    function,
    update,
}
impl CommunicationType {
    pub fn parse(p0: String) -> CommunicationType {
        let normalized = p0.to_lowercase().replace('_', "");

        match normalized.as_str() {
            "error" => CommunicationType::error,
            "success" => CommunicationType::success,
            "message" => CommunicationType::message,
            "messagelive" => CommunicationType::message_live,
            "messageotheriota" => CommunicationType::message_other_iota,
            "messagechunk" => CommunicationType::message_chunk,
            "messagesget" => CommunicationType::messages_get,
            "messagesend" => CommunicationType::message_send,
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
            "ping" => CommunicationType::ping,
            "pong" => CommunicationType::pong,
            "addchat" => CommunicationType::add_chat,
            "sendchat" => CommunicationType::send_chat,
            "iotaconnected" => CommunicationType::iota_connected,
            "iotaclosed" => CommunicationType::iota_closed,
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
            "watchstream" => CommunicationType::watch_stream,
            "getcall" => CommunicationType::get_call,
            "newcall" => CommunicationType::new_call,
            "callinvite" => CommunicationType::call_invite,
            "endcall" => CommunicationType::end_call,
            "function" => CommunicationType::function,
            "update" => CommunicationType::update,
            _ => CommunicationType::error,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CommunicationValue {
    pub id: Uuid,
    pub comm_type: CommunicationType,
    pub sender: Uuid,
    pub receiver: Uuid,
    pub data: HashMap<DataTypes, JsonValue>,
}

#[allow(dead_code)]
impl CommunicationValue {
    pub fn new(comm_type: CommunicationType) -> Self {
        Self {
            id: Uuid::new_v4(),
            comm_type,
            sender: Uuid::new_v4(),
            receiver: Uuid::new_v4(),
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
    pub fn with_sender(mut self, sender: Uuid) -> Self {
        self.sender = sender;
        self
    }
    pub fn get_sender(&self) -> Uuid {
        self.sender.clone()
    }
    pub fn with_receiver(mut self, receiver: Uuid) -> Self {
        self.receiver = receiver;
        self
    }
    pub fn get_receiver(&self) -> Uuid {
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

        object! {
            id: self.id.to_string(),
            type: format!("{:?}", self.comm_type),
            sender: self.sender.to_string(),
            receiver: self.receiver.to_string(),
            data: jdata
        }
    }

    pub fn from_json(json_str: &str) -> Self {
        let parsed = parse(json_str).unwrap();

        let comm_type = CommunicationType::parse(parsed["type"].to_string());

        let sender: Uuid = parsed["sender"]
            .as_str()
            .and_then(|s| Uuid::parse_str(s).ok())
            .unwrap_or(Uuid::new_v4());
        let receiver: Uuid = parsed["receiver"]
            .as_str()
            .and_then(|s| Uuid::parse_str(s).ok())
            .unwrap_or(Uuid::new_v4());

        let uuid = Uuid::parse_str(parsed["id"].as_str().unwrap_or("")).unwrap_or(Uuid::new_v4());
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
    }
    pub fn forward_to_other_iota(original: &mut CommunicationValue) -> CommunicationValue {
        let receiver = Uuid::from_str(
            &*original
                .get_data(DataTypes::receiver_id)
                .unwrap()
                .to_string(),
        )
        .ok()
        .or(Option::from(Uuid::nil()));

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        let cv = CommunicationValue::new(CommunicationType::message_other_iota)
            .with_id(original.get_id())
            .with_receiver(receiver.unwrap())
            .add_data(DataTypes::send_time, JsonValue::String(now_ms.to_string()))
            .add_data(
                DataTypes::content,
                JsonValue::String(original.get_data(DataTypes::content).unwrap().to_string()),
            );

        // include sender_id if the original had one
        let sender = original.get_sender();
        cv.add_data(DataTypes::sender_id, JsonValue::String(sender.to_string()))
    }
}
