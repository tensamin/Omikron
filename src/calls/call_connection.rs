// part of calls or in your ws-server file

use std::sync::Arc;

use futures::{SinkExt, StreamExt, channel::mpsc::UnboundedSender, lock::Mutex};
use json::JsonValue;
use tokio::sync::mpsc::unbounded_channel;
use tungstenite::{Message, Utf8Bytes};
use uuid::Uuid;

use crate::{
    calls::{call_group::CallGroup, call_group::Caller, call_manager::CallManagerState},
    data::communication::{CommunicationType, CommunicationValue, DataTypes},
};

pub async fn handle_connection(
    raw_stream: tokio::net::TcpStream,
    state: Arc<Mutex<CallManagerState>>,
) {
    let ws_stream = tokio_tungstenite::accept_async(raw_stream)
        .await
        .expect("Error during the websocket handshake");

    let (mut outgoing, mut incoming) = ws_stream.split();

    // We create a channel so other parts can send to this client
    pub type Tx = UnboundedSender<Utf8Bytes>;
    let (tx, mut rx): (_, _) = unbounded_channel();

    // Spawn a task to forward from rx → outgoing
    let mut outgoing_clone = outgoing;
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let _ = outgoing_clone
                .send(tokio_tungstenite::tungstenite::Message::Text(msg))
                .await;
        }
    });

    // Each connection will track its user_id, call_group, etc.
    let mut maybe_user_id: Option<Uuid> = None;
    let mut maybe_call_id: Option<Uuid> = None;

    while let Some(msg) = incoming.next().await {
        let msg = match msg {
            Ok(m) => m,
            Err(_) => break,
        };
        if let tokio_tungstenite::tungstenite::Message::Text(s) = msg {
            // parse CommunicationValue
            if let mut cv = CommunicationValue::from_json(&s) {
                match cv.comm_type {
                    CommunicationType::identification => {
                        // extract fields
                        let user_str = cv.get_data(DataTypes::user_id).unwrap().as_str().unwrap();
                        let call_str = cv.get_data(DataTypes::call_id).unwrap().as_str().unwrap();
                        let _secret_sha = cv
                            .get_data(DataTypes::call_secret_sha)
                            .unwrap()
                            .as_str()
                            .unwrap();

                        let user_id = Uuid::parse_str(user_str).ok();
                        let call_id = Uuid::parse_str(call_str).ok();
                        if let (Some(uid), Some(cid)) = (user_id, call_id) {
                            maybe_user_id = Some(uid);
                            maybe_call_id = Some(cid);
                            // Add to call group
                            let mut st = state.lock().await;
                            let group = state.lock().await.get_or_create_group(cid, &_secret_sha);
                            group.clone().add_member(uid, tx.clone());

                            // Response: identification_response plus states
                            let mut response =
                                CommunicationValue::new(CommunicationType::identification_response)
                                    .with_id(cv.get_id().clone());
                            // build user states
                            let mut users = JsonValue::new_object();
                            for c in group.callers.values() {
                                let mut user_info = JsonValue::new_object();
                                user_info.insert("state", JsonValue::from("muted".to_string()));
                                user_info.insert("streaming", JsonValue::from(false));
                                users.insert(&c.user_id.to_string(), JsonValue::from(user_info));
                            }
                            response = response.add_data(DataTypes::about, JsonValue::from(users));
                            // send back
                            let _ = tx.send(Utf8Bytes::from(response.to_json().to_string()));
                        }
                    }

                    CommunicationType::ping => {
                        // optionally parse LAST_PING
                        // reply with PONG with same message_id
                        let mut resp = CommunicationValue::new(CommunicationType::pong)
                            .with_id(cv.get_id().clone());
                        let _ = tx.send(Utf8Bytes::from(resp.to_json().to_string()));
                    }

                    CommunicationType::client_changed => {
                        match (maybe_user_id, cv.get_data(DataTypes::call_state)) {
                            (Some(uid), Some(JsonValue::String(state_str))) => {
                                if let Some(cid) = maybe_call_id {
                                    {
                                        let mut st = state.lock().await;
                                        if let Some(group) = st.call_groups.get_mut(&cid) {
                                            if let Some(caller) = group.caller_state_mut(&uid) {
                                                caller_state_change(caller, &state_str);
                                            }
                                            let mut bc = cv.clone();
                                            bc = bc.add_data(
                                                DataTypes::sender_id,
                                                JsonValue::String(uid.to_string()),
                                            );
                                            group.broadcast(&bc.to_json().to_string());
                                        }
                                    }
                                }
                            }
                            _ => (),
                        }
                    }

                    CommunicationType::start_stream | CommunicationType::end_stream => {
                        if let Some(uid) = maybe_user_id {
                            if let Some(cid) = maybe_call_id {
                                let mut st = state.lock().await;
                                if let Some(group) = st.call_groups.get_mut(&cid) {
                                    if let Some(caller) = group.caller_state_mut(&uid) {
                                        let streaming =
                                            cv.comm_type == CommunicationType::start_stream;
                                        // set streaming
                                        // caller.streaming = streaming;  // if you store streaming
                                    }
                                    let mut bc = cv.clone();
                                    bc = bc.add_data(
                                        DataTypes::sender_id,
                                        JsonValue::String(uid.to_string()),
                                    );
                                    group.broadcast(&bc.to_json().to_string());
                                }
                            }
                        }
                    }

                    CommunicationType::webrtc_sdp
                    | CommunicationType::webrtc_ice
                    | CommunicationType::watch_stream => {
                        if let Some(uid) = maybe_user_id {
                            if let Some(JsonValue::String(receiver_str)) =
                                cv.get_data(DataTypes::receiver_id)
                            {
                                if let Ok(receiver_id) = Uuid::parse_str(&receiver_str) {
                                    if let Some(cid) = maybe_call_id {
                                        let mut st = state.lock().await;
                                        if let Some(group) = st.call_groups.get(&cid) {
                                            let mut bc = cv.clone();
                                            bc = bc.add_data(
                                                DataTypes::sender_id,
                                                JsonValue::String(uid.to_string()),
                                            );
                                            group.send_to(&receiver_id, &bc.to_json().to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }

                    _ => {
                        // other types you may handle
                    }
                }
            }
        }
    }

    // on close / disconnection:
    if let (Some(uid), Some(cid)) = (maybe_user_id, maybe_call_id) {
        let mut st = state.lock().await;
        if let Some(group) = st.call_groups.get_mut(&cid) {
            group.remove_member(&uid);
        }
        st.remove_inactive();
    }
}

fn caller_state_change(_caller: &mut Caller, _state_str: &str) {
    // parse and set your enum, e.g. match _state_str { "active" => ..., etc. }
}
