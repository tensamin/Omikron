use std::sync::Arc;

use dashmap::DashMap;
use once_cell::sync::Lazy;

use crate::anonymous_clients::anonymous_client_connection::AnonymousClientConnection;

static ANONYMOUS_USERS: Lazy<DashMap<i64, Arc<AnonymousClientConnection>>> =
    Lazy::new(|| DashMap::new());

pub async fn add_anonymous_user(connection: Arc<AnonymousClientConnection>) {
    ANONYMOUS_USERS.insert(connection.get_user_id().await, connection);
}

pub async fn remove_anonymous_user(user_id: i64) {
    ANONYMOUS_USERS.remove(&user_id);
}

pub async fn get_anonymous_user(user_id: i64) -> Option<Arc<AnonymousClientConnection>> {
    ANONYMOUS_USERS.get(&user_id).map(|c| c.clone())
}

pub async fn get_anonymous_user_by_name(
    username: String,
) -> Option<Arc<AnonymousClientConnection>> {
    for user_conn in ANONYMOUS_USERS
        .iter()
        .map(|ref_multi| ref_multi.value().clone())
    {
        if user_conn.get_user_name().await == username {
            return Some(user_conn);
        }
    }

    return None;
}
