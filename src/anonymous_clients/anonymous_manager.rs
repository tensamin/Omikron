use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use once_cell::sync::Lazy;
use rand::prelude::{IndexedRandom, RngExt};
use std::sync::Arc;

use crate::anonymous_clients::anonymous_client_connection::AnonymousClientConnection;

static ANONYMOUS_USERS: Lazy<DashMap<u64, Arc<AnonymousClientConnection>>> =
    Lazy::new(|| DashMap::new());
static ANONYMOUS_USERNAMES: Lazy<DashMap<String, u64>> = Lazy::new(|| DashMap::new());

pub fn add_anonymous_user(connection: Arc<AnonymousClientConnection>) {
    ANONYMOUS_USERS.insert(connection.get_user_id(), connection);
}

#[allow(dead_code)]
pub async fn remove_anonymous_user(user_id: u64) {
    if let Some((_, connection)) = ANONYMOUS_USERS.remove(&user_id) {
        let username = connection.get_user_name().await;
        ANONYMOUS_USERNAMES.remove_if(&username, |_, reserved_user_id| {
            *reserved_user_id == user_id
        });
    }
}

pub async fn get_anonymous_user(user_id: u64) -> Option<Arc<AnonymousClientConnection>> {
    ANONYMOUS_USERS.get(&user_id).map(|c| c.clone())
}

pub async fn get_anonymous_user_by_name(
    username: String,
) -> Option<Arc<AnonymousClientConnection>> {
    let user_id = ANONYMOUS_USERNAMES
        .get(&username.to_lowercase())?
        .value()
        .to_owned();
    get_anonymous_user(user_id).await
}

pub fn generate_username(user_id: u64) -> String {
    let adjectives = ["Swift", "Clever", "Brave", "Sneaky", "Fierce"];
    let nouns = ["Tiger", "Eagle", "Shark", "Wolf", "Dragon"];

    let mut rng = rand::rng();
    loop {
        let Some(adj) = adjectives.choose(&mut rng) else {
            continue;
        };
        let Some(noun) = nouns.choose(&mut rng) else {
            continue;
        };
        let username = format!("{}{}{}", adj, noun, rng.random_range(0..10000));
        let canonical_username = username.to_lowercase();

        if reserve_username(canonical_username, user_id) {
            return username;
        }
    }
}

fn reserve_username(username: String, user_id: u64) -> bool {
    if let Entry::Vacant(entry) = ANONYMOUS_USERNAMES.entry(username) {
        entry.insert(user_id);
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn username_reservation_is_unique() {
        let username = "anonymous-manager-reservation-test".to_string();
        assert!(reserve_username(username.clone(), 1));
        assert!(!reserve_username(username.clone(), 2));
        ANONYMOUS_USERNAMES.remove(&username);
    }
}
