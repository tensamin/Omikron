use crate::calls::call_group::CallGroup;
use futures::lock::Mutex; // Used only to protect CallGroup contents
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock; // Used to protect the global HashMap
use uuid::Uuid;

// FIX 1: Simplify the global state. Only use RwLock to protect the HashMap.
// The inner Arc<Mutex<CallGroup>> protects the contents of each group.
pub static CALL_GROUPS: Lazy<RwLock<HashMap<Uuid, Arc<Mutex<CallGroup>>>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

/// Retrieves a CallGroup by ID, if it exists.
pub async fn get_group(call_id: Uuid) -> Option<Arc<Mutex<CallGroup>>> {
    // Acquire read lock (very fast, non-blocking for other readers)
    CALL_GROUPS
        .read()
        .await
        .get(&call_id) // Use get(), as we only need to clone the Arc
        .cloned()
}

/// Retrieves an existing group or creates a new one, performing a secret check.
pub async fn get_or_create_group(call_id: Uuid, secret: &str) -> Option<Arc<Mutex<CallGroup>>> {
    // Phase 1: Check existence under a READ lock.
    {
        let groups = CALL_GROUPS.read().await;
        if let Some(group_arc) = groups.get(&call_id) {
            // Found it. Release the global READ lock and check the secret.
            // This await on the group's lock only blocks access to that *specific* group.
            let group_lock = group_arc.lock().await;
            if group_lock.secret_hash.eq(secret) {
                return Some(group_arc.clone());
            } else {
                return None; // Secret mismatch
            }
        }
    } // READ lock automatically released here.

    // Phase 2: Not found, acquire a WRITE lock to create (only held for insertion).
    let mut groups = CALL_GROUPS.write().await;

    // FIX 2: Double-check (race condition prevention) - A group might have been created
    // between the read lock release and the write lock acquisition.
    if let Some(group_arc) = groups.get(&call_id) {
        // Already created by another task, check secret again.
        let group_lock = group_arc.lock().await;
        if group_lock.secret_hash.eq(secret) {
            return Some(group_arc.clone());
        } else {
            return None;
        }
    }

    // Still not found, proceed with creation.
    let new_group = Arc::new(Mutex::new(CallGroup::new(secret.to_string())));
    groups.insert(call_id, new_group.clone());

    // WRITE lock automatically released here.
    Some(new_group)
}

/// Removes inactive groups.
pub async fn remove_inactive() {
    // Collect keys to remove under a read lock first.
    let groups_to_check: Vec<Uuid> = CALL_GROUPS.read().await.keys().cloned().collect();

    let mut rem = Vec::new();
    for call_id in groups_to_check {
        // Retrieve the group Arc outside the global lock
        if let Some(group_arc) = get_group(call_id).await {
            // FIX 3: Check for emptiness outside the global lock
            if group_arc.lock().await.is_empty().await {
                rem.push(call_id);
            }
        }
    }

    // Acquire write lock only to perform the removals.
    if !rem.is_empty() {
        let mut groups = CALL_GROUPS.write().await;
        for call_id in rem {
            groups.remove(&call_id);
        }
    }
}
