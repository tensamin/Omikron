use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tokio::sync::watch;
use uuid::Uuid;

#[derive(Default)]
struct State {
    pauses: usize,
    active: HashMap<Uuid, watch::Sender<bool>>,
}

pub(super) struct NativeForwarding {
    state: Mutex<State>,
    changed: watch::Sender<u64>,
}

impl Default for NativeForwarding {
    fn default() -> Self {
        Self {
            state: Mutex::new(State::default()),
            changed: watch::channel(0).0,
        }
    }
}

impl NativeForwarding {
    pub fn begin(self: &Arc<Self>, nonce: Uuid) -> Option<Forward> {
        let mut state = self.state.lock().expect("native forwarding lock poisoned");
        if state.pauses != 0 || state.active.contains_key(&nonce) {
            return None;
        }
        let (cancel, cancellation) = watch::channel(false);
        state.active.insert(nonce, cancel);
        Some(Forward {
            owner: self.clone(),
            nonce,
            cancellation,
        })
    }

    /// Pause admission synchronously while the routing mutation lock is held.
    /// Wait for exact remote revocation outside that global lock.
    pub fn pause(self: &Arc<Self>) -> Pause {
        let mut state = self.state.lock().expect("native forwarding lock poisoned");
        state.pauses += 1;
        for cancel in state.active.values() {
            cancel.send_replace(true);
        }
        Pause {
            owner: self.clone(),
        }
    }
}

pub(super) struct Forward {
    owner: Arc<NativeForwarding>,
    nonce: Uuid,
    pub cancellation: watch::Receiver<bool>,
}

impl Drop for Forward {
    fn drop(&mut self) {
        self.owner
            .state
            .lock()
            .expect("native forwarding lock poisoned")
            .active
            .remove(&self.nonce);
        self.owner
            .changed
            .send_modify(|sequence| *sequence = sequence.wrapping_add(1));
    }
}

pub(super) struct Pause {
    owner: Arc<NativeForwarding>,
}

impl Pause {
    pub async fn wait(&self) {
        let mut changed = self.owner.changed.subscribe();
        loop {
            if self
                .owner
                .state
                .lock()
                .expect("native forwarding lock poisoned")
                .active
                .is_empty()
            {
                return;
            }
            if changed.changed().await.is_err() {
                return;
            }
        }
    }
}

impl Drop for Pause {
    fn drop(&mut self) {
        self.owner
            .state
            .lock()
            .expect("native forwarding lock poisoned")
            .pauses -= 1;
    }
}
