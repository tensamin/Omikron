use std::sync::atomic::{AtomicU32, Ordering};

// Call lookups have their own correlation namespace, independent of timestamps.
static NEXT_CALL_LOOKUP_ID: AtomicU32 = AtomicU32::new(1);

pub(crate) fn next_call_lookup_id() -> u32 {
    let mut current = NEXT_CALL_LOOKUP_ID.load(Ordering::Relaxed);
    loop {
        let next = current.checked_add(1).unwrap_or(1);
        match NEXT_CALL_LOOKUP_ID.compare_exchange_weak(
            current,
            next,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return next,
            Err(observed) => current = observed,
        }
    }
}
