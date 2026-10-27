use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Hash, PartialEq, Eq)]
enum PressureKey {
    Account(i64),
    Source(Option<IpAddr>),
}

pub struct PasswordAdmission {
    slots: Arc<Semaphore>,
    pressure: Mutex<HashMap<PressureKey, (Instant, u32)>>,
}

impl Default for PasswordAdmission {
    fn default() -> Self {
        let slots = std::env::var("PASSWORD_MAX_PENDING_FORWARDS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|value| (1..=1024).contains(value))
            .unwrap_or(64);
        Self {
            slots: Arc::new(Semaphore::new(slots)),
            pressure: Mutex::new(HashMap::new()),
        }
    }
}

impl PasswordAdmission {
    pub fn enter(
        &self,
        account: i64,
        source: Option<IpAddr>,
    ) -> Result<OwnedSemaphorePermit, &'static str> {
        let permit = self.pending()?;
        self.initiate(Some(account), source)?;
        Ok(permit)
    }

    pub fn pending(&self) -> Result<OwnedSemaphorePermit, &'static str> {
        self.slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| "password service busy")
    }

    pub fn initiate(
        &self,
        account: Option<i64>,
        source: Option<IpAddr>,
    ) -> Result<(), &'static str> {
        let mut pressure = self.pressure.lock().unwrap();
        let now = Instant::now();
        pressure.retain(|_, (started, _)| now.duration_since(*started) < Duration::from_secs(60));
        let keys: Vec<_> = std::iter::once((PressureKey::Source(source), 60))
            .chain(account.map(|account| (PressureKey::Account(account), 30)))
            .collect();
        let new_keys = keys
            .iter()
            .filter(|(key, _)| !pressure.contains_key(key))
            .count();
        if pressure.len().saturating_add(new_keys) > 8192
            || keys
                .iter()
                .any(|(key, limit)| pressure.get(key).is_some_and(|(_, count)| *count >= *limit))
        {
            return Err("password service busy");
        }
        for (key, _) in keys {
            pressure.entry(key).or_insert((now, 0)).1 += 1;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_pressure_preserves_capacity_for_other_accounts() {
        let admission = PasswordAdmission::default();
        for _ in 0..30 {
            drop(admission.enter(7, None).unwrap());
        }
        assert!(admission.enter(7, None).is_err());
        assert!(admission.enter(8, None).is_ok());
    }

    #[test]
    fn rejected_account_does_not_exhaust_source() {
        let admission = PasswordAdmission::default();
        for _ in 0..30 {
            drop(admission.enter(7, None).unwrap());
        }
        for _ in 0..100 {
            assert!(admission.enter(7, None).is_err());
        }
        assert!(admission.enter(8, None).is_ok());
    }

    #[test]
    fn source_and_account_thresholds_are_independent() {
        let admission = PasswordAdmission::default();
        for account in 0..60 {
            admission.initiate(Some(account), None).unwrap();
        }
        assert!(admission.initiate(Some(61), None).is_err());
        assert_eq!(admission.pressure.lock().unwrap().len(), 61);
        let admission = PasswordAdmission::default();
        for address in 0..30 {
            admission
                .initiate(Some(7), Some(IpAddr::from([127, 0, 0, address])))
                .unwrap();
        }
        assert!(
            admission
                .initiate(Some(7), Some(IpAddr::from([127, 0, 0, 31])))
                .is_err()
        );
        assert_eq!(admission.pressure.lock().unwrap().len(), 31);
    }

    #[test]
    fn full_map_allows_existing_keys_but_new_keys_are_atomic() {
        let admission = PasswordAdmission::default();
        {
            let mut pressure = admission.pressure.lock().unwrap();
            for account in 0..8191 {
                pressure.insert(PressureKey::Account(account), (Instant::now(), 0));
            }
        }
        // Two new keys cannot partially fill the remaining slot.
        assert!(admission.initiate(Some(9000), None).is_err());
        assert_eq!(admission.pressure.lock().unwrap().len(), 8191);
        admission.initiate(Some(7), None).unwrap();
        admission.initiate(Some(7), None).unwrap();
        assert!(admission.initiate(Some(9000), None).is_err());
    }

    #[test]
    fn exhausted_pending_slots_do_not_charge_pressure() {
        let admission = PasswordAdmission {
            slots: Arc::new(Semaphore::new(1)),
            pressure: Mutex::new(HashMap::new()),
        };
        let permit = admission.pending().unwrap();
        assert!(admission.enter(7, None).is_err());
        assert!(admission.pressure.lock().unwrap().is_empty());
        drop(permit);
        assert!(admission.enter(7, None).is_ok());
    }

    #[test]
    fn concurrent_admission_never_exceeds_account_limit() {
        let admission = Arc::new(PasswordAdmission::default());
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let admission = admission.clone();
                std::thread::spawn(move || {
                    (0..30)
                        .filter(|_| admission.initiate(Some(7), None).is_ok())
                        .count()
                })
            })
            .collect();
        assert_eq!(
            workers
                .into_iter()
                .map(|worker| worker.join().unwrap())
                .sum::<usize>(),
            30
        );
        assert!(admission.enter(8, None).is_ok());
    }

    #[test]
    fn expired_pressure_is_reclaimed() {
        let admission = PasswordAdmission::default();
        admission.pressure.lock().unwrap().insert(
            PressureKey::Source(None),
            (Instant::now() - Duration::from_secs(61), 60),
        );
        admission.initiate(None, None).unwrap();
        assert_eq!(
            admission.pressure.lock().unwrap()[&PressureKey::Source(None)].1,
            1
        );
    }
}
