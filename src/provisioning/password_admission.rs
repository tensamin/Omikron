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
        pressure.retain(|_, (started, _)| started.elapsed() < Duration::from_secs(60));
        if pressure.len() >= 8192 {
            return Err("password service busy");
        }
        for (key, limit) in std::iter::once((PressureKey::Source(source), 60))
            .chain(account.map(|account| (PressureKey::Account(account), 30)))
        {
            let (_, count) = pressure.entry(key).or_insert((Instant::now(), 0));
            if *count >= limit {
                return Err("password service busy");
            }
            *count += 1;
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
}
