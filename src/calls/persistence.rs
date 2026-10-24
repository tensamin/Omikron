//! Read-only policy import from the pre-Tau tables. Managed calls never write them.
use super::call_group::{CallMember, CallRole, PendingCallInvite};
use rusqlite::Connection;
use std::{path::Path, sync::Mutex, time::Duration};
use uuid::Uuid;

pub struct CallPersistence {
    db: Mutex<Connection>,
}

pub struct RestoredCall {
    pub id: Uuid,
    pub owner: u64,
    pub created_at_ms: i64,
    pub members: Vec<CallMember>,
    pub invites: Vec<(u64, PendingCallInvite)>,
}

pub struct RestoredReservation {
    pub id: Uuid,
    pub owner: u64,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
}

fn positive_id(row: &rusqlite::Row<'_>, index: usize) -> Result<u64, rusqlite::Error> {
    let value: i64 = row.get(index)?;
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(rusqlite::Error::InvalidQuery)
}

impl CallPersistence {
    pub fn open(path: &Path) -> Result<Self, rusqlite::Error> {
        let db = Connection::open(path)?;
        db.busy_timeout(Duration::from_secs(5))?;
        db.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
             CREATE TABLE IF NOT EXISTS active_calls (id TEXT PRIMARY KEY, owner INTEGER NOT NULL, created_at_ms INTEGER NOT NULL, empty_since_ms INTEGER);
             CREATE TABLE IF NOT EXISTS call_members (call_id TEXT NOT NULL, user_id INTEGER NOT NULL, role INTEGER NOT NULL, timeout_until_ms INTEGER, PRIMARY KEY(call_id, user_id));
             CREATE TABLE IF NOT EXISTS call_invites (call_id TEXT NOT NULL, user_id INTEGER NOT NULL, inviter_id INTEGER NOT NULL, created_at_ms INTEGER NOT NULL, PRIMARY KEY(call_id, user_id));",
        )?;
        for (table, name, declaration) in [
            (
                "active_calls",
                "anonymous_joining",
                "INTEGER NOT NULL DEFAULT 0",
            ),
            ("active_calls", "short_link", "TEXT"),
            (
                "call_members",
                "participating",
                "INTEGER NOT NULL DEFAULT 0",
            ),
        ] {
            if !db
                .prepare(&format!(
                    "SELECT 1 FROM pragma_table_info('{table}') WHERE name = ?1"
                ))?
                .exists([name])?
            {
                db.execute_batch(&format!(
                    "ALTER TABLE {table} ADD COLUMN {name} {declaration}"
                ))?;
            }
        }
        Ok(Self { db: Mutex::new(db) })
    }

    pub fn restore(&self, now: i64, max_age_ms: i64) -> Result<Vec<RestoredCall>, rusqlite::Error> {
        let db = self.db.lock().map_err(|_| rusqlite::Error::InvalidQuery)?;
        // Old anonymous pointers remain in the source table, but cannot grant
        // access without a new scoped guest capability.
        let mut stmt = db.prepare("SELECT id, owner, created_at_ms FROM active_calls WHERE created_at_ms >= 0 AND created_at_ms > ?1")?;
        let calls = stmt
            .query_map([now.saturating_sub(max_age_ms)], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    positive_id(row, 1)?,
                    row.get::<_, i64>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        calls.into_iter().map(|(id, owner, created_at_ms)| {
            let members = db.prepare("SELECT user_id, role, timeout_until_ms, participating FROM call_members WHERE call_id = ?1 ORDER BY user_id")?
                .query_map([&id], |row| Ok(CallMember { user_id: positive_id(row, 0)?,
                    role: match row.get::<_, i64>(1)? {0=>CallRole::Member,1=>CallRole::Admin,_=>return Err(rusqlite::Error::InvalidQuery)},
                    timeout_until_ms: row.get(2)?, participating: row.get(3)? }))?.collect::<Result<Vec<_>, _>>()?;
            let invites = db.prepare("SELECT user_id, inviter_id, created_at_ms FROM call_invites WHERE call_id = ?1")?
                .query_map([&id], |row| Ok((positive_id(row, 0)?, PendingCallInvite {
                    inviter_id: positive_id(row, 1)?, created_at_ms: row.get(2)? })))?.collect::<Result<Vec<_>, _>>()?;
            Ok(RestoredCall { id: Uuid::parse_str(&id).map_err(|_| rusqlite::Error::InvalidQuery)?,
                owner, created_at_ms, members, invites })
        }).collect()
    }

    pub fn restore_reservations(
        &self,
        now: i64,
    ) -> Result<Vec<RestoredReservation>, rusqlite::Error> {
        let db = self.db.lock().map_err(|_| rusqlite::Error::InvalidQuery)?;
        let mut statement = db.prepare("SELECT id,owner,empty_since_ms FROM active_calls WHERE created_at_ms=-1 AND empty_since_ms>?1 ORDER BY id")?;
        statement
            .query_map([now], |row| {
                let id: String = row.get(0)?;
                let expires_at_ms: i64 = row.get(2)?;
                // The old schema used a fixed 30-second reservation TTL.
                let created_at_ms = expires_at_ms
                    .checked_sub(30_000)
                    .filter(|value| *value >= 0)
                    .ok_or(rusqlite::Error::InvalidQuery)?;
                Ok(RestoredReservation {
                    id: Uuid::parse_str(&id).map_err(|_| rusqlite::Error::InvalidQuery)?,
                    owner: positive_id(row, 1)?,
                    created_at_ms,
                    expires_at_ms,
                })
            })?
            .collect()
    }
}

#[cfg(test)]
mod tests;
