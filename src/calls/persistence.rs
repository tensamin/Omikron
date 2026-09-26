use std::{path::Path, sync::Mutex, time::Duration};

use rusqlite::{Connection, OptionalExtension, params};
use uuid::Uuid;

use super::call_group::{CallGroup, CallMember, CallRole, PendingCallInvite};

pub struct CallPersistence {
    db: Mutex<Connection>,
}

pub struct RestoredCall {
    pub id: Uuid,
    pub owner: u64,
    pub created_at_ms: i64,
    pub anonymous_joining: bool,
    pub short_link: Option<String>,
    pub members: Vec<CallMember>,
    pub invites: Vec<(u64, PendingCallInvite)>,
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
        if !db
            .prepare(
                "SELECT 1 FROM pragma_table_info('active_calls') WHERE name = 'anonymous_joining'",
            )?
            .exists([])?
        {
            db.execute_batch(
                "ALTER TABLE active_calls ADD COLUMN anonymous_joining INTEGER NOT NULL DEFAULT 0",
            )?;
        }
        if !db
            .prepare("SELECT 1 FROM pragma_table_info('active_calls') WHERE name = 'short_link'")?
            .exists([])?
        {
            db.execute_batch("ALTER TABLE active_calls ADD COLUMN short_link TEXT")?;
        }
        if !db
            .prepare(
                "SELECT 1 FROM pragma_table_info('call_members') WHERE name = 'participating'",
            )?
            .exists([])?
        {
            db.execute_batch(
                "ALTER TABLE call_members ADD COLUMN participating INTEGER NOT NULL DEFAULT 0",
            )?;
        }
        Ok(Self { db: Mutex::new(db) })
    }

    pub fn reserve(&self, id: Uuid, owner: u64, until: i64) -> Result<bool, rusqlite::Error> {
        let db = self.db.lock().unwrap();
        db.execute(
            "DELETE FROM active_calls WHERE created_at_ms < 0 AND empty_since_ms <= ?1",
            [until - 30_000],
        )?;
        db.execute(
            "INSERT OR IGNORE INTO active_calls (id, owner, created_at_ms, empty_since_ms) VALUES (?1, ?2, -1, ?3)",
            params![id.to_string(), owner as i64, until],
        ).map(|rows| rows == 1)
    }

    /*
     * The `owner` column holds the creator's user ID: it authorizes activation
     * of a reservation and is not the owning Omikron (this database belongs to
     * exactly one Omikron).
     */
    pub fn activate(&self, group: &CallGroup, creator: u64) -> Result<bool, rusqlite::Error> {
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction()?;
        let rows = tx.execute("UPDATE active_calls SET created_at_ms = ?2, empty_since_ms = ?3 WHERE id = ?1 AND created_at_ms = -1 AND owner = ?4", params![group.call_id.to_string(), group.created_at_ms, group.created_at_ms, creator as i64])?;
        if rows == 1 {
            let creator = group
                .state
                .try_read()
                .expect("new group state is not locked")
                .members
                .values()
                .next()
                .unwrap()
                .user_id;
            tx.execute(
                "INSERT INTO call_members (call_id, user_id, role) VALUES (?1, ?2, 1)",
                params![group.call_id.to_string(), creator as i64],
            )?;
        }
        tx.commit()?;
        Ok(rows == 1)
    }

    pub fn store_invite(
        &self,
        id: Uuid,
        user: u64,
        inviter: u64,
        created_at: i64,
    ) -> Result<(), rusqlite::Error> {
        let db = self.db.lock().unwrap();
        db.execute("INSERT INTO call_invites (call_id, user_id, inviter_id, created_at_ms) VALUES (?1, ?2, ?3, ?4) ON CONFLICT(call_id, user_id) DO UPDATE SET inviter_id=excluded.inviter_id", params![id.to_string(), user as i64, inviter as i64, created_at])?;
        Ok(())
    }

    pub fn accept(&self, id: Uuid, user: u64) -> Result<(), rusqlite::Error> {
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction()?;
        let deleted = tx.execute(
            "DELETE FROM call_invites WHERE call_id = ?1 AND user_id = ?2",
            params![id.to_string(), user as i64],
        )?;
        if deleted != 1 {
            return Err(rusqlite::Error::QueryReturnedNoRows);
        }
        tx.execute(
            "INSERT OR IGNORE INTO call_members (call_id, user_id, role) VALUES (?1, ?2, 0)",
            params![id.to_string(), user as i64],
        )?;
        tx.commit()
    }

    pub fn revoke(&self, id: Uuid, user: u64) -> Result<(), rusqlite::Error> {
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction()?;
        tx.execute(
            "DELETE FROM call_members WHERE call_id = ?1 AND user_id = ?2",
            params![id.to_string(), user as i64],
        )?;
        tx.execute(
            "DELETE FROM call_invites WHERE call_id = ?1 AND user_id = ?2",
            params![id.to_string(), user as i64],
        )?;
        tx.commit()
    }
    pub fn set_timeout(&self, id: Uuid, user: u64, until: i64) -> Result<(), rusqlite::Error> {
        let rows = self.db.lock().unwrap().execute(
            "UPDATE call_members SET timeout_until_ms = ?3 WHERE call_id = ?1 AND user_id = ?2",
            params![id.to_string(), user as i64, until],
        )?;
        if rows == 0 {
            return Err(rusqlite::Error::QueryReturnedNoRows);
        }
        Ok(())
    }
    pub fn set_participating(
        &self,
        id: Uuid,
        user: u64,
        participating: bool,
    ) -> Result<(), rusqlite::Error> {
        self.db.lock().unwrap().execute(
            "UPDATE call_members SET participating = ?3 WHERE call_id = ?1 AND user_id = ?2",
            params![id.to_string(), user as i64, participating],
        )?;
        Ok(())
    }
    pub fn reconcile_participants(
        &self,
        id: Uuid,
        participants: &[u64],
    ) -> Result<(), rusqlite::Error> {
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction()?;
        tx.execute(
            "UPDATE call_members SET participating = 0 WHERE call_id = ?1",
            [id.to_string()],
        )?;
        for participant in participants {
            tx.execute(
                "UPDATE call_members SET participating = 1 WHERE call_id = ?1 AND user_id = ?2",
                params![id.to_string(), *participant as i64],
            )?;
        }
        tx.commit()
    }
    pub fn set_anonymous(
        &self,
        id: Uuid,
        enabled: bool,
        short_link: Option<&str>,
    ) -> Result<(), rusqlite::Error> {
        self.db.lock().unwrap().execute(
            "UPDATE active_calls SET anonymous_joining = ?2, short_link = ?3 WHERE id = ?1",
            params![id.to_string(), enabled, short_link],
        )?;
        Ok(())
    }
    pub fn transfer_admin(
        &self,
        id: Uuid,
        departing: u64,
        successor: u64,
    ) -> Result<(), rusqlite::Error> {
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction()?;
        tx.execute(
            "UPDATE call_members SET role = 0 WHERE call_id = ?1 AND user_id = ?2",
            params![id.to_string(), departing as i64],
        )?;
        tx.execute(
            "UPDATE call_members SET role = 1 WHERE call_id = ?1 AND user_id = ?2",
            params![id.to_string(), successor as i64],
        )?;
        tx.commit()
    }

    pub fn remove(&self, id: Uuid) -> Result<(), rusqlite::Error> {
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction()?;
        for table in ["call_members", "call_invites", "active_calls"] {
            tx.execute(
                &format!(
                    "DELETE FROM {table} WHERE {} = ?1",
                    if table == "active_calls" {
                        "id"
                    } else {
                        "call_id"
                    }
                ),
                [id.to_string()],
            )?;
        }
        tx.commit()
    }

    pub fn set_empty_since(&self, id: Uuid, since: Option<i64>) -> Result<(), rusqlite::Error> {
        self.db.lock().unwrap().execute(
            "UPDATE active_calls SET empty_since_ms = ?2 WHERE id = ?1",
            params![id.to_string(), since],
        )?;
        Ok(())
    }
    pub fn empty_since(&self, id: Uuid, now: i64) -> Result<i64, rusqlite::Error> {
        let db = self.db.lock().unwrap();
        db.execute(
            "UPDATE active_calls SET empty_since_ms = ?2 WHERE id = ?1 AND empty_since_ms IS NULL",
            params![id.to_string(), now],
        )?;
        db.query_row(
            "SELECT empty_since_ms FROM active_calls WHERE id = ?1",
            [id.to_string()],
            |row| row.get(0),
        )
    }

    pub fn restore(&self, now: i64) -> Result<Vec<RestoredCall>, rusqlite::Error> {
        let db = self.db.lock().unwrap();
        let mut stmt = db.prepare("SELECT id, owner, created_at_ms, anonymous_joining, short_link FROM active_calls WHERE created_at_ms >= 0 AND created_at_ms + 259200000 > ?1")?;
        let calls = stmt
            .query_map([now], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, bool>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        calls.into_iter().map(|(id, owner, created_at_ms, anonymous_joining, short_link)| {
            let members = db.prepare("SELECT user_id, role, timeout_until_ms, participating FROM call_members WHERE call_id = ?1 ORDER BY user_id")?
                .query_map([&id], |row| Ok(CallMember { user_id: row.get::<_, i64>(0)? as u64, role: if row.get::<_, i64>(1)? == 1 { CallRole::Admin } else { CallRole::Member }, timeout_until_ms: row.get(2)?, participating: row.get(3)? }))?
                .collect::<Result<Vec<_>, _>>()?;
            let invites = db.prepare("SELECT user_id, inviter_id, created_at_ms FROM call_invites WHERE call_id = ?1")?
                .query_map([&id], |row| Ok((row.get::<_, i64>(0)? as u64, PendingCallInvite { inviter_id: row.get::<_, i64>(1)? as u64, created_at_ms: row.get(2)? })))?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(RestoredCall { id: Uuid::parse_str(&id).map_err(|_| rusqlite::Error::InvalidQuery)?, owner: owner as u64, created_at_ms, anonymous_joining, short_link, members, invites })
        }).collect()
    }

    pub fn reservation_owner(&self, id: Uuid, now: i64) -> Result<Option<u64>, rusqlite::Error> {
        self.db.lock().unwrap().query_row("SELECT owner FROM active_calls WHERE id = ?1 AND created_at_ms = -1 AND empty_since_ms > ?2", params![id.to_string(), now], |row| row.get::<_, i64>(0)).optional().map(|value| value.map(|v| v as u64))
    }
    pub fn reservation_created_at(
        &self,
        id: Uuid,
        owner: u64,
        now: i64,
    ) -> Result<Option<i64>, rusqlite::Error> {
        self.db.lock().unwrap().query_row("SELECT empty_since_ms - 30000 FROM active_calls WHERE id = ?1 AND created_at_ms = -1 AND owner = ?2 AND empty_since_ms > ?3", params![id.to_string(), owner as i64, now], |row| row.get(0)).optional()
    }
}
