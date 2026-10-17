//! Write-ahead evidence for remote mutations. An ambiguous send is never retried
//! automatically: Omega correlation IDs do not provide durable idempotency.
use std::path::Path;

use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use rusqlite::{Connection, OptionalExtension, params};
use uuid::Uuid;

pub(crate) struct MutationJournal(Connection);

impl MutationJournal {
    pub(crate) fn unresolved(&self) -> Result<usize, String> {
        self.0
            .query_row(
                "SELECT count(*) FROM omega_mutations WHERE response IS NULL",
                [],
                |row| row.get(0),
            )
            .map_err(|e| e.to_string())
    }
    pub(crate) fn open(path: &Path) -> Result<Self, String> {
        let mut options = std::fs::OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(path).map_err(|e| e.to_string())?;
        let connection = Connection::open(path).map_err(|e| e.to_string())?;
        connection
            .busy_timeout(std::time::Duration::from_millis(100))
            .map_err(|e| e.to_string())?;
        connection
            .execute_batch(
                "PRAGMA synchronous=FULL;
             CREATE TABLE IF NOT EXISTS omega_mutations (
                 operation_id TEXT PRIMARY KEY,
                 request BLOB NOT NULL,
                 response BLOB,
                 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
             );
             CREATE UNIQUE INDEX IF NOT EXISTS omega_mutations_unresolved
                 ON omega_mutations(request) WHERE response IS NULL;
             CREATE TABLE IF NOT EXISTS omega_mutation_context (
                 operation_id TEXT PRIMARY KEY,
                 routing_generation INTEGER
             );
             CREATE TABLE IF NOT EXISTS omega_local_publications (
                 operation_id TEXT PRIMARY KEY,
                 stage TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS omega_mutation_observations (
                 operation_id TEXT PRIMARY KEY,
                 response BLOB NOT NULL
             );",
            )
            .map_err(|e| e.to_string())?;
        Ok(Self(connection))
    }

    pub(crate) fn begin(
        &self,
        request: &CommunicationValue,
        service: &str,
        generation: Option<u64>,
    ) -> Result<String, String> {
        let evidence = frame_evidence(request, service)?;
        let transaction = self
            .0
            .unchecked_transaction()
            .map_err(|error| error.to_string())?;
        let id = self.begin_record(&evidence)?;
        self.0.execute(
            "INSERT INTO omega_mutation_context(operation_id, routing_generation) VALUES (?1, ?2)",
            params![id, generation],
        ).map_err(|error| error.to_string())?;
        if request.is_type(CommunicationType::RedeemUserInvitation) && service == "omega" {
            self.mark_publication(&id, "awaiting_response")?;
        }
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(id)
    }

    pub(crate) fn lookup_redemption(
        &self,
        request: &CommunicationValue,
    ) -> Result<Option<String>, String> {
        let evidence = frame_evidence(request, "omega")?;
        self.0
            .query_row(
                "SELECT m.operation_id FROM omega_mutations m
             JOIN omega_local_publications p ON p.operation_id = m.operation_id
             WHERE m.request = ?1 AND p.stage != 'rejected' ORDER BY m.rowid DESC LIMIT 1",
                [&evidence],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())
    }

    pub(crate) fn lookup_attempt(
        &self,
        request: &CommunicationValue,
        service: &str,
        include_completed: bool,
    ) -> Result<Option<String>, String> {
        let evidence = frame_evidence(request, service)?;
        self.0
            .query_row(
                "SELECT operation_id FROM omega_mutations
                 WHERE request = ?1 AND (?2 OR response IS NULL) ORDER BY rowid DESC LIMIT 1",
                params![evidence, include_completed],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())
    }

    pub(crate) fn mark_publication(&self, id: &str, stage: &str) -> Result<(), String> {
        self.0
            .execute(
                "INSERT INTO omega_local_publications(operation_id, stage) VALUES (?1, ?2)
             ON CONFLICT(operation_id) DO UPDATE SET stage = excluded.stage",
                params![id, stage],
            )
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    pub(crate) fn begin_record(&self, bytes: &[u8]) -> Result<String, String> {
        let existing: Option<String> = self
            .0
            .query_row(
                "SELECT operation_id FROM omega_mutations WHERE request = ?1 AND response IS NULL",
                [&bytes],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        if let Some(id) = existing {
            return Err(format!(
                "Remote operation {id} has an uncertain outcome; reconcile before retrying"
            ));
        }
        let id = Uuid::new_v4().to_string();
        self.0
            .execute(
                "INSERT INTO omega_mutations(operation_id, request) VALUES (?1, ?2)",
                params![id, bytes],
            )
            .map_err(|e| e.to_string())?;
        Ok(id)
    }

    pub(crate) fn resolve(&self, id: &str, response: &CommunicationValue) -> Result<(), String> {
        let bytes = frame_evidence(response, "response")?;
        let transaction = self
            .0
            .unchecked_transaction()
            .map_err(|error| error.to_string())?;
        if response.is_type(CommunicationType::ErrorInternal) {
            // A generic server failure does not prove that its mutation rolled
            // back. Keep the intent unresolved and retain redacted observations.
            self.0.execute(
                "INSERT INTO omega_mutation_observations(operation_id, response) VALUES (?1, ?2)
                 ON CONFLICT(operation_id) DO UPDATE SET response = excluded.response",
                params![id, bytes],
            ).map_err(|error| error.to_string())?;
            self.0
                .execute(
                    "UPDATE omega_mutations SET response = NULL WHERE operation_id = ?1",
                    [id],
                )
                .map_err(|error| error.to_string())?;
            return transaction.commit().map_err(|error| error.to_string());
        }
        self.resolve_record(id, &bytes)?;
        self.0
            .execute(
                "UPDATE omega_local_publications SET stage = ?2 WHERE operation_id = ?1",
                params![
                    id,
                    if response
                        .get_comm_type_enum()
                        .is_some_and(tau::is_protocol_error)
                    {
                        "rejected"
                    } else {
                        "remote_completed"
                    }
                ],
            )
            .map_err(|error| error.to_string())?;
        transaction.commit().map_err(|error| error.to_string())
    }

    pub(crate) fn resolve_record(&self, id: &str, bytes: &[u8]) -> Result<(), String> {
        self.0
            .execute(
                "UPDATE omega_mutations SET response = ?2 WHERE operation_id = ?1",
                params![id, bytes],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}

fn frame_evidence(request: &CommunicationValue, service: &str) -> Result<Vec<u8>, String> {
    // Never persist challenges, credentials, opaque authentication messages or
    // private application payloads. Canonical fingerprints detect exact retries.
    let mut payload = request.payload().clone();
    canonicalize_fields(&mut payload);
    let bytes = request
        .clone()
        .with_id(1)
        .with_payload(payload)
        .to_bytes()
        .map_err(|error| error.to_string())?;
    let application_id = request
        .get_data(DataType::Uuid)
        .and_then(DataValue::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
        .map(|id| id.to_string());
    let number = |kind| {
        request
            .get_data(kind)
            .and_then(DataValue::as_number)
            .map(|id| id.to_string())
    };
    serde_json::to_vec(&serde_json::json!({
        "service": service,
        "type": request.get_type().0,
        "fingerprint": mtp::crypto::sha256(&bytes),
        "application_id": application_id,
        "sender": request.sender(),
        "receiver": request.receiver(),
        "user_id": number(DataType::UserId),
        "iota_id": number(DataType::IotaId),
        "invitation_id": number(DataType::InvitationId),
    }))
    .map_err(|error| error.to_string())
}

pub(crate) fn mutation_recovery_report() -> Result<(usize, usize), String> {
    let path = std::env::var("OMEGA_MUTATION_DB_PATH")
        .unwrap_or_else(|_| "omega-mutations.sqlite3".into());
    let path = Path::new(&path);
    if !path.try_exists().map_err(|e| e.to_string())? {
        return Ok((0, 0));
    }
    let journal = MutationJournal::open(path)?;
    let local = journal.0.query_row(
        "SELECT count(*) FROM omega_local_publications WHERE stage IN ('remote_completed', 'pending')",
        [], |row| row.get(0),
    ).map_err(|error| error.to_string())?;
    Ok((journal.unresolved()?, local))
}

pub(crate) fn mutation_journal_path() -> std::path::PathBuf {
    if let Some(path) = std::env::var_os("OMEGA_MUTATION_DB_PATH") {
        return path.into();
    }
    #[cfg(test)]
    return std::env::temp_dir().join(format!("remote-mutations-{}.sqlite3", Uuid::new_v4()));
    #[cfg(not(test))]
    std::path::PathBuf::from("omega-mutations.sqlite3")
}

// Container field order is not operation identity. Preserve array ordering and
// opaque signed/encrypted values while normalizing clear structured fields.
fn canonicalize_fields(value: &mut DataValue) {
    match value {
        DataValue::Container(fields) => {
            fields.sort_by_key(|(kind, _)| kind.0);
            for (_, value) in fields {
                canonicalize_fields(value);
            }
        }
        DataValue::Array(values) => {
            for value in values {
                canonicalize_fields(value);
            }
        }
        _ => {}
    }
}

pub(super) fn requires_reconciliation(value: &CommunicationValue) -> bool {
    matches!(
        value.get_comm_type_enum(),
        Some(
            CommunicationType::CompleteRegisterIota
                | CommunicationType::CompleteRegisterUser
                | CommunicationType::ChangeUserData
                | CommunicationType::ShortenLink
                | CommunicationType::ReadNotification
                | CommunicationType::PushNotification
                | CommunicationType::EraseHostedUserDataAck
                | CommunicationType::Relay
                | CommunicationType::RedeemUserInvitation
                | CommunicationType::CreateUserInvitation
                | CommunicationType::RevokeUserInvitation
                | CommunicationType::AttachUserComplete
                | CommunicationType::DeleteUserCredentialComplete
                | CommunicationType::AcknowledgeIotaUserProvision
                | CommunicationType::ReleaseUserFromIota
                | CommunicationType::DeleteUser
                | CommunicationType::DeleteIota
        )
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_error_preserves_uncertainty_until_authoritative_reconciliation() {
        let path = std::env::temp_dir().join(format!("omega-journal-{}.sqlite3", Uuid::new_v4()));
        let request = CommunicationValue::new(CommunicationType::RedeemUserInvitation);
        let journal = MutationJournal::open(&path).unwrap();
        let id = journal.begin(&request, "omega", None).unwrap();
        journal
            .resolve(
                &id,
                &CommunicationValue::new(CommunicationType::ErrorInternal).add_typed_default(
                    DataType::ErrorType,
                    DataValue::Str("private-server-detail".into()),
                ),
            )
            .unwrap();
        assert_eq!(journal.unresolved().unwrap(), 1);
        assert_eq!(
            journal.lookup_redemption(&request).unwrap(),
            Some(id.clone())
        );
        let observation: Vec<u8> = journal
            .0
            .query_row(
                "SELECT response FROM omega_mutation_observations WHERE operation_id = ?1",
                [&id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            !String::from_utf8(observation)
                .unwrap()
                .contains("private-server-detail")
        );
        drop(journal);
        let journal = MutationJournal::open(&path).unwrap();
        assert!(journal.begin(&request, "omega", None).is_err());
        journal
            .resolve(
                &id,
                &CommunicationValue::new(CommunicationType::RedeemUserInvitation),
            )
            .unwrap();
        assert_eq!(journal.unresolved().unwrap(), 0);
        drop(journal);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn intent_and_context_commit_together_before_any_send() {
        let path = std::env::temp_dir().join(format!("omega-journal-{}.sqlite3", Uuid::new_v4()));
        let journal = MutationJournal::open(&path).unwrap();
        journal
            .0
            .execute_batch(
                "CREATE TRIGGER reject_context BEFORE INSERT ON omega_mutation_context
             BEGIN SELECT RAISE(ABORT, 'context unavailable'); END;",
            )
            .unwrap();
        let request = CommunicationValue::new(CommunicationType::RedeemUserInvitation);
        assert!(journal.begin(&request, "omega", Some(1)).is_err());
        assert_eq!(journal.unresolved().unwrap(), 0);
        drop(journal);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn remote_response_local_publication_and_delivery_are_separate_milestones() {
        let path = std::env::temp_dir().join(format!("omega-journal-{}.sqlite3", Uuid::new_v4()));
        let request = CommunicationValue::new(CommunicationType::RedeemUserInvitation);
        let journal = MutationJournal::open(&path).unwrap();
        let id = journal.begin(&request, "omega", None).unwrap();
        drop(journal);
        let journal = MutationJournal::open(&path).unwrap();
        assert_eq!(
            journal.lookup_redemption(&request).unwrap(),
            Some(id.clone())
        );
        journal
            .resolve(
                &id,
                &CommunicationValue::new(CommunicationType::RedeemUserInvitation),
            )
            .unwrap();
        let stage = || -> String {
            journal
                .0
                .query_row(
                    "SELECT stage FROM omega_local_publications WHERE operation_id = ?1",
                    [&id],
                    |row| row.get(0),
                )
                .unwrap()
        };
        assert_eq!(stage(), "remote_completed");
        journal.mark_publication(&id, "pending").unwrap();
        assert_eq!(stage(), "pending");
        journal.mark_publication(&id, "activated").unwrap();
        assert_eq!(stage(), "activated");
        assert_eq!(journal.lookup_redemption(&request).unwrap(), Some(id));
        drop(journal);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn private_frames_are_fingerprinted_and_generation_does_not_change_identity() {
        let path = std::env::temp_dir().join(format!("omega-journal-{}.sqlite3", Uuid::new_v4()));
        let journal = MutationJournal::open(&path).unwrap();
        let application_id = Uuid::new_v4().to_string();
        let request = CommunicationValue::new(CommunicationType::PasswordEnrollmentFinish)
            .with_sender(7)
            .add_typed_default(DataType::Uuid, DataValue::Str(application_id.clone()))
            .add_typed_default(
                DataType::OpaqueMessage,
                DataValue::Bytes(b"private-credential-material".to_vec()),
            );
        let id = journal.begin(&request, "iota:2", Some(3)).unwrap();
        assert!(
            journal
                .begin(&request.clone().with_id(99), "iota:2", Some(4))
                .unwrap_err()
                .contains(&id)
        );
        let response = CommunicationValue::new(CommunicationType::Success).add_typed_default(
            DataType::OpaqueMessage,
            DataValue::Bytes(b"private-response-material".to_vec()),
        );
        journal.resolve(&id, &response).unwrap();
        let (request, response): (Vec<u8>, Vec<u8>) = journal
            .0
            .query_row(
                "SELECT request, response FROM omega_mutations WHERE operation_id = ?1",
                [&id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let request = String::from_utf8(request).unwrap();
        let response = String::from_utf8(response).unwrap();
        assert!(request.contains(&application_id));
        assert!(request.contains("fingerprint"));
        assert!(!request.contains("private-credential-material"));
        assert!(!response.contains("private-response-material"));
        let generation: u64 = journal
            .0
            .query_row(
                "SELECT routing_generation FROM omega_mutation_context WHERE operation_id = ?1",
                [&id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(generation, 3);
        drop(journal);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn uncertain_outcomes_survive_restart_and_ignore_transport_ids() {
        let path = std::env::temp_dir().join(format!("omega-journal-{}.sqlite3", Uuid::new_v4()));
        let request = CommunicationValue::new(CommunicationType::CompleteRegisterIota).with_id(12);
        let journal = MutationJournal::open(&path).unwrap();
        let id = journal.begin(&request, "omega", None).unwrap();
        assert_eq!(journal.unresolved().unwrap(), 1);
        drop(journal);
        let journal = MutationJournal::open(&path).unwrap();
        assert!(
            journal
                .begin(&request.clone().with_id(13), "omega", None)
                .unwrap_err()
                .contains(&id)
        );
        journal
            .resolve(&id, &CommunicationValue::new(CommunicationType::Success))
            .unwrap();
        assert_eq!(journal.unresolved().unwrap(), 0);
        assert_ne!(journal.begin(&request, "omega", None).unwrap(), id);
        drop(journal);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn reordered_fields_cannot_retry_an_uncertain_mutation() {
        use mtp::codec::DataType;
        let path = std::env::temp_dir().join(format!("omega-journal-{}.sqlite3", Uuid::new_v4()));
        let journal = MutationJournal::open(&path).unwrap();
        let request = CommunicationValue::new(CommunicationType::RedeemUserInvitation)
            .add_typed_default(DataType::InvitationId, DataValue::SignedNumber(7))
            .add_typed_default(DataType::IotaId, DataValue::SignedNumber(2));
        let id = journal.begin(&request, "omega", None).unwrap();
        let reordered = CommunicationValue::new(CommunicationType::RedeemUserInvitation)
            .add_typed_default(DataType::IotaId, DataValue::SignedNumber(2))
            .add_typed_default(DataType::InvitationId, DataValue::SignedNumber(7));
        assert!(
            journal
                .begin(&reordered, "omega", None)
                .unwrap_err()
                .contains(&id)
        );
        assert_eq!(journal.unresolved().unwrap(), 1);
        drop(journal);
        std::fs::remove_file(path).unwrap();
    }
}
