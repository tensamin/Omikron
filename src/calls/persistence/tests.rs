use super::*;

#[test]
fn legacy_reservations_keep_their_original_identity_and_expiry() {
    let persistence = CallPersistence::open(Path::new(":memory:")).unwrap();
    let id = Uuid::new_v4();
    persistence.db.lock().unwrap().execute("INSERT INTO active_calls(id,owner,created_at_ms,empty_since_ms) VALUES (?1,7,-1,120000)", [id.to_string()]).unwrap();
    let reservations = persistence.restore_reservations(100_000).unwrap();
    assert_eq!(reservations.len(), 1);
    assert_eq!(reservations[0].id, id);
    assert_eq!(reservations[0].owner, 7);
    assert_eq!(reservations[0].created_at_ms, 90_000);
    assert_eq!(reservations[0].expires_at_ms, 120_000);
    assert!(
        persistence
            .restore_reservations(120_000)
            .unwrap()
            .is_empty()
    );
    assert!(persistence.restore(100_000, 100_000).unwrap().is_empty());
}

#[test]
fn corrupt_signed_legacy_identities_never_become_unsigned_principals() {
    for (table, column) in [
        ("active_calls", "owner"),
        ("call_members", "user_id"),
        ("call_invites", "user_id"),
        ("call_invites", "inviter_id"),
    ] {
        for invalid in [-1, 0] {
            let persistence = CallPersistence::open(Path::new(":memory:")).unwrap();
            let id = Uuid::new_v4().to_string();
            {
                let db = persistence.db.lock().unwrap();
                db.execute(
                    "INSERT INTO active_calls(id,owner,created_at_ms) VALUES (?1,1,99999)",
                    [&id],
                )
                .unwrap();
                db.execute(
                    "INSERT INTO call_members(call_id,user_id,role) VALUES (?1,1,1)",
                    [&id],
                )
                .unwrap();
                db.execute("INSERT INTO call_invites(call_id,user_id,inviter_id,created_at_ms) VALUES (?1,2,1,99999)", [&id]).unwrap();
                db.execute(&format!("UPDATE {table} SET {column}=?1"), [invalid])
                    .unwrap();
            }
            assert!(
                persistence.restore(100_000, 100_000).is_err(),
                "{table}.{column}={invalid}"
            );
        }
    }
    let persistence = CallPersistence::open(Path::new(":memory:")).unwrap();
    persistence.db.lock().unwrap().execute("INSERT INTO active_calls(id,owner,created_at_ms,empty_since_ms) VALUES (?1,-1,-1,120000)", [Uuid::new_v4().to_string()]).unwrap();
    assert!(persistence.restore_reservations(100_000).is_err());
}

#[test]
fn unknown_legacy_roles_block_migration_instead_of_granting_membership() {
    let persistence = CallPersistence::open(Path::new(":memory:")).unwrap();
    let id = Uuid::new_v4().to_string();
    {
        let db = persistence.db.lock().unwrap();
        db.execute(
            "INSERT INTO active_calls(id,owner,created_at_ms) VALUES(?1,1,99999)",
            [&id],
        )
        .unwrap();
        db.execute(
            "INSERT INTO call_members(call_id,user_id,role) VALUES(?1,1,2)",
            [&id],
        )
        .unwrap();
    }
    assert!(persistence.restore(100_000, 100_000).is_err());
}
