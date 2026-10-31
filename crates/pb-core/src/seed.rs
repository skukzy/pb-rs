//! Default data seeding: the `settings` param row and the system collections.
//!
//! Everything except the token secrets is fixed. The oracle generates 50-char
//! `[A-Za-z0-9]` secrets per install (`security.RandomString(50)` in
//! `core/collection_model_auth_options.go`), so the seed template is stored with
//! the oracle's values and every `secret` field is replaced at seed time.

use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use serde_json::Value;

use crate::ids;

const SETTINGS: &str = include_str!("../assets/settings.json");
const COLLECTIONS: &str = include_str!("../assets/system_collections.json");

/// Length of the per-install token secrets (`security.RandomString(50)`).
const SECRET_LENGTH: usize = 50;

/// Collection option objects that carry a generated `secret`.
const SECRET_OPTIONS: &[&str] = &[
    "authToken",
    "passwordResetToken",
    "emailChangeToken",
    "verificationToken",
    "fileToken",
];

/// Seed a freshly migrated database. Existing rows are never overwritten.
pub fn seed(conn: &Connection) -> Result<()> {
    seed_settings(conn)?;
    seed_collections(conn)?;
    Ok(())
}

fn seed_settings(conn: &Connection) -> Result<()> {
    let exists: i64 = conn.query_row(
        "SELECT count(*) FROM _params WHERE id = 'settings'",
        [],
        |row| row.get(0),
    )?;
    if exists > 0 {
        return Ok(());
    }
    // The oracle stores compact JSON. `preserve_order` keeps the key order of
    // the recorded seed instead of sorting it.
    //
    // `_params.value` is a BLOB in an oracle-created database (Go binds
    // `types.JSONRaw`, a `[]byte`), so bind bytes here too: the storage class is
    // part of what a drop-in replacement must reproduce.
    let settings: Value = serde_json::from_str(SETTINGS).context("parse settings seed")?;
    let json = serde_json::to_vec(&settings)?;
    conn.execute(
        "INSERT INTO _params (id, value) VALUES ('settings', ?1)",
        [json],
    )
    .context("seed settings param")?;
    Ok(())
}

fn seed_collections(conn: &Connection) -> Result<()> {
    let mut collections: Vec<Value> =
        serde_json::from_str(COLLECTIONS).context("parse system collections template")?;

    for collection in &mut collections {
        let name = collection["name"]
            .as_str()
            .context("system collection without a name")?
            .to_string();
        let id = collection["id"]
            .as_str()
            .context("system collection without an id")?;

        // A system collection is identified by its id. The non-system `users`
        // collection may have been renamed while keeping `_pb_users_auth_`;
        // the oracle does not recreate it in that case, and inserting it again
        // would trip the `_collections.id` primary key. The name is checked too
        // because collection names are application-unique.
        let exists: i64 = conn.query_row(
            "SELECT count(*) FROM _collections WHERE id = ?1 OR name = ?2",
            params![id, &name],
            |row| row.get(0),
        )?;
        if exists > 0 {
            continue;
        }

        refresh_secrets(collection);

        let rules = |key: &str| -> Option<String> {
            match collection.get(key) {
                Some(Value::String(s)) => Some(s.clone()),
                _ => None,
            }
        };

        // `system` may arrive as a JSON bool or as SQLite's 1/0 integer.
        let system = match &collection["system"] {
            Value::Bool(b) => *b,
            Value::Number(n) => n.as_i64().unwrap_or(0) != 0,
            _ => false,
        };

        conn.execute(
            "INSERT INTO _collections
                (id, system, type, name, fields, indexes,
                 listRule, viewRule, createRule, updateRule, deleteRule, options)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                collection["id"].as_str(),
                system,
                collection["type"].as_str(),
                name,
                collection["fields"].to_string(),
                collection["indexes"].to_string(),
                rules("listRule"),
                rules("viewRule"),
                rules("createRule"),
                rules("updateRule"),
                rules("deleteRule"),
                collection["options"].to_string(),
            ],
        )
        .with_context(|| format!("seed system collection {name}"))?;
    }

    Ok(())
}

fn refresh_secrets(collection: &mut Value) {
    let Some(options) = collection.get_mut("options").and_then(Value::as_object_mut) else {
        return;
    };
    for key in SECRET_OPTIONS {
        if let Some(token) = options.get_mut(*key).and_then(Value::as_object_mut) {
            token.insert("secret".into(), Value::String(ids::random_string(SECRET_LENGTH)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations;

    fn fresh() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        migrations::migrate_data(&conn).unwrap();
        seed(&conn).unwrap();
        conn
    }

    #[test]
    fn seeds_six_system_collections() {
        let conn = fresh();
        let count: i64 = conn
            .query_row("SELECT count(*) FROM _collections", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 6);
    }

    #[test]
    fn secrets_are_regenerated_not_copied() {
        let conn = fresh();
        let options: String = conn
            .query_row(
                "SELECT options FROM _collections WHERE name = 'users'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let v: Value = serde_json::from_str(&options).unwrap();
        let secret = v["authToken"]["secret"].as_str().unwrap();
        assert_eq!(secret.len(), SECRET_LENGTH);
        assert!(secret.chars().all(|c| c.is_ascii_alphanumeric()));
        assert_ne!(
            secret,
            "0".repeat(SECRET_LENGTH),
            "the seed template's placeholder secret must be replaced"
        );
    }

    #[test]
    fn settings_are_stored_as_a_blob_like_the_oracle() {
        let conn = fresh();
        let ty: String = conn
            .query_row(
                "SELECT typeof(value) FROM _params WHERE id = 'settings'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(ty, "blob");
    }

    #[test]
    fn seeding_is_idempotent() {
        let conn = fresh();
        seed(&conn).unwrap();
        let count: i64 = conn
            .query_row("SELECT count(*) FROM _collections", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 6);
    }

    #[test]
    fn renamed_users_collection_is_not_reseeded() {
        // The default `users` collection is not `system`, so it can be renamed
        // while keeping `_pb_users_auth_`. Restoring such a backup used to
        // fail with "UNIQUE constraint failed: _collections.id".
        let conn = fresh();
        conn.execute(
            "UPDATE _collections SET name = 'members' WHERE id = '_pb_users_auth_'",
            [],
        )
        .unwrap();

        seed(&conn).unwrap();

        let name: String = conn
            .query_row(
                "SELECT name FROM _collections WHERE id = '_pb_users_auth_'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(name, "members");
        let users: i64 = conn
            .query_row(
                "SELECT count(*) FROM _collections WHERE name = 'users'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(users, 0);
        let count: i64 = conn
            .query_row("SELECT count(*) FROM _collections", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 6);
    }

    #[test]
    fn an_existing_name_blocks_reseeding_that_collection() {
        // Same name, different id: `_collections.name` is UNIQUE, so seed must
        // not attempt the insert.
        let conn = fresh();
        conn.execute(
            "DELETE FROM _collections WHERE id = '_pb_users_auth_'",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO _collections (id, type, name) VALUES ('custom_users_id', 'auth', 'users')",
            [],
        )
        .unwrap();

        seed(&conn).unwrap();

        let count: i64 = conn
            .query_row("SELECT count(*) FROM _collections WHERE name = 'users'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(count, 1);
    }
}
