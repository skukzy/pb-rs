//! Migration chain parity.
//!
//! The oracle records eight rows in `_migrations` for `data.db`. A port must
//! produce the same set, otherwise the Go binary would try to re-apply
//! migrations on a database created by the port (or vice versa).
//!
//! Fresh installs are created directly at the v0.40 schema shape. The historical
//! intermediate states (v0.22 -> v0.23 transformations) are not replayed; see
//! `docs/COMPATIBILITY.md` "Deliberate divergences".

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use rusqlite::Connection;

use crate::db;

/// Exact `_migrations.file` values, in application order, as observed in a
/// database created by the oracle.
pub const CHAIN: &[&str] = &[
    "1640988000_init.go",
    "1640988000_aux_init.go",
    "1717233556_v0.23_migrate.go",
    "1717233557_v0.23_migrate2.go",
    "1717233558_v0.23_migrate3.go",
    "1717233559_v0.23_migrate4.go",
    "1763020353_update_default_auth_alert_templates.go",
    "1778828400_normalize_indexes.go",
];

/// `data.db` schema at v0.40, captured from the oracle with `.schema`.
const SCHEMA: &str = include_str!("../assets/schema.sql");
/// `auxiliary.db` schema (`_logs` + indexes).
const AUX_SCHEMA: &str = include_str!("../assets/aux_schema.sql");

/// Create or upgrade the main database, returning how many migrations were
/// recorded by this call (0 for an already-current database).
pub fn migrate_data(conn: &Connection) -> Result<usize> {
    let has_migrations_table = db::table_exists(conn, "_migrations")?;

    if !has_migrations_table {
        if db::table_exists(conn, "_collections")? {
            bail!(
                "database has PocketBase tables but no _migrations table; \
                 refusing to guess the schema state"
            );
        }
        conn.execute_batch(SCHEMA)
            .context("apply v0.40 baseline schema")?;
    }

    let applied: HashSet<String> = {
        let mut stmt = conn.prepare("SELECT file FROM _migrations")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        rows.collect::<rusqlite::Result<HashSet<_>>>()?
    };

    let mut recorded = 0usize;
    for file in CHAIN {
        if applied.contains(*file) {
            continue;
        }
        conn.execute(
            "INSERT INTO _migrations (file, applied) VALUES (?1, ?2)",
            rusqlite::params![file, now_micros()],
        )
        .with_context(|| format!("record migration {file}"))?;
        recorded += 1;
    }

    Ok(recorded)
}

/// Create the auxiliary (`_logs`) database if needed.
///
/// The oracle does not track auxiliary migrations in a table; its migration is
/// idempotent (`CREATE TABLE IF NOT EXISTS`), so presence of `_logs` is enough.
pub fn migrate_aux(conn: &Connection) -> Result<bool> {
    if db::table_exists(conn, "_logs")? {
        return Ok(false);
    }
    conn.execute_batch(AUX_SCHEMA)
        .context("apply auxiliary schema")?;
    Ok(true)
}

/// `applied` is stored in microseconds, as the oracle does.
fn now_micros() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        migrate_data(&conn).unwrap();
        conn
    }

    #[test]
    fn fresh_db_records_the_full_chain() {
        let conn = fresh();
        let count: i64 = conn
            .query_row("SELECT count(*) FROM _migrations", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count as usize, CHAIN.len());
    }

    #[test]
    fn migration_is_idempotent() {
        let conn = fresh();
        assert_eq!(migrate_data(&conn).unwrap(), 0);
    }

    #[test]
    fn refuses_unknown_partial_state() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE _collections (id TEXT);").unwrap();
        assert!(migrate_data(&conn).is_err());
    }
}
