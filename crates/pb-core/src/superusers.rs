//! Superuser bootstrap, mirroring `apis/installer.go` + `core/record_model_superusers.go`.
//!
//! On every `serve`, the oracle checks whether any superuser other than the
//! installer placeholder exists. If none does, it creates
//! `__pbinstaller@example.com` with a random password and a random `tokenKey`,
//! then hands a short-lived auth token to the installer UI. The record itself is
//! deleted as soon as a real superuser is created.
//!
//! Replicating the row matters for drop-in behaviour: without it, a port-created
//! install looks like "a superuser already exists" to the oracle and the
//! installer flow would be skipped.

use anyhow::{Context, Result};
use rusqlite::Connection;

use crate::ids;

/// `core.DefaultInstallerEmail`
pub const DEFAULT_INSTALLER_EMAIL: &str = "__pbinstaller@example.com";

/// `core.CollectionNameSuperusers`
pub const COLLECTION_NAME_SUPERUSERS: &str = "_superusers";

/// bcrypt cost used by the oracle (`$2a$10$`).
const BCRYPT_COST: u32 = 10;
/// `SetRandomPassword` uses `security.RandomString(30)`.
const RANDOM_PASSWORD_LENGTH: usize = 30;
/// The `tokenKey` field autogenerates `[a-zA-Z0-9]{50}`.
const TOKEN_KEY_LENGTH: usize = 50;

/// `needInstallerSuperuser`: true when every existing superuser is the
/// installer placeholder (or there are none at all).
pub fn needs_installer_superuser(conn: &Connection) -> Result<bool> {
    let total: i64 = conn.query_row(
        "SELECT count(*) FROM _superusers WHERE email <> ?1",
        [DEFAULT_INSTALLER_EMAIL],
        |row| row.get(0),
    )?;
    Ok(total == 0)
}

/// `findOrCreateInstallerSuperuser`. Returns `true` when a row was inserted.
pub fn ensure_installer_superuser(conn: &Connection) -> Result<bool> {
    if !needs_installer_superuser(conn)? {
        return Ok(false);
    }

    let existing: i64 = conn.query_row(
        "SELECT count(*) FROM _superusers WHERE email = ?1",
        [DEFAULT_INSTALLER_EMAIL],
        |row| row.get(0),
    )?;
    if existing > 0 {
        return Ok(false);
    }

    let password = ids::random_string(RANDOM_PASSWORD_LENGTH);
    let hash = bcrypt::hash_with_result(password, BCRYPT_COST)
        .context("hash installer password")?
        // The oracle's hashes are `$2a$` (Go's x/crypto/bcrypt); the crate
        // defaults to `$2b$`. Both verify in Go, but matching the prefix keeps
        // at-rest dumps comparable.
        .format_for_version(bcrypt::Version::TwoA);

    conn.execute(
        "INSERT INTO _superusers
            (id, email, emailVisibility, password, tokenKey, verified, created, updated)
         VALUES (?1, ?2, 0, ?3, ?4, 1,
                 strftime('%Y-%m-%d %H:%M:%fZ', 'now'),
                 strftime('%Y-%m-%d %H:%M:%fZ', 'now'))",
        rusqlite::params![
            ids::default_random_id(),
            DEFAULT_INSTALLER_EMAIL,
            hash,
            ids::random_string(TOKEN_KEY_LENGTH),
        ],
    )
    .context("create installer superuser")?;

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{migrations, seed};

    fn fresh() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        migrations::migrate_data(&conn).unwrap();
        seed::seed(&conn).unwrap();
        conn
    }

    #[test]
    fn creates_the_installer_row_once() {
        let conn = fresh();
        assert!(ensure_installer_superuser(&conn).unwrap());
        assert!(!ensure_installer_superuser(&conn).unwrap());

        let (email, verified, hash): (String, i64, String) = conn
            .query_row(
                "SELECT email, verified, password FROM _superusers",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(email, DEFAULT_INSTALLER_EMAIL);
        assert_eq!(verified, 1);
        assert!(hash.starts_with("$2a$10$"), "unexpected hash: {hash}");
    }

    #[test]
    fn skips_when_a_real_superuser_exists() {
        let conn = fresh();
        conn.execute(
            "INSERT INTO _superusers (id, email, password, tokenKey, verified)
             VALUES ('abc123456789012', 'admin@example.com', '', 'k', 1)",
            [],
        )
        .unwrap();
        assert!(!ensure_installer_superuser(&conn).unwrap());
        let count: i64 = conn
            .query_row("SELECT count(*) FROM _superusers", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }
}

// ---------------------------------------------------------------------------
// CLI operations (`pocketbase superuser ...`), mirroring `cmd/superuser.go`.
// ---------------------------------------------------------------------------

use crate::collections::Collection;
use crate::records::Record;

/// Minimal email check matching `is.EmailFormat`'s intent: a local part, an
/// `@`, and a dotted domain, with no whitespace.
pub fn is_valid_email(email: &str) -> bool {
    if email.len() > 255 || email.contains(char::is_whitespace) {
        return false;
    }
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    if local.is_empty() || domain.is_empty() || domain.contains('@') {
        return false;
    }
    let Some((host, tld)) = domain.rsplit_once('.') else {
        return false;
    };
    !host.is_empty() && tld.len() >= 2
}

fn superusers_collection(conn: &Connection) -> Result<Collection> {
    Collection::find(conn, COLLECTION_NAME_SUPERUSERS)?
        .with_context(|| format!("failed to fetch {COLLECTION_NAME_SUPERUSERS:?} collection"))
}

/// `FindAuthRecordByEmail` for the superusers collection.
pub fn find(conn: &Connection, email: &str) -> Result<Option<Record>> {
    let collection = superusers_collection(conn)?;
    Record::find_by_email(conn, &collection, email)
}

/// Create or update a superuser by email (`superuser upsert`).
pub fn upsert(conn: &Connection, email: &str, password: &str) -> Result<Record> {
    match find(conn, email)? {
        Some(existing) => {
            update_record(conn, &existing, email, password)?;
            find(conn, email)?.context("superuser vanished after update")
        }
        None => create_record(conn, email, password),
    }
}

/// `superuser create`: fails when the email is already taken.
pub fn create(conn: &Connection, email: &str, password: &str) -> Result<Record> {
    if find(conn, email)?.is_some() {
        anyhow::bail!("superuser with email {email:?} already exists");
    }
    create_record(conn, email, password)
}

/// `superuser update`: changes the password of an existing superuser.
pub fn update_password(conn: &Connection, email: &str, password: &str) -> Result<Record> {
    let existing = find(conn, email)?
        .with_context(|| format!("superuser with email {email:?} doesn't exist"))?;
    update_record(conn, &existing, email, password)?;
    find(conn, email)?.context("superuser vanished after update")
}

/// `superuser delete`: returns false when the record was already gone.
pub fn delete(conn: &Connection, email: &str) -> Result<bool> {
    let deleted = conn.execute(
        "DELETE FROM _superusers WHERE email = ?1",
        [email.to_lowercase()],
    )?;
    Ok(deleted > 0)
}

fn create_record(conn: &Connection, email: &str, password: &str) -> Result<Record> {
    let hash = bcrypt::hash_with_result(password, BCRYPT_COST)
        .context("hash password")?
        .format_for_version(bcrypt::Version::TwoA);

    conn.execute(
        "INSERT INTO _superusers
            (id, email, emailVisibility, password, tokenKey, verified, created, updated)
         VALUES (?1, ?2, 0, ?3, ?4, 1,
                 strftime('%Y-%m-%d %H:%M:%fZ', 'now'),
                 strftime('%Y-%m-%d %H:%M:%fZ', 'now'))",
        rusqlite::params![
            ids::default_random_id(),
            email.to_lowercase(),
            hash,
            ids::random_string(TOKEN_KEY_LENGTH),
        ],
    )
    .context("create superuser")?;

    // `pbSuperusersRecordSaveExec`: creating a real superuser removes the
    // installer placeholder.
    if !email.eq_ignore_ascii_case(DEFAULT_INSTALLER_EMAIL) {
        conn.execute(
            "DELETE FROM _superusers WHERE email = ?1",
            [DEFAULT_INSTALLER_EMAIL],
        )?;
    }

    find(conn, email)?.context("superuser vanished after create")
}

fn update_record(conn: &Connection, existing: &Record, email: &str, password: &str) -> Result<()> {
    let hash = bcrypt::hash_with_result(password, BCRYPT_COST)
        .context("hash password")?
        .format_for_version(bcrypt::Version::TwoA);

    // `onRecordSaveExecute`: the token key is regenerated whenever the password
    // or the email changes, which invalidates every issued token.
    let token_key = ids::random_string(TOKEN_KEY_LENGTH);

    conn.execute(
        "UPDATE _superusers
         SET email = ?1, password = ?2, tokenKey = ?3,
             updated = strftime('%Y-%m-%d %H:%M:%fZ', 'now')
         WHERE id = ?4",
        rusqlite::params![email.to_lowercase(), hash, token_key, existing.id()],
    )
    .context("update superuser")?;
    Ok(())
}
