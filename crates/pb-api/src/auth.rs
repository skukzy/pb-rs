//! Request authentication: token extraction, record resolution and the
//! `RequireSuperuserAuth` guard.
//!
//! Mirrors `apis/middlewares.go` + `core.FindAuthRecordByToken`: the token is
//! parsed *unverified* first to learn which collection/record it belongs to, and
//! only then is the signature checked against `tokenKey + token secret`.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use axum::http::HeaderMap;
use pb_core::collections::Collection;
use pb_core::records::Record;
use pb_core::tokens;
use rusqlite::Connection;

use crate::error::ApiError;

/// Everything a handler needs about the authenticated record.
#[derive(Clone, Debug)]
pub struct AuthContext {
    pub record: Record,
    pub collection: Collection,
}

impl AuthContext {
    pub fn is_superuser(&self) -> bool {
        self.collection.name == pb_core::superusers::COLLECTION_NAME_SUPERUSERS
    }
}

/// A small pool of SQLite connections so that concurrent requests are not
/// serialized on a single `Mutex<Connection>` (the main latency bottleneck
/// versus the Go oracle, which uses `database/sql`'s connection pool).
#[derive(Clone)]
pub struct Db {
    path: std::sync::Arc<PathBuf>,
    pool: Arc<Mutex<Vec<Connection>>>,
}

impl Db {
    pub fn open(path: &Path, size: usize) -> anyhow::Result<Self> {
        let mut conns = Vec::with_capacity(size.max(1));
        for _ in 0..size.max(1) {
            conns.push(pb_core::db::open(path)?);
        }
        Ok(Self {
            path: std::sync::Arc::from(path.to_path_buf()),
            pool: Arc::new(Mutex::new(conns)),
        })
    }

    /// Check out one connection. The connection is returned to the pool when
    /// the guard is dropped.
    pub fn lock(&self) -> Result<PooledConn, ()> {
        let mut guard = self.pool.lock().map_err(|_| ())?;
        let conn = if let Some(c) = guard.pop() {
            c
        } else {
            drop(guard);
            // Pool exhausted: open a fresh connection on demand.
            pb_core::db::open(&self.path).map_err(|_| ())?
        };
        Ok(PooledConn {
            pool: self.pool.clone(),
            conn: Some(conn),
        })
    }
}

pub struct PooledConn {
    pool: Arc<Mutex<Vec<Connection>>>,
    conn: Option<Connection>,
}

impl Drop for PooledConn {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            if let Ok(mut guard) = self.pool.lock() {
                guard.push(conn);
            }
        }
    }
}

impl std::ops::Deref for PooledConn {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        self.conn.as_ref().expect("pooled connection present")
    }
}

impl std::ops::DerefMut for PooledConn {
    fn deref_mut(&mut self) -> &mut Connection {
        self.conn.as_mut().expect("pooled connection present")
    }
}

/// `getAuthTokenFromRequest`: the raw header, with an optional `Bearer ` prefix.
pub fn token_from_headers(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(axum::http::header::AUTHORIZATION)?.to_str().ok()?;
    if raw.is_empty() {
        return None;
    }
    if raw.len() > 7 && raw[..7].eq_ignore_ascii_case("Bearer ") {
        return Some(raw[7..].to_string());
    }
    Some(raw.to_string())
}

/// Resolve the auth record for a request, if any.
///
/// Invalid, expired or unknown tokens are silently ignored — exactly like the
/// `loadAuthToken` middleware, which leaves `e.Auth` nil so that individual
/// handlers can decide how to respond.
pub fn load_auth(db: &Db, headers: &HeaderMap) -> Option<AuthContext> {
    let token = token_from_headers(headers)?;
    let conn = db.lock().ok()?;
    find_auth_record(&conn, &token, &[tokens::TYPE_AUTH]).ok()
}

/// `FindAuthRecordByToken`.
pub fn find_auth_record(
    conn: &Connection,
    token: &str,
    valid_types: &[&str],
) -> anyhow::Result<AuthContext> {
    let claims = tokens::parse_unverified(token)?;

    if claims.id.is_empty() || claims.collection_id.is_empty() || claims.kind.is_empty() {
        anyhow::bail!("missing or invalid token claims");
    }
    if !valid_types.is_empty() && !valid_types.contains(&claims.kind.as_str()) {
        anyhow::bail!("invalid token type");
    }

    let collection = Collection::find(conn, &claims.collection_id)?
        .ok_or_else(|| anyhow::anyhow!("collection not found"))?;
    if !collection.is_auth() {
        anyhow::bail!("the token is not associated to an auth collection record");
    }

    let record = Record::find_by_id(conn, &collection, &claims.id)?
        .ok_or_else(|| anyhow::anyhow!("record not found"))?;

    let secret = match claims.kind.as_str() {
        tokens::TYPE_AUTH => collection.token_secret("authToken"),
        tokens::TYPE_FILE => collection.token_secret("fileToken"),
        tokens::TYPE_VERIFICATION => collection.token_secret("verificationToken"),
        tokens::TYPE_PASSWORD_RESET => collection.token_secret("passwordResetToken"),
        tokens::TYPE_EMAIL_CHANGE => collection.token_secret("emailChangeToken"),
        other => anyhow::bail!("unknown token type {other}"),
    }
    .ok_or_else(|| anyhow::anyhow!("missing signing key"))?;

    let key = tokens::signing_key(record.token_key(), secret);
    tokens::parse_jwt(token, &key)?;

    Ok(AuthContext {
        record,
        collection,
    })
}

/// `RequireSuperuserAuth`.
pub fn require_superuser(db: &Db, headers: &HeaderMap) -> Result<AuthContext, ApiError> {
    let auth = load_auth(db, headers).ok_or_else(|| {
        ApiError::unauthorized("The request requires valid record authorization token.")
    })?;
    if !auth.is_superuser() {
        return Err(ApiError::forbidden(
            "The authorized record is not allowed to perform this action.",
        ));
    }
    Ok(auth)
}
