//! `POST /api/sql` — run a raw SQL query (superusers only).
//!
//! Mirrors `apis/sql.go`: writes run inside a transaction and report the last
//! statement's affected rows; reads return the declared column types and up to
//! 1000 rows. Values are stringified the way Go's `database/sql` scans them
//! into `*string` (null stays null, numbers become their decimal form).

use std::time::Instant;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use rusqlite::types::ValueRef;
use serde_json::{json, Map, Value};

use crate::auth::{load_auth, Db};
use crate::error::ApiError;
use pb_core::schema_sync::go_sqlite_error;

const MAX_ROWS: usize = 1000;
const MAX_QUERY_LENGTH: usize = 5000;

const WRITE_PREFIXES: &[&str] = &[
    "INSERT", "CREATE", "UPDATE", "DELETE", "DROP", "DETACH", "ALTER", "REPLACE",
];

/// `POST /api/sql`
pub async fn run(
    State(db): State<Db>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    let auth = load_auth(&db, &headers).ok_or_else(|| {
        ApiError::unauthorized("The request requires valid record authorization token.")
    })?;
    if !auth.is_superuser() {
        return Err(ApiError::forbidden(
            "The authorized record is not allowed to perform this action.",
        ));
    }

    crate::records::require_json(&headers)?;
    let form = crate::records::parse_json_body(&body)?;
    let query = match form.get("query") {
        None | Some(Value::Null) => "",
        Some(Value::String(value)) => value.as_str(),
        Some(_) => return Err(ApiError::body_load()),
    };

    if query.is_empty() {
        return Err(ApiError::validation(json!({
            "query": crate::error::validation_required()
        })));
    }
    if query.chars().count() > MAX_QUERY_LENGTH {
        return Err(ApiError::validation(json!({
            "query": {
                "code": "validation_length_too_long",
                "message": format!("the length must be no more than {MAX_QUERY_LENGTH}"),
                "params": {"max": MAX_QUERY_LENGTH, "min": 0}
            }
        })));
    }

    let start = Instant::now();
    let result = execute(&db, query)?;
    let mut result = result;
    let mut map = match result.take() {
        Value::Object(map) => map,
        other => return Ok(Json(other)),
    };
    map.insert(
        "execTime".into(),
        json!(start.elapsed().as_millis() as i64),
    );
    Ok(Json(Value::Object(map)))
}

fn execute(db: &Db, query: &str) -> Result<Value, ApiError> {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return Err(query_error("empty query"));
    }

    let upper = trimmed.to_ascii_uppercase();
    let is_write = !upper.starts_with("SELECT")
        && WRITE_PREFIXES
            .iter()
            .any(|prefix| upper.starts_with(prefix));

    let conn = db
        .lock()
        .map_err(|_| ApiError::internal("database lock poisoned"))?;

    if is_write {
        // `app.RunInTransaction`: a nested savepoint keeps the batch endpoint's
        // outer transaction intact.
        conn.execute_batch("SAVEPOINT pb_sql")
            .map_err(|e| query_error(&go_sqlite_error(&e)))?;
        let result = conn.execute_batch(trimmed);
        match result {
            Ok(()) => {
                let affected = conn.changes() as i64;
                conn.execute_batch("RELEASE pb_sql")
                    .map_err(|e| query_error(&go_sqlite_error(&e)))?;
                Ok(json!({
                    "affectedRows": affected,
                    "columns": [],
                    "rows": [],
                }))
            }
            Err(err) => {
                let _ = conn.execute_batch("ROLLBACK TO pb_sql; RELEASE pb_sql");
                Err(query_error(&go_sqlite_error(&err)))
            }
        }
    } else {
        read_query(&conn, trimmed)
    }
}

fn read_query(conn: &rusqlite::Connection, query: &str) -> Result<Value, ApiError> {
    // go-sqlite3 executes every statement in the string; only the last
    // statement's rows are exposed.
    let statements = split_statements(query);
    let Some(last) = statements.last() else {
        return Err(query_error("empty query"));
    };
    for statement in &statements[..statements.len() - 1] {
        conn.execute_batch(statement)
            .map_err(|e| query_error(&go_sqlite_error(&e)))?;
    }

    let mut stmt = conn
        .prepare(last)
        .map_err(|e| query_error(&go_sqlite_error(&e)))?;

    let columns = stmt
        .columns()
        .into_iter()
        .map(|column| {
            let declared = column.decl_type().unwrap_or("");
            json!({
                "name": column.name(),
                "type": declared,
                // `ColumnType.Nullable` is always unknown for the driver.
                "nullable": true,
            })
        })
        .collect::<Vec<_>>();

    let column_count = stmt.column_count();
    let mut rows = stmt
        .query([])
        .map_err(|e| query_error(&go_sqlite_error(&e)))?;
    let mut out: Vec<Value> = Vec::new();
    loop {
        let row = rows
            .next()
            .map_err(|e| query_error(&go_sqlite_error(&e)))?;
        let Some(row) = row else {
            break;
        };
        if out.len() >= MAX_ROWS {
            break;
        }
        let mut cells = Vec::with_capacity(column_count);
        for i in 0..column_count {
            let value = row
                .get_ref(i)
                .map_err(|e| query_error(&go_sqlite_error(&e)))?;
            cells.push(scan_string(value));
        }
        out.push(Value::Array(cells));
    }

    Ok(json!({
        "affectedRows": 0,
        "columns": columns,
        "rows": out,
    }))
}

fn scan_string(value: ValueRef<'_>) -> Value {
    match value {
        ValueRef::Null => Value::Null,
        ValueRef::Integer(value) => Value::String(value.to_string()),
        ValueRef::Real(value) => Value::String(format_float(value)),
        ValueRef::Text(bytes) => Value::String(String::from_utf8_lossy(bytes).into_owned()),
        ValueRef::Blob(bytes) => Value::String(String::from_utf8_lossy(bytes).into_owned()),
    }
}

/// `strconv.FormatFloat(v, 'g', -1, 64)` used by `database/sql` for `*string`.
fn format_float(value: f64) -> String {
    if value.is_nan() {
        return "NaN".into();
    }
    if value.is_infinite() {
        return if value.is_sign_negative() { "-Inf" } else { "+Inf" }.into();
    }
    let mut out = value.to_string();
    if let Some(index) = out.find('e') {
        let (mantissa, exp) = out.split_at(index);
        let exponent = exp[1..].trim_start_matches('+');
        let sign = if exponent.starts_with('-') { "" } else { "+" };
        out = format!("{mantissa}e{sign}{}", exponent.trim_start_matches('-'));
    }
    out
}

fn query_error(raw: &str) -> ApiError {
    ApiError::new(
        StatusCode::BAD_REQUEST,
        format!("Failed to execute query. Raw error:\n{raw}"),
        Map::new().into(),
    )
    .with_raw_data(Value::String(raw.to_string()))
}

/// Split a SQL string on top-level semicolons, ignoring quoted strings and
/// comments. This only feeds statement-by-statement execution; SQLite still
/// parses each piece.
fn split_statements(sql: &str) -> Vec<String> {
    let bytes = sql.as_bytes();
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'\'' | b'"' | b'`' => {
                let quote = bytes[i];
                i += 1;
                while i < bytes.len() {
                    if bytes[i] == quote {
                        if i + 1 < bytes.len() && bytes[i + 1] == quote {
                            i += 2;
                            continue;
                        }
                        break;
                    }
                    i += 1;
                }
            }
            b'-' if i + 1 < bytes.len() && bytes[i + 1] == b'-' => {
                i += 2;
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'*' => {
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                i += 1;
            }
            b';' => {
                let statement = sql[start..i].trim();
                if !statement.is_empty() {
                    out.push(statement.to_string());
                }
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    let tail = sql[start..].trim();
    if !tail.is_empty() {
        out.push(tail.to_string());
    }
    out
}
