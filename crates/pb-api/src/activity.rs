//! Request activity logging (`apis/middlewares.go` + `core/log_model.go`).
//!
//! Every API request is recorded in the auxiliary database `_logs` table unless
//! the log retention is disabled (`logs.maxDays == 0`) or the route opts out of
//! successful-request logging. The oracle writes these rows from a fire-and-
//! forget goroutine; we write them synchronously after the handler returns so a
//! following request always observes a completed log row. That only affects
//! timing, not the recorded shape.

use std::net::SocketAddr;
use std::time::Instant;

use axum::body::Body;
use axum::extract::{ConnectInfo, OriginalUri, Request, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use serde_json::{json, Map, Value};

use crate::auth::{load_auth, Db};
use crate::records::AUX_DB;

/// Routes that bind `SkipSuccessActivityLog()` in the oracle.
fn skips_success_log(path: &str, method: &Method) -> bool {
    path.starts_with("/api/logs")
        || path == "/api/oauth2-redirect"
        || (path == "/api/realtime" && method == Method::GET)
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> &'a str {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
}

/// `apis.cutStr`: byte based truncation with an ellipsis.
fn cut_str(value: &str, max: usize) -> String {
    if value.len() <= max {
        return value.to_string();
    }
    let mut end = max;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &value[..end])
}

/// `url.PathUnescape`-ish decoding for the log message. Invalid escapes are
/// left untouched (the oracle falls back to the raw URI on an unescape error).
fn path_unescape(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn remote_ip(request: &Request) -> String {
    request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip().to_string())
        .unwrap_or_else(|| "127.0.0.1".to_string())
}

fn write_log(level: i64, message: &str, data: &Value) {
    let Some(aux) = AUX_DB.get().cloned() else {
        return;
    };
    let Ok(conn) = aux.lock() else {
        return;
    };
    let id = pb_core::ids::default_random_id();
    let message = cut_str(message, 8000);
    let _ = conn.execute(
        "INSERT INTO _logs (id, level, message, data, created)
         VALUES (?1, ?2, ?3, ?4, strftime('%Y-%m-%d %H:%M:%fZ','now'))",
        rusqlite::params![id, level, message, data.to_string()],
    );
}

/// `slog` renders a validation error map by calling `Error()` on each leaf.
/// The public envelope keeps `{code,message}` objects, but the log stores just
/// the messages (nested maps stay nested).
fn flatten_log_details(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut out = Map::new();
            for (key, value) in map {
                let is_leaf = value.get("code").is_some()
                    && value.get("message").and_then(Value::as_str).is_some();
                if is_leaf {
                    let message = value
                        .get("message")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string();
                    out.insert(key.clone(), Value::String(message));
                } else {
                    out.insert(key.clone(), flatten_log_details(value));
                }
            }
            Value::Object(out)
        }
        Value::Array(items) => {
            Value::Array(items.iter().map(flatten_log_details).collect())
        }
        other => other.clone(),
    }
}

/// Extracts the oracle's `error` / `details` log attributes from an error
/// response. The MFA challenge is special-cased because the handler returns a
/// bare `{"mfaId":...}` body but the oracle's error is the `ErrMFA` sentinel.
fn error_attributes(
    status: StatusCode,
    body: &[u8],
    extensions: &axum::http::Extensions,
) -> (Option<String>, Option<Value>) {
    // ApiError responses carry their internal raw data; the oracle logs that
    // (not the public `data` envelope).
    if let Some(log) = extensions.get::<crate::error::ErrorLogData>() {
        return (
            Some(log.message.clone()),
            Some(flatten_log_details(&log.details)),
        );
    }

    let parsed: Option<Value> = serde_json::from_slice(body).ok();
    if let Some(value) = &parsed {
        if value.get("mfaId").is_some() {
            return (Some("mfa required".to_string()), None);
        }
        if let Some(message) = value.get("message").and_then(Value::as_str) {
            let details = match value.get("data") {
                Some(Value::Object(map)) if map.is_empty() => None,
                Some(Value::Null) | None => None,
                Some(other) => Some(other.clone()),
            };
            return (Some(message.to_string()), details);
        }
    }
    if status.as_u16() >= 400 {
        (Some(status.canonical_reason().unwrap_or("").to_string()), None)
    } else {
        (None, None)
    }
}

/// Axum middleware mirroring PocketBase's activity logger.
pub async fn activity_logger(State(db): State<Db>, request: Request, next: Next) -> Response {
    let started = Instant::now();
    let method = request.method().clone();
    // `nest("/api", ...)` rewrites the request URI to the inner path; the
    // activity logger must record the public `/api/...` URI like the oracle.
    let uri = request
        .extensions()
        .get::<OriginalUri>()
        .map(|original| original.0.clone())
        .unwrap_or_else(|| request.uri().clone());
    let headers = request.headers().clone();
    let ip = remote_ip(&request);

    let response = next.run(request).await;
    let status = response.status();

    if status.is_success() && skips_success_log(uri.path(), &method) {
        return response;
    }

    let settings = {
        let Ok(conn) = db.lock() else {
            return response;
        };
        pb_core::settings::load(&conn).ok()
    };
    let Some(settings) = settings else {
        return response;
    };
    if settings.logs.max_days <= 0 {
        return response;
    }

    let level = if status.as_u16() >= 400 { 8 } else { 0 };
    if level < settings.logs.min_level {
        return response;
    }

    let auth = load_auth(&db, &headers);
    let method_text = cut_str(&method.as_str().to_uppercase(), 50);
    let uri_text = uri.to_string();
    let message = format!("{} {}", method_text, path_unescape(&uri_text));

    let mut data = Map::new();
    data.insert("type".into(), json!("request"));
    data.insert(
        "execTime".into(),
        json!(started.elapsed().as_secs_f64() * 1000.0),
    );
    data.insert("url".into(), json!(cut_str(&uri_text, 3000)));
    data.insert("method".into(), json!(method_text));
    data.insert("status".into(), json!(status.as_u16()));
    data.insert(
        "referer".into(),
        json!(cut_str(header(&headers, "referer"), 2000)),
    );
    data.insert(
        "userAgent".into(),
        json!(cut_str(header(&headers, "user-agent"), 2000)),
    );
    data.insert(
        "auth".into(),
        json!(auth
            .as_ref()
            .map(|a| a.collection.name.clone())
            .unwrap_or_default()),
    );
    if settings.logs.log_auth_id {
        if let Some(auth) = &auth {
            data.insert("authId".into(), json!(auth.record.id()));
        }
    }
    if settings.logs.log_ip {
        data.insert("userIP".into(), json!(ip));
        data.insert("remoteIP".into(), json!(ip));
    }

    if status.as_u16() >= 400 {
        let (parts, body) = response.into_parts();
        let bytes = axum::body::to_bytes(body, 1024 * 1024)
            .await
            .unwrap_or_default();
        let (error, details) = error_attributes(status, &bytes, &parts.extensions);
        if let Some(error) = error {
            data.insert("error".into(), json!(error));
        }
        if let Some(details) = details {
            data.insert("details".into(), details);
        }
        let data_clone = Value::Object(data);
        let message_clone = message.clone();
        tokio::task::spawn_blocking(move || {
            write_log(level, &message_clone, &data_clone);
        });
        return Response::from_parts(parts, Body::from(bytes));
    }

    let data_clone = Value::Object(data);
    let message_clone = message.clone();
    tokio::task::spawn_blocking(move || {
        write_log(level, &message_clone, &data_clone);
    });

    response
}
