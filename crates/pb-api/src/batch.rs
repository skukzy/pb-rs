//! `POST /api/batch` transactional request batching.
//!
//! The Rust port executes the batched requests through the same handlers as
//! the public API, wrapped in a SQLite savepoint so a failure at index `N`
//! rolls back every previous request and reports the oracle-shaped
//! `batch_request_failed` error.

use std::collections::HashMap;

use axum::body::Bytes;
use axum::extract::{ConnectInfo, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use pb_core::validation::{self, Errors, Node};
use serde_json::{json, Map, Value};

use crate::auth::Db;
use crate::error::ApiError;
use crate::records;

const SAVEPOINT: &str = "pb_batch";

fn batch_error(status: u16, message: &str, data: Value) -> Value {
    json!({
        "code": "batch_request_failed",
        "message": "Batch request failed.",
        "response": {
            "status": status,
            "message": message,
            "data": data,
        }
    })
}

fn request_error(message: &str, errors: &Errors) -> ApiError {
    ApiError::new(
        StatusCode::BAD_REQUEST,
        message,
        validation::errors_to_value(errors),
    )
    .with_raw_data(validation::errors_to_log_value(errors))
}

fn parse_query(raw: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for pair in raw.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let decode = |s: &str| {
            urlencoding::decode(s)
                .map(|c| c.into_owned())
                .unwrap_or_else(|_| s.to_string())
        };
        out.insert(decode(key), decode(value));
    }
    out
}

struct ParsedUrl {
    collection: String,
    record_id: Option<String>,
    query: HashMap<String, String>,
}

fn parse_records_url(url: &str) -> Option<ParsedUrl> {
    let (path, query) = url.split_once('?').unwrap_or((url, ""));
    let path = path.strip_prefix("/api/")?;
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if segments.len() < 3 || segments[0] != "collections" || segments[2] != "records" {
        return None;
    }
    if segments.len() > 4 {
        return None;
    }
    Some(ParsedUrl {
        collection: segments[1].to_string(),
        record_id: segments.get(3).map(|s| s.to_string()),
        query: parse_query(query),
    })
}

/// Header map with the batch item headers merged over the outer request ones.
fn merged_headers(base: &HeaderMap, extra: &Map<String, Value>) -> HeaderMap {
    let mut headers = base.clone();
    for (key, value) in extra {
        if key.eq_ignore_ascii_case("authorization") {
            continue;
        }
        let Some(text) = value.as_str() else {
            continue;
        };
        if let (Ok(name), Ok(value)) = (
            axum::http::HeaderName::from_bytes(key.as_bytes()),
            axum::http::HeaderValue::from_str(text),
        ) {
            headers.insert(name, value);
        }
    }
    headers
}

enum HandlerResult {
    Json(Value),
    Empty,
}

#[allow(clippy::too_many_arguments)]
async fn dispatch(
    db: &Db,
    base_headers: &HeaderMap,
    method: &str,
    url: &str,
    body: Value,
    headers: &Map<String, Value>,
    addr: std::net::SocketAddr,
) -> Result<HandlerResult, ApiError> {
    let Some(parsed) = parse_records_url(url) else {
        return Err(ApiError::bad_request("Something went wrong while processing your request."));
    };
    let ParsedUrl {
        collection,
        record_id,
        query,
    } = parsed;
    let headers = merged_headers(base_headers, headers);
    let query = Query(query);
    let inner_path = url.split('?').next().unwrap_or(url);

    if matches!(method, "POST" | "PUT" | "PATCH") {
        let payload = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
        let mut headers = headers;
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json"),
        );
        let bytes = Bytes::from(payload);

        let result = match (method, record_id.as_deref()) {
            ("POST", None) => {
                records::create_inner(
                    db.clone(),
                    headers,
                    collection,
                    query.0,
                    bytes,
                    addr,
                    inner_path,
                    "",
                )
                .await
            }
            ("PATCH", Some(id)) => {
                records::update_inner(
                    db.clone(),
                    headers,
                    collection,
                    id.to_string(),
                    query.0,
                    bytes,
                    addr,
                    inner_path,
                    "",
                )
                .await
            }
            ("PUT", None) => {
                return upsert(db, headers, collection, query, bytes, addr).await
            }
            _ => return Err(ApiError::bad_request("Something went wrong while processing your request.")),
        };
        return result.map(|Json(value)| HandlerResult::Json(value));
    }

    match (method, record_id) {
        ("DELETE", Some(id)) => {
            records::delete_inner(
                db.clone(),
                headers,
                collection,
                id,
                addr,
                inner_path,
                "",
            )
            .await?;
            Ok(HandlerResult::Empty)
        }
        _ => Err(ApiError::bad_request("Something went wrong while processing your request.")),
    }
}

/// `PUT /api/collections/{collection}/records` — update when the body carries
/// an existing record id, create otherwise.
async fn upsert(
    db: &Db,
    headers: HeaderMap,
    collection: String,
    query: Query<HashMap<String, String>>,
    bytes: Bytes,
    addr: std::net::SocketAddr,
) -> Result<HandlerResult, ApiError> {
    let id = serde_json::from_slice::<Value>(&bytes)
        .ok()
        .and_then(|v| v.get("id").and_then(Value::as_str).map(str::to_string))
        .unwrap_or_default();

    if !id.is_empty() {
        let exists = {
            let conn = db
                .lock()
                .map_err(|_| ApiError::internal("database lock poisoned"))?;
            pb_core::collections::Collection::find(&conn, &collection)
                .ok()
                .flatten()
                .and_then(|coll| {
                    pb_core::records::Record::find_by_id(&conn, &coll, &id)
                        .ok()
                        .flatten()
                })
                .is_some()
        };
        if exists {
            let path = format!("/api/collections/{collection}/records/{id}");
            let result = records::update_inner(
                db.clone(),
                headers,
                collection,
                id,
                query.0,
                bytes,
                addr,
                &path,
                "",
            )
            .await?;
            return Ok(HandlerResult::Json(result.0));
        }
    }

    let path = format!("/api/collections/{collection}/records");
    let result = records::create_inner(
        db.clone(),
        headers,
        collection,
        query.0,
        bytes,
        addr,
        &path,
        "",
    )
    .await?;
    Ok(HandlerResult::Json(result.0))
}

fn length_too_long(max: usize) -> Node {
    Node::Leaf(pb_core::validation::ValidationError {
        code: "validation_length_too_long".into(),
        message: "the length must be no more than {{.max}}".into(),
        params: Some(json!({ "min": 0, "max": max })),
    })
}

pub async fn batch_transaction(
    State(db): State<Db>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    let settings = {
        let conn = db
            .lock()
            .map_err(|_| ApiError::internal("database lock poisoned"))?;
        pb_core::settings::load(&conn)
            .map_err(|e| ApiError::internal(format!("failed to load settings: {e}")))?
    };

    if !settings.batch.enabled || settings.batch.max_requests <= 0 {
        return Err(ApiError::forbidden("Batch requests are not allowed."));
    }
    let max_requests = settings.batch.max_requests as usize;

    let form: Value = if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&body)
            .map_err(|_| ApiError::bad_request("Failed to read the submitted batch data."))?
    };

    let requests = form.get("requests");
    let Some(Value::Array(requests)) = requests else {
        let mut errors = Errors::new();
        errors.insert("requests".into(), validation::required());
        return Err(request_error(
            "Invalid batch request data.",
            &errors,
        ));
    };

    if requests.is_empty() {
        let mut errors = Errors::new();
        errors.insert("requests".into(), validation::required());
        return Err(request_error(
            "Invalid batch request data.",
            &errors,
        ));
    }
    if requests.len() > max_requests {
        let mut errors = Errors::new();
        errors.insert("requests".into(), length_too_long(max_requests));
        return Err(request_error(
            "Invalid batch request data.",
            &errors,
        ));
    }

    // Per-request validation (method/url).
    let mut request_errors = Errors::new();
    for (index, item) in requests.iter().enumerate() {
        let mut errors = Errors::new();
        let method = item.get("method").and_then(Value::as_str).unwrap_or("");
        if method.is_empty() {
            errors.insert("method".into(), validation::required());
        } else if !matches!(method, "GET" | "POST" | "PUT" | "PATCH" | "DELETE") {
            errors.insert("method".into(), validation::invalid_in());
        }
        let url = item.get("url").and_then(Value::as_str).unwrap_or("");
        if url.is_empty() {
            errors.insert("url".into(), validation::required());
        } else if let Some(node) = validation::length(url, 0, 2000) {
            errors.insert("url".into(), node);
        }
        if !errors.is_empty() {
            request_errors.insert(index.to_string(), Node::Branch(errors));
        }
    }
    if !request_errors.is_empty() {
        let mut errors = Errors::new();
        errors.insert("requests".into(), Node::Branch(request_errors));
        return Err(request_error(
            "Invalid batch request data.",
            &errors,
        ));
    }

    // Start the savepoint used for rollback on failure.
    {
        let conn = db
            .lock()
            .map_err(|_| ApiError::internal("database lock poisoned"))?;
        conn.execute_batch(&format!("SAVEPOINT {SAVEPOINT}"))
            .map_err(|e| ApiError::internal(format!("failed to start batch transaction: {e}")))?;
    }

    let mut results: Vec<Value> = Vec::with_capacity(requests.len());
    for (index, item) in requests.iter().enumerate() {
        let method = item.get("method").and_then(Value::as_str).unwrap_or("");
        let url = item.get("url").and_then(Value::as_str).unwrap_or("");
        let body = item.get("body").cloned().unwrap_or(Value::Null);
        let item_headers = item
            .get("headers")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();

        match dispatch(&db, &headers, method, url, body, &item_headers, addr).await {
            Ok(HandlerResult::Json(value)) => {
                results.push(json!({ "body": value, "status": 200 }));
            }
            Ok(HandlerResult::Empty) => {
                results.push(json!({ "body": Value::Null, "status": 204 }));
            }
            Err(err) => {
                let status = err.status.as_u16();
                let message = err.message.clone();
                let data = err.data.clone();
                if let Ok(conn) = db.lock() {
                    let _ = conn
                        .execute_batch(&format!("ROLLBACK TO {SAVEPOINT}; RELEASE {SAVEPOINT}"));
                }
                let mut requests_data = Map::new();
                requests_data.insert(index.to_string(), batch_error(status, &message, data));
                let mut top = Map::new();
                top.insert("requests".into(), Value::Object(requests_data));
                return Err(ApiError::new(
                    StatusCode::BAD_REQUEST,
                    "Batch transaction failed.",
                    Value::Object(top),
                ));
            }
        }
    }

    if let Ok(conn) = db.lock() {
        conn.execute_batch(&format!("RELEASE {SAVEPOINT}")).ok();
    }
    Ok(Json(Value::Array(results)))
}
