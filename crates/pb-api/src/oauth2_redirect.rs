//! `GET/POST /api/oauth2-redirect` — OAuth2 realtime subscription redirect.
//!
//! Mirrors `.upstream/apis/record_auth_with_oauth2_redirect.go`: validates the
//! realtime client identified by `state`, pushes the redirect payload over the
//! `@oauth2` subscription, then redirects the browser to the success/failure
//! hash route depending on whether a code was delivered.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{Method, StatusCode};
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use crate::rate_limit;
use crate::{realtime, Db};

#[derive(Deserialize, Default, Clone)]
struct RedirectData {
    #[serde(default, rename = "state")]
    state: String,
    #[serde(default, rename = "code")]
    code: String,
    #[serde(default, rename = "error")]
    error: String,
    #[serde(default, rename = "user")]
    apple_user: String,
}

#[derive(Serialize)]
struct OutData {
    state: String,
    code: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    error: String,
}

#[derive(Deserialize, Default)]
struct AppleUser {
    #[serde(default)]
    name: AppleUserName,
}

#[derive(Deserialize, Default)]
struct AppleUserName {
    #[serde(default, rename = "firstName")]
    first_name: String,
    #[serde(default, rename = "lastName")]
    last_name: String,
}

// ---------------------------------------------------------------------------
// Tiny in-memory app store (mirrors core.App.Store for the Apple name hack).
// ---------------------------------------------------------------------------

static STORE: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();

fn store() -> &'static Mutex<HashMap<String, String>> {
    STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn store_get(key: &str) -> Option<String> {
    store().lock().ok()?.get(key).cloned()
}

pub fn store_set(key: String, value: String) {
    if let Ok(mut m) = store().lock() {
        m.insert(key, value);
    }
}

pub fn store_remove(key: &str) {
    if let Ok(mut m) = store().lock() {
        m.remove(key);
    }
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

pub async fn oauth2_redirect(
    State(db): State<Db>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    req: Request,
) -> impl IntoResponse {
    let method = req.method().clone();
    let headers = req.headers().clone();

    let settings = {
        let conn = db.lock().unwrap();
        pb_core::settings::load(&conn).ok()
    }
    .unwrap_or_default();
    let addr = connect_info.map(|c| c.0);
    let real_ip = rate_limit::real_ip(&headers, &settings, addr);

    // Parse the redirect payload.
    let data = if method == Method::GET {
        Some(parse_query(req.uri().query().unwrap_or("")))
    } else {
        let content_type = headers
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let (_parts, body) = req.into_parts();
        let bytes = axum::body::to_bytes(body, 1024 * 1024)
            .await
            .unwrap_or_default();
        if bytes.is_empty() {
            Some(RedirectData::default())
        } else {
            parse_body(&content_type, &bytes)
        }
    };

    let Some(data) = data else {
        return failure_redirect(method);
    };

    let broker = realtime::broker();

    // Client validation.
    let Some((stored_ip, _stored_auth)) = broker.client_state(&data.state) else {
        return failure_redirect(method);
    };

    let subs = broker.subscriptions(&data.state).unwrap_or_default();
    let has_oauth = subs
        .iter()
        .any(|s| realtime::subscription_topic(s) == "@oauth2");
    if !has_oauth {
        return failure_redirect(method);
    }

    // IP check.
    if !stored_ip.is_empty() && stored_ip != real_ip {
        return failure_redirect(method);
    }

    // Apple user name stashing (non-critical).
    if !data.apple_user.is_empty() && data.error.is_empty() && !data.code.is_empty() {
        let name_key = format!("@redirect_name_{}", data.code);
        if name_key.len() <= 1000 {
            if let Ok(parsed) = serde_json::from_str::<AppleUser>(&data.apple_user) {
                let full = format!("{} {}", parsed.name.first_name, parsed.name.last_name);
                let truncated: String = full.chars().take(150).collect();
                let trimmed = truncated.trim().to_string();
                if !trimmed.is_empty() {
                    store_set(name_key.clone(), trimmed);
                    let key = name_key;
                    tokio::spawn(async move {
                        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                        store_remove(&key);
                    });
                }
            }
        }
    }

    let encoded = serde_json::to_string(&OutData {
        state: data.state.clone(),
        code: data.code.clone(),
        error: data.error.clone(),
    })
    .unwrap_or_default();

    let msg = realtime::Event {
        name: "@oauth2".to_string(),
        data: encoded,
    };
    broker.send(&data.state, msg);
    broker.unsubscribe(&data.state, "@oauth2");

    if !data.error.is_empty() || data.code.is_empty() {
        return redirect_response(method, "../_/#/auth/oauth2-redirect-failure");
    }
    redirect_response(method, "../_/#/auth/oauth2-redirect-success")
}

fn failure_redirect(method: Method) -> axum::response::Response {
    redirect_response(method, "../_/#/auth/oauth2-redirect-failure")
}

fn redirect_response(method: Method, location: &str) -> axum::response::Response {
    let status = if method == Method::GET {
        StatusCode::TEMPORARY_REDIRECT
    } else {
        StatusCode::SEE_OTHER
    };
    (status, [(axum::http::header::LOCATION, location)]).into_response()
}

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

fn parse_query(q: &str) -> RedirectData {
    let mut data = RedirectData::default();
    for pair in q.split('&') {
        if pair.is_empty() {
            continue;
        }
        let mut parts = pair.splitn(2, '=');
        let key = parts.next().unwrap_or("");
        let val = parts.next().unwrap_or("");
        let key = urlencoding::decode(key).unwrap_or_default();
        let val = urlencoding::decode(val).unwrap_or_default();
        match key.as_ref() {
            "state" => data.state = val.into_owned(),
            "code" => data.code = val.into_owned(),
            "error" => data.error = val.into_owned(),
            "user" => data.apple_user = val.into_owned(),
            _ => {}
        }
    }
    data
}

fn parse_body(content_type: &str, bytes: &[u8]) -> Option<RedirectData> {
    let ct = content_type.to_lowercase();
    if ct.starts_with("application/json") {
        serde_json::from_slice(bytes).ok()
    } else if ct.starts_with("application/x-www-form-urlencoded") {
        let text = std::str::from_utf8(bytes).ok()?;
        Some(parse_query(text))
    } else if ct.starts_with("multipart/form-data") {
        parse_multipart(content_type, bytes)
    } else {
        None
    }
}

fn parse_multipart(content_type: &str, bytes: &[u8]) -> Option<RedirectData> {
    let boundary = content_type
        .split("boundary=")
        .nth(1)?
        .trim()
        .trim_matches('"')
        .to_string();
    let body = std::str::from_utf8(bytes).ok()?;
    let delim = format!("--{}", boundary);
    let mut data = RedirectData::default();
    for part in body.split(&delim) {
        let Some((headers, value)) = part.split_once("\r\n\r\n") else {
            continue;
        };
        let value = value.trim_end_matches("\r\n").trim_end_matches("--").trim_end_matches("\r\n");
        let mut name: Option<String> = None;
        for line in headers.lines() {
            if line.to_lowercase().starts_with("content-disposition") {
                for seg in line.split(';') {
                    let seg = seg.trim();
                    if let Some(rest) = seg.strip_prefix("name=") {
                        name = Some(rest.trim_matches('"').to_string());
                    }
                }
            }
        }
        let Some(name) = name else { continue; };
        match name.as_str() {
            "state" => data.state = value.to_string(),
            "code" => data.code = value.to_string(),
            "error" => data.error = value.to_string(),
            "user" => data.apple_user = value.to_string(),
            _ => {}
        }
    }
    Some(data)
}


