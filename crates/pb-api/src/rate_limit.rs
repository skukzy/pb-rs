//! Rate limiting (`apis/middlewares_rate_limit.go`).
//!
//! PocketBase uses a fixed-window limiter per rule + client IP. The global
//! middleware is bound to every route except the record CRUD group, which
//! inlines `checkCollectionRateLimit` inside its handlers (so batch requests
//! are limited too). Auth and file routes additionally run the
//! `collectionPathRateLimit` middleware.
//!
//! The limiter store is reset whenever the settings are reloaded; in this port
//! settings are read per request, so `reset()` is called after a successful
//! `PATCH /api/settings`.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{ConnectInfo, OriginalUri, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use pb_core::collections::Collection;
use pb_core::settings::{self, RateLimitRule, RateLimitsConfig, Settings};
use serde_json::json;

use crate::auth::{load_auth, AuthContext, Db};
use crate::error::ApiError;

/// `newRateLimiter(..., 1800)`: stale clients are pruned after 30 minutes.
const MIN_DELETE_INTERVAL: i64 = 1800;

struct RateClient {
    max_allowed: i64,
    available: i64,
    start: i64,
    interval: i64,
}

impl RateClient {
    fn new(max_allowed: i64, interval: i64) -> Self {
        Self {
            max_allowed,
            available: 0,
            start: 0,
            interval,
        }
    }

    fn consume(&mut self) -> bool {
        let now = unix_now();
        if now - self.start >= self.interval {
            self.available = self.max_allowed;
            self.start = now;
        }
        if self.available > 0 {
            self.available -= 1;
            true
        } else {
            false
        }
    }

    fn has_expired(&self, now: i64, min_elapsed: i64) -> bool {
        now - (self.start + self.interval) > min_elapsed
    }
}

type LimiterMap = HashMap<String, Arc<Mutex<RateClient>>>;

fn limiters() -> &'static Mutex<LimiterMap> {
    static LIMITERS: OnceLock<Mutex<LimiterMap>> = OnceLock::new();
    LIMITERS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Whether `initRateLimitersStore` has run. The oracle registers the
/// `__pbRateLimitersCleanup__` cron job lazily, the first time a rate-limit
/// rule actually matches (`checkRateLimit`), and removes it again on every
/// settings reload.
static STORE_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub fn is_initialized() -> bool {
    STORE_INITIALIZED.load(Ordering::Relaxed)
}

fn mark_initialized() {
    STORE_INITIALIZED.store(true, Ordering::Relaxed);
}

/// `initRateLimitersStore`/`destroyRateLimitersStore`: a settings reload
/// discards every limiter and unregisters the cleanup cron job.
pub fn reset() {
    STORE_INITIALIZED.store(false, Ordering::Relaxed);
    if let Ok(mut map) = limiters().lock() {
        map.clear();
    }
}

/// `__pbRateLimitersCleanup__` (every hour at minute 2).
pub fn clean() {
    let now = unix_now();
    if let Ok(mut map) = limiters().lock() {
        map.retain(|_, client| {
            client
                .lock()
                .map(|c| !c.has_expired(now, MIN_DELETE_INTERVAL))
                .unwrap_or(false)
        });
    }
}

fn is_allowed(rt_id: &str, max_allowed: i64, interval: i64, key: &str) -> bool {
    // Each limiter keeps one fixed-window client per IP.
    let map_key = format!("{rt_id}\u{0}{key}");
    let client = {
        let mut map = match limiters().lock() {
            Ok(map) => map,
            Err(_) => return true,
        };
        map.entry(map_key)
            .or_insert_with(|| Arc::new(Mutex::new(RateClient::new(max_allowed, interval))))
            .clone()
    };
    let mut guard = match client.lock() {
        Ok(guard) => guard,
        Err(_) => return true,
    };
    guard.consume()
}

/// `RateLimitsConfig.FindRateLimitRule`.
pub fn find_rate_limit_rule<'a>(
    config: &'a RateLimitsConfig,
    labels: &[String],
    audiences: &[&str],
) -> Option<&'a RateLimitRule> {
    let mut prefix_rules: Vec<usize> = Vec::new();

    for (i, label) in labels.iter().enumerate() {
        for (j, rule) in config.rules.iter().enumerate() {
            if *label == rule.label && audiences.contains(&rule.audience.as_str()) {
                return Some(rule);
            }
            if i == 0 && rule.label.ends_with('/') {
                prefix_rules.push(j);
            }
        }

        for &j in &prefix_rules {
            let rule = &config.rules[j];
            if format!("{label}/").starts_with(&rule.label)
                && audiences.contains(&rule.audience.as_str())
            {
                return Some(rule);
            }
        }
    }

    None
}

fn default_audiences(auth: Option<&AuthContext>) -> Vec<&'static str> {
    if auth.is_some() {
        vec!["", "@auth"]
    } else {
        vec!["", "@guest"]
    }
}

pub fn is_ip_in_list(ips_or_subnets: &[String], ip: &str) -> bool {
    if ips_or_subnets.is_empty() || ip.is_empty() {
        return false;
    }
    let Ok(search) = ip.parse::<IpAddr>() else {
        return false;
    };
    for item in ips_or_subnets {
        if let Some((addr, len)) = parse_prefix(item) {
            if prefix_contains(addr, len, search) {
                return true;
            }
            continue;
        }
        if let Ok(addr) = item.parse::<IpAddr>() {
            if addr == search {
                return true;
            }
        }
    }
    false
}

fn parse_prefix(value: &str) -> Option<(IpAddr, u8)> {
    let (addr, len) = value.split_once('/')?;
    let addr = addr.trim().parse::<IpAddr>().ok()?;
    let len = len.trim().parse::<u8>().ok()?;
    Some((addr, len))
}

fn prefix_contains(addr: IpAddr, len: u8, other: IpAddr) -> bool {
    match (addr, other) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            if len > 32 {
                return false;
            }
            let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
            (u32::from(a) & mask) == (u32::from(b) & mask)
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            if len > 128 {
                return false;
            }
            let mask = if len == 0 {
                0
            } else {
                u128::MAX << (128 - len)
            };
            (u128::from(a) & mask) == (u128::from(b) & mask)
        }
        _ => false,
    }
}

/// `netip.Addr.StringExpanded`: IPv6 addresses are printed in full form with
/// leading zeros and no `::` compression.
fn string_expanded(addr: IpAddr) -> String {
    match addr {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => v6
            .segments()
            .iter()
            .map(|segment| format!("{segment:04x}"))
            .collect::<Vec<_>>()
            .join(":"),
    }
}

/// `RequestEvent.RealIP`.
pub fn real_ip(headers: &HeaderMap, settings: &Settings, addr: Option<SocketAddr>) -> String {
    for name in &settings.trusted_proxy.headers {
        let values: Vec<&str> = headers
            .get_all(name.as_str())
            .iter()
            .filter_map(|value| value.to_str().ok())
            .collect();
        let Some(last) = values.last() else {
            continue;
        };
        if last.is_empty() {
            continue;
        }
        let ips: Vec<&str> = last.split(',').collect();
        if settings.trusted_proxy.use_leftmost_ip {
            for ip in &ips {
                if let Ok(parsed) = ip.trim().parse::<IpAddr>() {
                    return string_expanded(parsed);
                }
            }
        } else {
            for ip in ips.iter().rev() {
                if let Ok(parsed) = ip.trim().parse::<IpAddr>() {
                    return string_expanded(parsed);
                }
            }
        }
    }

    addr.map(|addr| string_expanded(addr.ip())).unwrap_or_default()
}

fn skip_rate_limit(
    settings: &Settings,
    auth: Option<&AuthContext>,
    ip: &str,
) -> bool {
    !settings.rate_limits.enabled
        || auth.is_some_and(AuthContext::is_superuser)
        || is_ip_in_list(&settings.rate_limits.excluded_ips, ip)
}

fn rate_limit_error(rule: &RateLimitRule) -> ApiError {
    // `NewTooManyRequestsError("", error)` keeps the default message; the raw
    // error becomes the activity-log `details` string.
    let rule_json = serde_json::to_string(rule).unwrap_or_else(|_| rule.label.clone());
    ApiError::new(
        StatusCode::TOO_MANY_REQUESTS,
        "Too Many Requests.",
        json!({}),
    )
    .with_raw_data(json!(format!("triggered rate limit rule: {rule_json}")))
}

fn check_rate_limit(
    rt_id: &str,
    rule: &RateLimitRule,
    auth: Option<&AuthContext>,
    ip: &str,
) -> Result<(), ApiError> {
    match rule.audience.as_str() {
        "" => {}
        "@guest" => {
            if auth.is_some() {
                return Ok(());
            }
        }
        "@auth" => {
            if auth.is_none() {
                return Ok(());
            }
        }
        _ => {}
    }

    // `checkRateLimit` calls `initRateLimitersStore` before looking up the
    // client key, so a matched rule registers the cleanup job even when the
    // IP is empty.
    mark_initialized();

    if ip.is_empty() {
        return Ok(());
    }

    if !is_allowed(
        &format!("{rt_id}{}", rule.audience),
        rule.max_requests,
        rule.duration,
        ip,
    ) {
        return Err(rate_limit_error(rule));
    }

    Ok(())
}

/// Global `rateLimit()` middleware.
pub async fn global_middleware(
    State(db): State<Db>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    let method = request.method().as_str().to_string();
    let path = request.uri().path().to_string();

    // `bindRecordCrudApi` unbinds the global middleware on the CRUD group.
    if is_record_crud_path(&path) {
        return next.run(request).await;
    }

    let headers = request.headers().clone();
    let settings = load_settings(&db);
    let Some(settings) = settings else {
        return next.run(request).await;
    };
    let auth = load_auth(&db, &headers);
    let ip = real_ip(&headers, &settings, Some(addr));

    if skip_rate_limit(&settings, auth.as_ref(), &ip) {
        return next.run(request).await;
    }

    let labels = vec![format!("{method} {path}"), path];
    let audiences = default_audiences(auth.as_ref());
    if let Some(rule) = find_rate_limit_rule(&settings.rate_limits, &labels, &audiences) {
        let rt_id = format!("{}{}", rule.label, rule.audience);
        if let Err(err) = check_rate_limit(&rt_id, rule, auth.as_ref(), &ip) {
            return err.into_response();
        }
    }

    next.run(request).await
}

fn load_settings(db: &Db) -> Option<Settings> {
    let conn = db.lock().ok()?;
    settings::load(&conn).ok()
}

fn is_record_crud_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("/api/collections/") else {
        return false;
    };
    let segments: Vec<&str> = rest.split('/').collect();
    matches!(segments.as_slice(), [_, "records"] | [_, "records", _])
}

/// One collection-scoped route and the labels its `collectionPathRateLimit`
/// binding uses.
struct CollectionRoute {
    base_tags: &'static [&'static str],
    pattern: &'static str,
}

fn collection_route(method: &str, path: &str) -> Option<(CollectionRoute, String)> {
    // `/api/collections/{collection}/<action>`
    if let Some(rest) = path.strip_prefix("/api/collections/") {
        let segments: Vec<&str> = rest.split('/').collect();
        if segments.len() == 2 && !segments[0].is_empty() {
            let collection = segments[0].to_string();
            let action = segments[1];
            let (tags, pattern): (&'static [&'static str], &'static str) = match action {
                    "auth-methods" => (
                        &["listAuthMethods"],
                        "/api/collections/{collection}/auth-methods",
                    ),
                    "auth-refresh" => (
                        &["authRefresh"],
                        "/api/collections/{collection}/auth-refresh",
                    ),
                    "auth-with-password" => (
                        &["authWithPassword", "auth"],
                        "/api/collections/{collection}/auth-with-password",
                    ),
                    "auth-with-oauth2" => (
                        &["authWithOAuth2", "auth"],
                        "/api/collections/{collection}/auth-with-oauth2",
                    ),
                    "request-otp" => (
                        &["requestOTP"],
                        "/api/collections/{collection}/request-otp",
                    ),
                    "auth-with-otp" => (
                        &["authWithOTP", "auth"],
                        "/api/collections/{collection}/auth-with-otp",
                    ),
                    "request-password-reset" => (
                        &["requestPasswordReset"],
                        "/api/collections/{collection}/request-password-reset",
                    ),
                    "confirm-password-reset" => (
                        &["confirmPasswordReset"],
                        "/api/collections/{collection}/confirm-password-reset",
                    ),
                    "request-verification" => (
                        &["requestVerification"],
                        "/api/collections/{collection}/request-verification",
                    ),
                    "confirm-verification" => (
                        &["confirmVerification"],
                        "/api/collections/{collection}/confirm-verification",
                    ),
                    "request-email-change" => (
                        &["requestEmailChange"],
                        "/api/collections/{collection}/request-email-change",
                    ),
                    "confirm-email-change" => (
                        &["confirmEmailChange"],
                        "/api/collections/{collection}/confirm-email-change",
                    ),
                    _ => return None,
                };
            return Some((
                CollectionRoute {
                    base_tags: tags,
                    pattern,
                },
                collection,
            ));
        }
    }

    // `/api/files/{collection}/{recordId}/{filename}`
    if let Some(rest) = path.strip_prefix("/api/files/") {
        let segments: Vec<&str> = rest.split('/').collect();
        if segments.len() == 3 && !segments[0].is_empty() {
            if method != "GET" {
                return None;
            }
            return Some((
                CollectionRoute {
                    base_tags: &["file"],
                    pattern: "/api/files/{collection}/{recordId}/{filename}",
                },
                segments[0].to_string(),
            ));
        }
    }

    None
}

/// `collectionPathRateLimit()` middleware for auth and file routes.
pub async fn collection_middleware(
    State(db): State<Db>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    OriginalUri(uri): OriginalUri,
    request: Request,
    next: Next,
) -> Response {
    let method = request.method().as_str().to_string();
    let path = uri.path().to_string();
    let Some((route, collection_ref)) = collection_route(&method, &path) else {
        return next.run(request).await;
    };

    let headers = request.headers().clone();
    let collection = {
        let Ok(conn) = db.lock() else {
            return ApiError::internal("database lock poisoned").into_response();
        };
        match Collection::find(&conn, &collection_ref) {
            Ok(Some(collection)) => collection,
            Ok(None) => {
                return ApiError::not_found("Missing or invalid collection context.")
                    .with_raw_data(serde_json::json!("sql: no rows in result set"))
                    .into_response()
            }
            Err(err) => {
                return ApiError::internal(format!("failed to load collection: {err}"))
                    .into_response()
            }
        }
    };

    let auth = load_auth(&db, &headers);
    let settings = load_settings(&db);
    let Some(settings) = settings else {
        return next.run(request).await;
    };
    let ip = real_ip(&headers, &settings, Some(addr));

    if !skip_rate_limit(&settings, auth.as_ref(), &ip) {
        let mut labels: Vec<String> = Vec::new();
        let mut rt_id = format!("{}{}", collection.id, route.pattern);
        for tag in route.base_tags {
            rt_id.push_str(tag);
            labels.push(format!("{}:{}", collection.name, tag));
        }
        for tag in route.base_tags {
            labels.push(format!("*:{tag}"));
        }
        labels.push(format!("{method} {path}"));
        labels.push(path.clone());

        let audiences = default_audiences(auth.as_ref());
        if let Some(rule) = find_rate_limit_rule(&settings.rate_limits, &labels, &audiences) {
            if let Err(err) = check_rate_limit(&rt_id, rule, auth.as_ref(), &ip) {
                return err.into_response();
            }
        }
    }

    next.run(request).await
}

/// `checkCollectionRateLimit` for the record CRUD handlers (also used by the
/// batch endpoint, where the oracle's internal request has an empty pattern).
#[allow(clippy::too_many_arguments)]
pub fn check_collection(
    conn: &rusqlite::Connection,
    collection: &Collection,
    headers: &HeaderMap,
    addr: Option<SocketAddr>,
    auth: Option<&AuthContext>,
    base_tags: &[&str],
    pattern: &str,
    method: &str,
    path: &str,
) -> Result<(), ApiError> {
    let settings = settings::load(conn)
        .map_err(|e| ApiError::internal(format!("failed to load settings: {e}")))?;
    let ip = real_ip(headers, &settings, addr);

    if skip_rate_limit(&settings, auth, &ip) {
        return Ok(());
    }

    let mut labels: Vec<String> = Vec::new();
    let mut rt_id = format!("{}{}", collection.id, pattern);
    for tag in base_tags {
        rt_id.push_str(tag);
        labels.push(format!("{}:{}", collection.name, tag));
    }
    for tag in base_tags {
        labels.push(format!("*:{tag}"));
    }
    labels.push(format!("{method} {path}"));
    labels.push(path.to_string());

    let audiences = default_audiences(auth);
    if let Some(rule) = find_rate_limit_rule(&settings.rate_limits, &labels, &audiences) {
        check_rate_limit(&rt_id, rule, auth, &ip)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(label: &str, audience: &str, max: i64, duration: i64) -> RateLimitRule {
        RateLimitRule {
            label: label.into(),
            audience: audience.into(),
            duration,
            max_requests: max,
        }
    }

    #[test]
    fn find_rule_prefers_direct_then_prefix() {
        let config = RateLimitsConfig {
            rules: vec![
                rule("/api/collections/", "", 10, 1),
                rule("/api/collections/posts/records", "", 2, 1),
            ],
            excluded_ips: vec![],
            enabled: true,
        };
        let labels = vec![
            "GET /api/collections/posts/records".to_string(),
            "/api/collections/posts/records".to_string(),
        ];
        let found = find_rate_limit_rule(&config, &labels, &["", "@guest"]).unwrap();
        assert_eq!(found.label, "/api/collections/posts/records");

        let labels = vec![
            "GET /api/collections/posts/records/abc".to_string(),
            "/api/collections/posts/records/abc".to_string(),
        ];
        let found = find_rate_limit_rule(&config, &labels, &["", "@guest"]).unwrap();
        assert_eq!(found.label, "/api/collections/");
    }

    #[test]
    fn audience_filters_rules() {
        let config = RateLimitsConfig {
            rules: vec![
                rule("*:list", "@auth", 1, 60),
                rule("*:list", "@guest", 2, 60),
            ],
            excluded_ips: vec![],
            enabled: true,
        };
        let labels = vec!["*:list".to_string()];
        let found = find_rate_limit_rule(&config, &labels, &["", "@guest"]).unwrap();
        assert_eq!(found.max_requests, 2);
        let found = find_rate_limit_rule(&config, &labels, &["", "@auth"]).unwrap();
        assert_eq!(found.max_requests, 1);
    }

    #[test]
    fn ip_list_matches_individual_addresses_and_subnets() {
        let list = vec!["127.0.0.1".to_string(), "10.0.0.0/8".to_string()];
        assert!(is_ip_in_list(&list, "127.0.0.1"));
        assert!(is_ip_in_list(&list, "10.20.30.40"));
        assert!(!is_ip_in_list(&list, "11.0.0.1"));
        assert!(!is_ip_in_list(&list, "not-an-ip"));
    }

    #[test]
    fn ipv6_is_expanded_like_go() {
        assert_eq!(
            string_expanded("2001:db8::1".parse().unwrap()),
            "2001:0db8:0000:0000:0000:0000:0000:0001"
        );
        assert_eq!(string_expanded("127.0.0.1".parse().unwrap()), "127.0.0.1");
    }
}
