//! Application settings: the `settings` row of `_params`.
//!
//! Mirrors `core/settings_model.go`. Two representations matter:
//!
//! * the **stored** form (`DBExport`): the struct serialized in declaration
//!   order, with the SMTP password and the S3 secrets included;
//! * the **API** form (`Settings.MarshalJSON`): the same, but every sensitive
//!   field is masked, so `smtp.password`, `s3.secret` and `backups.s3.secret`
//!   never appear.
//!
//! `PATCH /api/settings` binds the submitted JSON onto a clone of the current
//! settings. Go unmarshals into a struct, which means: objects merge
//! recursively, arrays and scalars are replaced, and `null` resets a value to
//! its zero value. `merge_json` + [`null_default`] reproduce that.

use std::net::IpAddr;
use std::str::FromStr;

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::validation::{
    branch, invalid_in, leaf, leaf_with_params, length, max, min, push, required, Errors, Node,
};

/// Re-exported so existing callers keep their import path.
pub use crate::validation::{errors_to_value, ValidationError};

pub const PARAM_ID: &str = "settings";

/// The default settings, used when the row is missing and as the documented
/// seed shape (shared with `pb_core::seed`).
const DEFAULT_SETTINGS: &str = include_str!("../assets/settings.json");

/// `core.maxSafeJSONInt`
const MAX_SAFE_JSON_INT: i64 = (1 << 53) - 1;

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

/// `null` unmarshals to the zero value, like `encoding/json/v2` does when
/// binding a request body onto a Go struct.
fn null_default<'de, D, T>(deserializer: D) -> std::result::Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

/// `core.Settings` (the embedded `settings` struct).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Settings {
    #[serde(default, rename = "superuserIPs", deserialize_with = "null_default")]
    pub superuser_ips: Vec<String>,
    #[serde(default, deserialize_with = "null_default")]
    pub smtp: SmtpConfig,
    #[serde(default, deserialize_with = "null_default")]
    pub backups: BackupsConfig,
    #[serde(default, deserialize_with = "null_default")]
    pub s3: S3Config,
    #[serde(default, deserialize_with = "null_default")]
    pub meta: MetaConfig,
    #[serde(default, deserialize_with = "null_default")]
    pub rate_limits: RateLimitsConfig,
    #[serde(default, deserialize_with = "null_default")]
    pub trusted_proxy: TrustedProxyConfig,
    #[serde(default, deserialize_with = "null_default")]
    pub batch: BatchConfig,
    #[serde(default, deserialize_with = "null_default")]
    pub logs: LogsConfig,
}

impl Default for Settings {
    fn default() -> Self {
        serde_json::from_str(DEFAULT_SETTINGS).expect("embedded default settings are valid")
    }
}

/// `core.SMTPConfig`
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SmtpConfig {
    #[serde(deserialize_with = "null_default")]
    pub enabled: bool,
    #[serde(deserialize_with = "null_default")]
    pub port: i64,
    #[serde(deserialize_with = "null_default")]
    pub host: String,
    #[serde(deserialize_with = "null_default")]
    pub username: String,
    #[serde(deserialize_with = "null_default")]
    pub password: String,
    #[serde(deserialize_with = "null_default")]
    pub auth_method: String,
    #[serde(deserialize_with = "null_default")]
    pub tls: bool,
    #[serde(deserialize_with = "null_default")]
    pub local_name: String,
}

/// `core.S3Config` (`secret` is `omitempty` in Go).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct S3Config {
    #[serde(deserialize_with = "null_default")]
    pub enabled: bool,
    #[serde(deserialize_with = "null_default")]
    pub bucket: String,
    #[serde(deserialize_with = "null_default")]
    pub region: String,
    #[serde(deserialize_with = "null_default")]
    pub endpoint: String,
    #[serde(deserialize_with = "null_default")]
    pub access_key: String,
    #[serde(
        default,
        deserialize_with = "null_default",
        skip_serializing_if = "String::is_empty"
    )]
    pub secret: String,
    #[serde(deserialize_with = "null_default")]
    pub force_path_style: bool,
}

/// `core.BackupsConfig`
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct BackupsConfig {
    #[serde(deserialize_with = "null_default")]
    pub cron: String,
    #[serde(deserialize_with = "null_default")]
    pub cron_max_keep: i64,
    #[serde(deserialize_with = "null_default")]
    pub s3: S3Config,
}

/// `core.MetaConfig`
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct MetaConfig {
    #[serde(deserialize_with = "null_default")]
    pub accent_color: String,
    #[serde(deserialize_with = "null_default")]
    pub app_name: String,
    #[serde(rename = "appURL", deserialize_with = "null_default")]
    pub app_url: String,
    #[serde(deserialize_with = "null_default")]
    pub sender_name: String,
    #[serde(deserialize_with = "null_default")]
    pub sender_address: String,
    #[serde(deserialize_with = "null_default")]
    pub hide_controls: bool,
}

/// `core.RateLimitsConfig`
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RateLimitsConfig {
    #[serde(deserialize_with = "null_default")]
    pub rules: Vec<RateLimitRule>,
    #[serde(rename = "excludedIPs", deserialize_with = "null_default")]
    pub excluded_ips: Vec<String>,
    #[serde(deserialize_with = "null_default")]
    pub enabled: bool,
}

/// `core.RateLimitRule`
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RateLimitRule {
    #[serde(deserialize_with = "null_default")]
    pub label: String,
    #[serde(deserialize_with = "null_default")]
    pub audience: String,
    #[serde(deserialize_with = "null_default")]
    pub duration: i64,
    #[serde(deserialize_with = "null_default")]
    pub max_requests: i64,
}

/// `core.TrustedProxyConfig`
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TrustedProxyConfig {
    #[serde(deserialize_with = "null_default")]
    pub headers: Vec<String>,
    #[serde(rename = "useLeftmostIP", deserialize_with = "null_default")]
    pub use_leftmost_ip: bool,
}

/// `core.BatchConfig`
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct BatchConfig {
    #[serde(deserialize_with = "null_default")]
    pub enabled: bool,
    #[serde(deserialize_with = "null_default")]
    pub max_requests: i64,
    #[serde(deserialize_with = "null_default")]
    pub timeout: i64,
    #[serde(deserialize_with = "null_default")]
    pub max_body_size: i64,
}

/// `core.LogsConfig`
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct LogsConfig {
    #[serde(deserialize_with = "null_default")]
    pub max_data_size: i64,
    #[serde(deserialize_with = "null_default")]
    pub max_days: i64,
    #[serde(deserialize_with = "null_default")]
    pub min_level: i64,
    #[serde(rename = "logIP", deserialize_with = "null_default")]
    pub log_ip: bool,
    #[serde(deserialize_with = "null_default")]
    pub log_auth_id: bool,
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

/// Load the raw stored settings JSON.
pub fn load_raw(conn: &Connection) -> Result<Value> {
    // `_params.value` is a BLOB in an oracle-created database (Go binds
    // `types.JSONRaw`); accept TEXT too so hand-edited databases still load.
    let raw: Option<rusqlite::types::Value> = conn
        .prepare_cached("SELECT value FROM _params WHERE id = ?1")?
        .query_row([PARAM_ID], |row| row.get(0))
        .optional()?;

    let bytes = match raw {
        Some(rusqlite::types::Value::Blob(bytes)) => bytes,
        Some(rusqlite::types::Value::Text(text)) => text.into_bytes(),
        Some(rusqlite::types::Value::Null) | None => {
            return Ok(Value::Object(Default::default()))
        }
        Some(other) => anyhow::bail!("unexpected _params.value storage class: {other:?}"),
    };

    serde_json::from_slice(&bytes).context("parse stored settings")
}

static SETTINGS_CACHE: LazyLock<Mutex<HashMap<usize, Settings>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Invalidate the settings cache (call after settings mutation or restore).
pub fn invalidate_cache() {
    if let Ok(mut cache) = SETTINGS_CACHE.lock() {
        cache.clear();
    }
}

/// Load the typed settings.
pub fn load(conn: &Connection) -> Result<Settings> {
    let raw = load_raw(conn)?;
    if raw.is_null() {
        return Ok(Settings::default());
    }
    serde_json::from_value(raw).context("parse stored settings")
}

/// Persist settings, keeping the oracle's BLOB storage class and key order.
pub fn save(conn: &Connection, settings: &Settings) -> Result<()> {
    let json = serde_json::to_vec(settings).context("serialize settings")?;
    conn.execute(
        "INSERT INTO _params (id, value) VALUES (?1, ?2)
         ON CONFLICT(id) DO UPDATE SET value = excluded.value,
                                       updated = strftime('%Y-%m-%d %H:%M:%fZ', 'now')",
        rusqlite::params![PARAM_ID, json],
    )
    .context("save settings")?;
    Ok(())
}

/// Keep the historical `save_raw` name for callers that already hold a `Value`.
pub fn save_raw(conn: &Connection, settings: &Value) -> Result<()> {
    let typed: Settings =
        serde_json::from_value(settings.clone()).context("parse settings for save")?;
    save(conn, &typed)
}

/// `PATCH /api/settings`: bind `patch` onto the stored settings.
///
/// Objects merge recursively, arrays and scalars are replaced, `null` resets
/// to the zero value (see [`null_default`]). Unknown keys are ignored later by
/// the deserializer, exactly like Go's struct unmarshalling.
pub fn load_with_patch(conn: &Connection, patch: &Value) -> Result<Settings> {
    let mut stored = load_raw(conn)?;
    if !stored.is_object() {
        stored = Value::Object(Default::default());
    }
    merge_json(&mut stored, patch);
    serde_json::from_value(stored).context("apply settings patch")
}

fn merge_json(target: &mut Value, patch: &Value) {
    match (target, patch) {
        (Value::Object(target), Value::Object(patch)) => {
            for (key, value) in patch {
                match target.get_mut(key) {
                    Some(slot) => merge_json(slot, value),
                    None => {
                        target.insert(key.clone(), value.clone());
                    }
                }
            }
        }
        (target, patch) => *target = patch.clone(),
    }
}

/// The JSON served by `GET /api/settings` and returned by `PATCH`.
pub fn api_json(conn: &Connection) -> Result<Value> {
    Ok(load(conn)?.to_api_json())
}

impl Settings {
    /// `Settings.MarshalJSON`: sensitive fields are masked, so they never
    /// appear in an API response.
    pub fn to_api_json(&self) -> Value {
        let mut value = serde_json::to_value(self).expect("settings serialize");
        if let Some(obj) = value.as_object_mut() {
            if let Some(smtp) = obj.get_mut("smtp").and_then(Value::as_object_mut) {
                smtp.remove("password");
            }
            if let Some(s3) = obj.get_mut("s3").and_then(Value::as_object_mut) {
                s3.remove("secret");
            }
            if let Some(s3) = obj
                .get_mut("backups")
                .and_then(Value::as_object_mut)
                .and_then(|backups| backups.get_mut("s3"))
                .and_then(Value::as_object_mut)
            {
                s3.remove("secret");
            }
        }
        value
    }
}

// ---------------------------------------------------------------------------
// Validation (`Settings.PostValidate` and the nested `Validate` methods)
// ---------------------------------------------------------------------------

/// `Settings.PostValidate`.
pub fn validate(settings: &Settings) -> Errors {
    let mut errs = Errors::new();
    push(
        &mut errs,
        "superuserIPs",
        validate_ip_list(&settings.superuser_ips),
    );
    push(&mut errs, "meta", settings.meta.validate());
    push(&mut errs, "logs", settings.logs.validate());
    push(&mut errs, "smtp", settings.smtp.validate());
    push(&mut errs, "s3", settings.s3.validate());
    push(&mut errs, "backups", settings.backups.validate());
    push(&mut errs, "batch", settings.batch.validate());
    push(&mut errs, "rateLimits", settings.rate_limits.validate());
    errs
}

/// `validation.Each(validation.Required, validators.IPOrSubnet)`.
fn validate_ip_list(items: &[String]) -> Option<Node> {
    let mut errs = Errors::new();
    for (i, item) in items.iter().enumerate() {
        let node = if item.is_empty() {
            Some(required())
        } else if ip_or_subnet(item).is_none() {
            Some(leaf(
                "validation_invlaid_ip_or_subnet",
                "Invalid IP or CIDR subnet.",
            ))
        } else {
            None
        };
        push(&mut errs, &i.to_string(), node);
    }
    if errs.is_empty() {
        None
    } else {
        Some(Node::Branch(errs))
    }
}

impl MetaConfig {
    fn validate(&self) -> Option<Node> {
        let mut errs = Errors::new();
        // validation.Length(7, 7) then is.HexColor
        if !self.accent_color.is_empty() {
            if self.accent_color.len() != 7 {
                push(&mut errs, "accentColor", length(&self.accent_color, 7, 7));
            } else if !is_hex_color(&self.accent_color) {
                push(
                    &mut errs,
                    "accentColor",
                    Some(leaf(
                        "validation_is_hex_color",
                        "must be a valid hexadecimal color code",
                    )),
                );
            }
        }
        push(&mut errs, "appName", required_or_length(&self.app_name, 1, 255));
        push(&mut errs, "appURL", required_or_url(&self.app_url));
        push(
            &mut errs,
            "senderName",
            required_or_length(&self.sender_name, 1, 255),
        );
        push(&mut errs, "senderAddress", email_then_required(&self.sender_address));
        branch(errs)
    }
}

impl LogsConfig {
    fn validate(&self) -> Option<Node> {
        let mut errs = Errors::new();
        push(
            &mut errs,
            "maxDataSize",
            min(self.max_data_size, 0).or_else(|| max(self.max_data_size, MAX_SAFE_JSON_INT)),
        );
        push(
            &mut errs,
            "maxDays",
            min(self.max_days, 0).or_else(|| max(self.max_days, MAX_SAFE_JSON_INT)),
        );
        push(&mut errs, "minLevel", max(self.min_level, MAX_SAFE_JSON_INT));
        branch(errs)
    }
}

impl SmtpConfig {
    fn validate(&self) -> Option<Node> {
        let mut errs = Errors::new();
        // validation.When(enabled, Required), is.Host
        let host = if self.enabled && self.host.is_empty() {
            Some(required())
        } else if !self.host.is_empty() && !is_host(&self.host) {
            Some(leaf(
                "validation_is_host",
                "Must be a valid IP address or DNS name.",
            ))
        } else {
            None
        };
        push(&mut errs, "host", host);
        // validation.When(enabled, Required), validation.Min(0)
        let port = if self.enabled && self.port == 0 {
            Some(required())
        } else {
            min(self.port, 0)
        };
        push(&mut errs, "port", port);
        // validation.In(LOGIN, PLAIN) — empty is valid
        let auth_method = if !self.auth_method.is_empty()
            && self.auth_method != "LOGIN"
            && self.auth_method != "PLAIN"
        {
            Some(invalid_in())
        } else {
            None
        };
        push(&mut errs, "authMethod", auth_method);
        // is.Host
        let local_name = if !self.local_name.is_empty() && !is_host(&self.local_name) {
            Some(leaf(
                "validation_is_host",
                "Must be a valid IP address or DNS name.",
            ))
        } else {
            None
        };
        push(&mut errs, "localName", local_name);
        branch(errs)
    }
}

impl S3Config {
    fn validate(&self) -> Option<Node> {
        let mut errs = Errors::new();
        // is.URL then When(enabled, Required)
        let endpoint = if !self.endpoint.is_empty() && !is_url(&self.endpoint) {
            Some(leaf("validation_is_url", "must be a valid URL"))
        } else if self.enabled && self.endpoint.is_empty() {
            Some(required())
        } else {
            None
        };
        push(&mut errs, "endpoint", endpoint);
        for (key, value) in [
            ("bucket", &self.bucket),
            ("region", &self.region),
            ("accessKey", &self.access_key),
            ("secret", &self.secret),
        ] {
            push(
                &mut errs,
                key,
                if self.enabled && value.is_empty() {
                    Some(required())
                } else {
                    None
                },
            );
        }
        branch(errs)
    }
}

impl BackupsConfig {
    fn validate(&self) -> Option<Node> {
        let mut errs = Errors::new();
        push(&mut errs, "s3", self.s3.validate());
        push(&mut errs, "cron", check_cron_expression(&self.cron));
        let cron_max_keep = if !self.cron.is_empty() && self.cron_max_keep == 0 {
            Some(required())
        } else {
            min(self.cron_max_keep, 1)
        };
        push(&mut errs, "cronMaxKeep", cron_max_keep);
        branch(errs)
    }
}

impl BatchConfig {
    fn validate(&self) -> Option<Node> {
        let mut errs = Errors::new();
        let max_requests = if self.enabled && self.max_requests == 0 {
            Some(required())
        } else {
            min(self.max_requests, 0)
        };
        push(&mut errs, "maxRequests", max_requests);
        let timeout = if self.enabled && self.timeout == 0 {
            Some(required())
        } else {
            min(self.timeout, 0)
        };
        push(&mut errs, "timeout", timeout);
        push(&mut errs, "maxBodySize", min(self.max_body_size, 0));
        branch(errs)
    }
}

impl RateLimitsConfig {
    fn validate(&self) -> Option<Node> {
        let mut errs = Errors::new();
        // Note: the oracle reports element errors before the conflict check,
        // so a single invalid rule hides a duplicate-label conflict.
        let mut rule_errs = Errors::new();
        for (i, rule) in self.rules.iter().enumerate() {
            push(&mut rule_errs, &i.to_string(), rule.validate());
        }
        let rules = if !rule_errs.is_empty() {
            Some(Node::Branch(rule_errs))
        } else if self.enabled && self.rules.is_empty() {
            Some(required())
        } else {
            check_unique_rule_labels(&self.rules)
        };
        push(&mut errs, "rules", rules);
        push(&mut errs, "excludedIPs", validate_ip_list(&self.excluded_ips));
        branch(errs)
    }
}

impl RateLimitRule {
    fn validate(&self) -> Option<Node> {
        let mut errs = Errors::new();
        let label = if self.label.is_empty() {
            Some(required())
        } else if !valid_rate_limit_label(&self.label) {
            Some(leaf("validation_match_invalid", "must be in a valid format"))
        } else {
            None
        };
        push(&mut errs, "label", label);
        let max_requests = if self.max_requests == 0 {
            Some(required())
        } else {
            min(self.max_requests, 1)
        };
        push(&mut errs, "maxRequests", max_requests);
        let duration = if self.duration == 0 {
            Some(required())
        } else {
            min(self.duration, 1)
        };
        push(&mut errs, "duration", duration);
        let audience = if !self.audience.is_empty()
            && self.audience != "@guest"
            && self.audience != "@auth"
        {
            Some(invalid_in())
        } else {
            None
        };
        push(&mut errs, "audience", audience);
        branch(errs)
    }
}

/// `core.checkUniqueRuleLabel`.
fn check_unique_rule_labels(rules: &[RateLimitRule]) -> Option<Node> {
    let mut existing: Vec<String> = Vec::new();
    for (i, rule) in rules.iter().enumerate() {
        let full_key = format!("{}@@{}", rule.label, rule.audience);
        let conflicts = existing
            .iter()
            .any(|key| key.starts_with(&full_key) || full_key.starts_with(key));
        if conflicts {
            let mut inner = Errors::new();
            inner.insert(
                "label".to_string(),
                leaf_with_params(
                    "validation_conflicting_rate_limit_rule",
                    format!(
                        "Rate limit rule configuration with label {} already exists or conflicts with another rule.",
                        rule.label
                    ),
                    json!({ "label": rule.label }),
                ),
            );
            let mut outer = Errors::new();
            outer.insert(i.to_string(), Node::Branch(inner));
            return Some(Node::Branch(outer));
        }
        existing.push(full_key);
    }
    None
}

/// `validation.Field(&c.AppName, validation.Required, validation.Length(1, 255))`
fn required_or_length(value: &str, min_len: usize, max_len: usize) -> Option<Node> {
    if value.is_empty() {
        Some(required())
    } else {
        length(value, min_len, max_len)
    }
}

/// `validation.Field(&c.AppURL, validation.Required, is.URL)`
fn required_or_url(value: &str) -> Option<Node> {
    if value.is_empty() {
        Some(required())
    } else if !is_url(value) {
        Some(leaf("validation_is_url", "must be a valid URL"))
    } else {
        None
    }
}

/// `validation.Field(&c.SenderAddress, is.EmailFormat, validation.Required)`
fn email_then_required(value: &str) -> Option<Node> {
    if !value.is_empty() && !is_email(value) {
        Some(leaf("validation_is_email", "must be a valid email address"))
    } else if value.is_empty() {
        Some(required())
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Value checks (ports of the validators used by the settings model)
// ---------------------------------------------------------------------------

/// `validators.IPOrSubnet`: an IP address or a CIDR subnet.
pub fn ip_or_subnet(value: &str) -> Option<()> {
    if let Ok(addr) = IpAddr::from_str(value) {
        let _ = addr;
        return Some(());
    }
    let (addr, prefix) = value.split_once('/')?;
    let addr = IpAddr::from_str(addr).ok()?;
    let prefix: u32 = prefix.parse().ok()?;
    let max = match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix > max {
        return None;
    }
    Some(())
}

/// `is.HexColor` (`govalidator.IsHexcolor`).
fn is_hex_color(value: &str) -> bool {
    let digits = value.strip_prefix('#').unwrap_or(value);
    matches!(digits.len(), 3 | 6) && digits.chars().all(|c| c.is_ascii_hexdigit())
}

/// `is.EmailFormat` (`govalidator.IsEmail`), simplified to the ASCII subset.
fn is_email(value: &str) -> bool {
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    if local.is_empty()
        || local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
        || !local.chars().all(|c| {
            c.is_ascii_alphanumeric() || "!#$%&'*+-/=?^_`{|}~.".contains(c)
        })
    {
        return false;
    }
    if domain.is_empty() || domain.starts_with('.') || domain.contains("..") {
        return false;
    }
    let domain = domain.strip_suffix('.').unwrap_or(domain);
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    let (tld, host_labels) = labels.split_last().expect("at least two labels");
    if tld.is_empty() || !tld.chars().all(|c| c.is_ascii_alphabetic()) {
        return false;
    }
    host_labels.iter().all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

/// `is.URL` (`govalidator.IsURL`), covering the shapes PocketBase accepts.
fn is_url(value: &str) -> bool {
    if value.is_empty() || value.chars().count() >= 2083 || value.starts_with('.') {
        return false;
    }
    if value.starts_with("//") || value.chars().any(char::is_whitespace) {
        return false;
    }

    // Explicit scheme (`http://…`, `ftp://…`, …).
    if let Some((scheme, rest)) = value.split_once("://") {
        if !valid_scheme(scheme) || rest.is_empty() {
            return false;
        }
        let host = rest.split(['/', '?', '#']).next().unwrap_or("");
        return valid_host_with_port(host);
    }

    // Any other scheme-like value (`mailto:a@b.c`, `localhost:8090`, …).
    if let Some((scheme, rest)) = value.split_once(':') {
        if valid_scheme(scheme) && !rest.is_empty() {
            return true;
        }
    }

    // Scheme-less host (`example.com`, `x.com/path`).
    let host = value.split(['/', '?', '#']).next().unwrap_or("");
    !host.is_empty() && (host.contains('.') || is_ip(host) || host.contains(':'))
}

fn valid_scheme(value: &str) -> bool {
    let mut chars = value.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

fn valid_host_with_port(value: &str) -> bool {
    let host = value.split('@').next_back().unwrap_or(value);
    if host.starts_with('[') {
        // IPv6 literal: `[::1]` or `[::1]:80`
        let Some((inside, after)) = host.strip_prefix('[').and_then(|h| h.split_once(']')) else {
            return false;
        };
        if !is_ip(inside) {
            return false;
        }
        return after.is_empty() || after.strip_prefix(':').is_some_and(|p| p.parse::<u16>().is_ok());
    }
    let (name, port) = match host.rsplit_once(':') {
        Some((name, port)) => (name, Some(port)),
        None => (host, None),
    };
    if name.is_empty() {
        return false;
    }
    if let Some(port) = port {
        if !port.is_empty() && port.parse::<u16>().is_err() {
            return false;
        }
    }
    is_ip(name) || is_dns_name(name)
}

fn is_ip(value: &str) -> bool {
    IpAddr::from_str(value).is_ok()
}

/// `govalidator.IsDNSName`.
fn is_dns_name(value: &str) -> bool {
    if value.is_empty() || value.replace('.', "").len() > 255 || is_ip(value) {
        return false;
    }
    let value = value
        .strip_suffix('.')
        .or_else(|| value.strip_suffix('_'))
        .unwrap_or(value);
    value.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.chars().next().is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
            && label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    })
}

/// `is.Host` (`govalidator.IsHost`).
fn is_host(value: &str) -> bool {
    is_ip(value) || is_dns_name(value)
}

/// `rateLimitRuleLabelRegex`
fn valid_rate_limit_label(value: &str) -> bool {
    // ^(\w+ /[\w/-]*|/[\w/-]*|^\w+:\w+|\*:\w+|\w+)$
    fn word(s: &str) -> bool {
        !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    }
    fn path(s: &str) -> bool {
        s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '/' || c == '-')
    }
    if let Some(rest) = value.strip_prefix('/') {
        return path(rest);
    }
    if let Some((method, rest)) = value.split_once(' ') {
        return word(method) && rest.starts_with('/') && path(&rest[1..]);
    }
    if let Some((left, right)) = value.split_once(':') {
        return (word(left) || left == "*") && word(right);
    }
    word(value)
}

/// `checkCronExpression`: empty is valid, otherwise `cron.NewSchedule`.
fn check_cron_expression(value: &str) -> Option<Node> {
    if value.is_empty() {
        return None;
    }
    match parse_cron(value) {
        Ok(()) => None,
        Err(message) => Some(leaf("validation_invalid_cron", message)),
    }
}

/// `cron.NewSchedule` (validation only: the slots themselves are irrelevant).
fn parse_cron(expr: &str) -> Result<(), String> {
    crate::cron::Schedule::new(expr).map(|_| ())
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
    fn defaults_match_the_seed_asset() {
        let conn = fresh();
        assert_eq!(load(&conn).unwrap(), Settings::default());
        assert_eq!(Settings::default().meta.app_name, "Acme");
    }

    #[test]
    fn stored_form_keeps_the_oracle_key_order() {
        let settings = Settings::default();
        let serialized = serde_json::to_string(&settings).unwrap();
        // Re-serializing the asset preserves its key order, so this compares
        // both the keys and their order (and the compact, BLOB-ready form).
        let expected: Value = serde_json::from_str(DEFAULT_SETTINGS).unwrap();
        assert_eq!(serialized, serde_json::to_string(&expected).unwrap());
        assert!(serialized.starts_with(
            r#"{"superuserIPs":[],"smtp":{"enabled":false,"port":587,"host":"smtp.example.com""#
        ));
    }

    #[test]
    fn api_json_masks_every_sensitive_field() {
        let mut settings = Settings::default();
        settings.smtp.password = "hunter2".into();
        settings.s3.secret = "s3secret".into();
        settings.backups.s3.secret = "backupsecret".into();
        let json = settings.to_api_json();
        assert!(json["smtp"].get("password").is_none());
        assert!(json["s3"].get("secret").is_none());
        assert!(json["backups"]["s3"].get("secret").is_none());
        // ... while the stored form keeps them.
        let stored = serde_json::to_value(&settings).unwrap();
        assert_eq!(stored["smtp"]["password"], "hunter2");
        assert_eq!(stored["s3"]["secret"], "s3secret");
        assert_eq!(stored["backups"]["s3"]["secret"], "backupsecret");
    }

    #[test]
    fn patch_merges_objects_and_replaces_arrays() {
        let conn = fresh();
        let patch = json!({
            "meta": {"appName": "My App"},
            "backups": {"s3": {"bucket": "mybucket"}},
            "rateLimits": {"rules": [{"label": "*:auth", "maxRequests": 9, "duration": 9}]},
        });
        let patched = load_with_patch(&conn, &patch).unwrap();
        assert_eq!(patched.meta.app_name, "My App");
        // untouched siblings survive the nested merge
        assert_eq!(patched.meta.app_url, "http://localhost:8090");
        assert_eq!(patched.backups.s3.bucket, "mybucket");
        assert_eq!(patched.backups.cron_max_keep, 3);
        assert_eq!(patched.s3.bucket, "");
        // arrays are replaced wholesale
        assert_eq!(patched.rate_limits.rules.len(), 1);
        assert_eq!(patched.rate_limits.rules[0].max_requests, 9);
    }

    #[test]
    fn patch_null_resets_to_the_zero_value() {
        let conn = fresh();
        let patched = load_with_patch(
            &conn,
            &json!({
                "meta": null,
                "smtp": {"enabled": null},
                "superuserIPs": null,
            }),
        )
        .unwrap();
        assert_eq!(patched.meta, MetaConfig::default());
        assert_eq!(patched.smtp.enabled, false);
        assert!(patched.superuser_ips.is_empty());
        // `meta: null` makes the required fields fail, like the oracle.
        let errs = validate(&patched);
        let meta = match &errs["meta"] {
            Node::Branch(errors) => errors,
            other => panic!("expected nested errors, got {other:?}"),
        };
        assert_eq!(meta["appName"], required());
    }

    #[test]
    fn patch_round_trips_through_the_database() {
        let conn = fresh();
        let patched = load_with_patch(&conn, &json!({"meta": {"appName": "Saved"}})).unwrap();
        save(&conn, &patched).unwrap();
        let reloaded = load(&conn).unwrap();
        assert_eq!(reloaded.meta.app_name, "Saved");
        // still a BLOB, like the oracle
        let kind: String = conn
            .query_row("SELECT typeof(value) FROM _params WHERE id = 'settings'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(kind, "blob");
    }

    #[test]
    fn validation_messages_match_the_oracle() {
        let mut settings = Settings::default();
        settings.meta.accent_color = "#gggggg".into();
        settings.meta.app_url = "nope".into();
        settings.meta.sender_address = "nope".into();
        let errs = validate(&settings);
        let meta = match &errs["meta"] {
            Node::Branch(errors) => errors,
            other => panic!("expected nested errors, got {other:?}"),
        };
        assert_eq!(
            meta["accentColor"],
            leaf("validation_is_hex_color", "must be a valid hexadecimal color code")
        );
        assert_eq!(meta["appURL"], leaf("validation_is_url", "must be a valid URL"));
        assert_eq!(
            meta["senderAddress"],
            leaf("validation_is_email", "must be a valid email address")
        );

        let mut settings = Settings::default();
        settings.meta.accent_color = "red".into();
        settings.meta.app_name = "a".repeat(256);
        let errs = validate(&settings);
        let meta = match &errs["meta"] {
            Node::Branch(errors) => errors,
            other => panic!("expected nested errors, got {other:?}"),
        };
        assert_eq!(
            meta["accentColor"],
            leaf_with_params(
                "validation_length_invalid",
                "the length must be exactly {{.min}}",
                json!({"min": 7, "max": 7})
            )
        );
        assert_eq!(
            meta["appName"],
            leaf_with_params(
                "validation_length_out_of_range",
                "the length must be between {{.min}} and {{.max}}",
                json!({"min": 1, "max": 255})
            )
        );
    }

    #[test]
    fn validation_reports_element_errors_before_rule_conflicts() {
        let mut settings = Settings::default();
        settings.rate_limits.rules = vec![
            RateLimitRule {
                label: "*:auth".into(),
                duration: 1,
                max_requests: 1,
                ..Default::default()
            },
            RateLimitRule {
                label: "*:auth".into(),
                duration: 1,
                max_requests: 0,
                ..Default::default()
            },
        ];
        let errs = validate(&settings);
        let rules = match &errs["rateLimits"] {
            Node::Branch(errors) => match &errors["rules"] {
                Node::Branch(errors) => errors,
                other => panic!("expected nested rules, got {other:?}"),
            },
            other => panic!("expected nested errors, got {other:?}"),
        };
        assert_eq!(rules.len(), 1);
        assert!(matches!(&rules["1"], Node::Branch(e) if e["maxRequests"] == required()));

        // Two valid duplicates: the conflict check runs and reports index 1.
        settings.rate_limits.rules[1].max_requests = 2;
        let errs = validate(&settings);
        let rules = match &errs["rateLimits"] {
            Node::Branch(errors) => match &errors["rules"] {
                Node::Branch(errors) => errors,
                other => panic!("expected nested rules, got {other:?}"),
            },
            other => panic!("expected nested errors, got {other:?}"),
        };
        assert!(matches!(&rules["1"], Node::Branch(e)
            if e["label"].clone() == leaf_with_params(
                "validation_conflicting_rate_limit_rule",
                "Rate limit rule configuration with label *:auth already exists or conflicts with another rule.",
                json!({"label": "*:auth"})
            )));
    }

    #[test]
    fn cron_validation_ports_the_parser() {
        assert_eq!(check_cron_expression(""), None);
        assert_eq!(check_cron_expression("* * * * *"), None);
        assert_eq!(check_cron_expression("@daily"), None);
        assert_eq!(check_cron_expression("*/5 * * * *"), None);
        assert_eq!(check_cron_expression("1-30/2 * * * *"), None);
        assert!(check_cron_expression("nope").is_some());
        assert!(check_cron_expression("* * * *").is_some());
        assert!(check_cron_expression("60 * * * *").is_some());
        assert_eq!(
            check_cron_expression("nope"),
            Some(leaf(
                "validation_invalid_cron",
                "invalid cron expression - must be a valid macro or to have exactly 5 space separated segments"
            ))
        );
    }

    #[test]
    fn value_checks_follow_the_oracle() {
        for url in [
            "http://localhost:8090",
            "localhost:8090",
            "example.com",
            "ftp://x.com",
            "http://x",
            "http://x.com/path?a=1",
            "mailto:a@b.c",
            "x.com:8080",
            "http://192.168.1.1:80",
        ] {
            assert!(is_url(url), "{url} should be a valid URL");
        }
        for url in ["nope", "//x.com", "x", "http://", ".com"] {
            assert!(!is_url(url), "{url} should be invalid");
        }

        for email in ["a@b.c", "A@B.CO", "a@b.c.d", "a+b@b.c"] {
            assert!(is_email(email), "{email} should be valid");
        }
        for email in ["a@b", "a b@c.d", "@b.c", "a@"] {
            assert!(!is_email(email), "{email} should be invalid");
        }

        for host in ["smtp.example.com", "localhost", "192.168.1.1", "smtp_example", "x", "2001:db8::1"] {
            assert!(is_host(host), "{host} should be a valid host");
        }
        for host in ["-bad", "a..b"] {
            assert!(!is_host(host), "{host} should be invalid");
        }

        assert!(ip_or_subnet("127.0.0.1").is_some());
        assert!(ip_or_subnet("10.0.0.0/8").is_some());
        assert!(ip_or_subnet("2001:db8::/32").is_some());
        assert!(ip_or_subnet("nope").is_none());
        assert!(ip_or_subnet("10.0.0.0/40").is_none());
    }
}
