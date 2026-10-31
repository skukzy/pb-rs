//! Settings endpoints.
//!
//! `GET /api/settings` serves the masked settings (`Settings.MarshalJSON`);
//! `PATCH /api/settings` binds the submitted JSON onto a clone of the current
//! settings, validates and persists it (`apis/settings.go: settingsSet`).

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use pb_core::settings::{self, Settings};
use serde_json::Value;

use crate::auth::{require_superuser, Db};
use crate::error::ApiError;

/// `GET /api/settings`
pub async fn list(State(db): State<Db>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    require_superuser(&db, &headers)?;

    let conn = db
        .lock()
        .map_err(|_| ApiError::internal("database lock poisoned"))?;
    let settings = settings::api_json(&conn)
        .map_err(|e| ApiError::internal(format!("failed to load settings: {e}")))?;
    Ok(Json(settings))
}

/// `e.BadRequestError("An error occurred while loading the submitted data.", err)`
fn load_error() -> ApiError {
    ApiError::bad_request("An error occurred while loading the submitted data.")
}

/// `PATCH /api/settings`
pub async fn set(
    State(db): State<Db>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    require_superuser(&db, &headers)?;

    let patch = bind_body(&headers, &body)?;

    // A JSON `null` body nils the target pointer in Go and the save panics;
    // the router recovers it as a generic 500.
    if patch.as_ref().is_some_and(Value::is_null) {
        return Err(ApiError::internal(
            "Something went wrong while processing your request.",
        ));
    }

    let conn = db
        .lock()
        .map_err(|_| ApiError::internal("database lock poisoned"))?;

    let settings = match &patch {
        // A type mismatch while binding is a load error, not an internal one.
        Some(patch) => settings::load_with_patch(&conn, patch).map_err(|_| load_error())?,
        None => settings::load(&conn).map_err(|e| {
            ApiError::internal(format!("failed to load settings: {e}"))
        })?,
    };

    let errors = settings::validate(&settings);
    if !errors.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "An error occurred while saving the new settings.",
            settings::errors_to_value(&errors),
        )
        .with_raw_data(pb_core::validation::errors_to_log_value(&errors)));
    }

    // The save hook normalizes nothing else; persist as-is.
    settings::save(&conn, &settings)
        .map_err(|e| ApiError::internal(format!("failed to save settings: {e}")))?;

    // Invalidate settings cache and rate limiter store.
    settings::invalidate_cache();
    crate::rate_limit::reset();

    let saved: Settings = settings::load(&conn)
        .map_err(|e| ApiError::internal(format!("failed to reload settings: {e}")))?;
    Ok(Json(saved.to_api_json()))
}

/// `router.Event.BindBody` for the settings endpoint.
///
/// Returns `None` when the request carries no bindable data: an empty body, or
/// a form-encoded body (PocketBase binds those through form tags, which the
/// admin UI never uses for settings).
fn bind_body(headers: &HeaderMap, body: &[u8]) -> Result<Option<Value>, ApiError> {
    crate::body::bind_json(headers, body).map_err(|_| load_error())
}

fn form_body(headers: &HeaderMap, body: &[u8]) -> Result<serde_json::Map<String, Value>, ApiError> {
    crate::records::require_json(headers)?;
    crate::records::parse_json_body(&axum::body::Bytes::copy_from_slice(body))
}

fn required_leaf() -> Value {
    crate::error::validation_required()
}

fn length_between(min: usize, max: usize) -> Value {
    serde_json::json!({
        "code": "validation_length_out_of_range",
        "message": format!("the length must be between {min} and {max}"),
        "params": {"max": max, "min": min},
    })
}

fn length_exact(length: usize) -> Value {
    serde_json::json!({
        "code": "validation_length_invalid",
        "message": format!("the length must be exactly {length}"),
        "params": {"max": length, "min": length},
    })
}

fn min_leaf(threshold: i64) -> Value {
    serde_json::json!({
        "code": "validation_min_greater_equal_than_required",
        "message": format!("must be no less than {threshold}"),
        "params": {"threshold": threshold},
    })
}

fn max_leaf(threshold: i64) -> Value {
    serde_json::json!({
        "code": "validation_max_less_equal_than_required",
        "message": format!("must be no greater than {threshold}"),
        "params": {"threshold": threshold},
    })
}

/// `POST /api/settings/test/email`
pub async fn test_email(
    State(db): State<Db>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    require_superuser(&db, &headers)?;
    let form = form_body(&headers, &body)?;

    let email = form.get("email").and_then(Value::as_str).unwrap_or("");
    let template = form.get("template").and_then(Value::as_str).unwrap_or("");
    let collection = form.get("collection").and_then(Value::as_str).unwrap_or("");

    let mut errors = serde_json::Map::new();
    if !collection.is_empty() {
        if collection.chars().count() > 255 {
            errors.insert("collection".into(), length_between(1, 255));
        } else {
            let valid = {
                let conn = db
                    .lock()
                    .map_err(|_| ApiError::internal("database lock poisoned"))?;
                pb_core::collections::Collection::find(&conn, collection)
                    .ok()
                    .flatten()
                    .is_some_and(|c| c.is_auth())
            };
            if !valid {
                errors.insert(
                    "collection".into(),
                    serde_json::json!({
                        "code": "validation_invalid_auth_collection",
                        "message": "must be a valid auth collection id or name",
                    }),
                );
            }
        }
    }

    if email.is_empty() {
        errors.insert("email".into(), required_leaf());
    } else if email.chars().count() > 255 {
        errors.insert("email".into(), length_between(1, 255));
    } else if !pb_core::validators::is_email(email) {
        errors.insert(
            "email".into(),
            serde_json::json!({
                "code": "validation_is_email",
                "message": "must be a valid email address",
            }),
        );
    }

    if template.is_empty() {
        errors.insert("template".into(), required_leaf());
    } else if !matches!(
        template,
        "verification" | "password-reset" | "email-change" | "otp" | "login-alert"
    ) {
        errors.insert(
            "template".into(),
            serde_json::json!({
                "code": "validation_in_invalid",
                "message": "must be a valid value",
            }),
        );
    }

    if !errors.is_empty() {
        return Err(ApiError::form_validation(
            "Failed to send the test email.",
            Value::Object(errors),
        ));
    }

    // With `smtp.enabled=false` the oracle's mailer is a no-op.
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /api/settings/test/s3`
pub async fn test_s3(
    State(db): State<Db>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    require_superuser(&db, &headers)?;
    let form = form_body(&headers, &body)?;

    let filesystem = form.get("filesystem").and_then(Value::as_str).unwrap_or("");
    let mut errors = serde_json::Map::new();
    if filesystem.is_empty() {
        errors.insert("filesystem".into(), required_leaf());
    } else if !matches!(filesystem, "storage" | "backups") {
        errors.insert(
            "filesystem".into(),
            serde_json::json!({
                "code": "validation_in_invalid",
                "message": "must be a valid value",
            }),
        );
    }
    if !errors.is_empty() {
        return Err(ApiError::form_validation(
            "Failed to test the S3 filesystem.",
            Value::Object(errors),
        ));
    }

    let enabled = {
        let conn = db
            .lock()
            .map_err(|_| ApiError::internal("database lock poisoned"))?;
        let settings = settings::load(&conn)
            .map_err(|e| ApiError::internal(format!("failed to load settings: {e}")))?;
        if filesystem == "backups" {
            settings.backups.s3.enabled
        } else {
            settings.s3.enabled
        }
    };
    if !enabled {
        return Err(ApiError::bad_request(
            "Failed to test the S3 filesystem. Raw error: \nS3 storage filesystem is not enabled",
        )
        .with_raw_data(serde_json::json!("S3 storage filesystem is not enabled")));
    }

    Err(ApiError::bad_request(
        "Failed to test the S3 filesystem. Raw error: \nS3 storage filesystem is not supported by this build",
    ))
}

/// `POST /api/settings/apple/generate-client-secret`
pub async fn apple_client_secret(
    State(db): State<Db>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    require_superuser(&db, &headers)?;
    let _ = db;
    let form = form_body(&headers, &body)?;

    let client_id = form.get("clientId").and_then(Value::as_str).unwrap_or("");
    let team_id = form.get("teamId").and_then(Value::as_str).unwrap_or("");
    let key_id = form.get("keyId").and_then(Value::as_str).unwrap_or("");
    let private_key = form.get("privateKey").and_then(Value::as_str).unwrap_or("");
    let duration = form
        .get("duration")
        .and_then(Value::as_i64)
        .unwrap_or(0);

    let mut errors = serde_json::Map::new();
    if client_id.is_empty() {
        errors.insert("clientId".into(), required_leaf());
    }
    if team_id.is_empty() {
        errors.insert("teamId".into(), required_leaf());
    } else if team_id.chars().count() != 10 {
        errors.insert("teamId".into(), length_exact(10));
    }
    if key_id.is_empty() {
        errors.insert("keyId".into(), required_leaf());
    } else if key_id.chars().count() != 10 {
        errors.insert("keyId".into(), length_exact(10));
    }
    if private_key.is_empty() {
        errors.insert("privateKey".into(), required_leaf());
    } else if !is_private_key_block(private_key) {
        errors.insert(
            "privateKey".into(),
            serde_json::json!({
                "code": "validation_match_invalid",
                "message": "must be in a valid format",
            }),
        );
    }
    if duration == 0 {
        errors.insert("duration".into(), required_leaf());
    } else if duration < 1 {
        errors.insert("duration".into(), min_leaf(1));
    } else if duration > 15_777_000 {
        errors.insert("duration".into(), max_leaf(15_777_000));
    }
    if !errors.is_empty() {
        return Err(ApiError::form_validation(
            "Invalid client secret data.",
            Value::Object(errors),
        ));
    }

    match make_apple_secret(client_id, team_id, key_id, private_key, duration) {
        Ok(secret) => Ok(Json(serde_json::json!({ "secret": secret }))),
        Err(raw) => Err(ApiError::bad_request(format!(
            "Failed to generate client secret. Raw error: \n{raw}"
        ))
        .with_raw_data(Value::String(raw))),
    }
}

/// `privateKeyRegex`: a PKCS8 PEM block with at least one character of body.
fn is_private_key_block(value: &str) -> bool {
    const BEGIN: &str = "-----BEGIN PRIVATE KEY-----";
    const END: &str = "-----END PRIVATE KEY-----";
    let Some(start) = value.find(BEGIN) else {
        return false;
    };
    let rest = &value[start + BEGIN.len()..];
    let Some(end) = rest.find(END) else {
        return false;
    };
    !rest[..end].is_empty()
}

#[derive(serde::Serialize)]
struct AppleClaims {
    iss: String,
    sub: String,
    aud: Vec<String>,
    exp: i64,
    iat: i64,
}

fn make_apple_secret(
    client_id: &str,
    team_id: &str,
    key_id: &str,
    private_key: &str,
    duration: i64,
) -> Result<String, String> {
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

    let key = EncodingKey::from_ec_pem(private_key.trim().as_bytes())
        .map_err(|_| "invalid key: Key must be a PEM encoded PKCS1 or PKCS8 key".to_string())?;

    let now = pb_core::tokens::now_unix();
    let claims = AppleClaims {
        iss: team_id.to_string(),
        sub: client_id.to_string(),
        aud: vec!["https://appleid.apple.com".to_string()],
        exp: now + duration,
        iat: now,
    };
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(key_id.to_string());
    encode(&header, &claims, &key).map_err(|e| e.to_string())
}


#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{header, HeaderValue};

    fn headers(content_type: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_str(content_type).unwrap());
        headers
    }

    #[test]
    fn binds_json_and_ignores_trailing_bytes() {
        let json = headers("application/json");
        let value = bind_body(&json, br#"{"meta":{"appName":"X"}}"#)
            .unwrap()
            .unwrap();
        assert_eq!(value["meta"]["appName"], "X");
        // Go decodes the first value and ignores the rest.
        assert!(bind_body(&json, br#"{"meta":{}} trailing"#).is_ok());
    }

    #[test]
    fn empty_body_is_a_no_op() {
        assert_eq!(bind_body(&headers("application/json"), b"").unwrap(), None);
    }

    #[test]
    fn form_bodies_are_accepted_as_a_no_op() {
        assert_eq!(
            bind_body(&headers("application/x-www-form-urlencoded"), b"meta.appName=X").unwrap(),
            None
        );
    }

    #[test]
    fn unsupported_content_types_fail_to_bind() {
        assert!(bind_body(&headers("text/plain"), br#"{"meta":{}}"#).is_err());
    }

    #[test]
    fn invalid_json_fails_to_bind() {
        assert!(bind_body(&headers("application/json"), b"{").is_err());
    }
}
