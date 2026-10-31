//! The PocketBase error envelope.
//!
//! Every error response is `{"data":{...},"message":"...","status":N}`. The
//! `message` strings are part of the contract (`docs/COMPATIBILITY.md` rule 3),
//! so they are copied from the oracle's recordings, not invented.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub message: String,
    pub data: Value,
    /// `ApiError.RawData()`: the unformatted error data used by the activity
    /// logger. It is not part of the public response envelope.
    pub raw_data: Option<Value>,
    /// When set, the response body is this JSON value instead of the usual
    /// `{data,message,status}` envelope (used by the MFA challenge response).
    pub raw: Option<Value>,
}

/// Attached to error responses so the activity logger can record the oracle's
/// `error`/`details` attributes without re-parsing the public body.
#[derive(Debug, Clone)]
pub struct ErrorLogData {
    pub message: String,
    pub details: Value,
}

impl ApiError {
    pub fn new(status: StatusCode, message: impl Into<String>, data: Value) -> Self {
        // `router.NewApiError`: `strings.TrimSpace(inflector.Sentenize(message))`.
        Self {
            status,
            message: pb_core::validation::sentenize(&message.into()),
            data,
            raw_data: None,
            raw: None,
        }
    }

    /// A bare JSON body with the given status (no error envelope).
    pub fn raw(status: StatusCode, body: Value) -> Self {
        Self {
            status,
            message: String::new(),
            data: json!({}),
            raw_data: None,
            raw: Some(body),
        }
    }

    /// Attach the internal raw error data used by the activity logger.
    pub fn with_raw_data(mut self, value: Value) -> Self {
        self.raw_data = Some(value);
        self
    }

    /// `router.NewBadRequestError` with an explicit message.
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message, json!({}))
    }

    /// `router.NewNotFoundError` with an explicit message.
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, message, json!({}))
    }

    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, message, json!({}))
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, message, json!({}))
    }

    /// A request body validation failure: `data` holds one entry per field.
    ///
    /// `data` is expected to contain **raw** (`validation.Error`) messages; the
    /// public envelope sentenizes them while the activity logger keeps the raw
    /// form, matching `ApiError.RawData()`.
    pub fn validation(data: Value) -> Self {
        Self::form_validation(
            "An error occurred while validating the submitted data.",
            data,
        )
    }

    /// Like [`ApiError::validation`] but with a custom (usually empty) message.
    pub fn form_validation(message: impl Into<String>, data: Value) -> Self {
        let raw_data = data.clone();
        Self::new(StatusCode::BAD_REQUEST, message, sentenize_value(data))
            .with_raw_data(raw_data)
    }

    /// `e.BadRequestError("An error occurred while loading the submitted data.", err)`
    pub fn body_load() -> Self {
        Self::bad_request("An error occurred while loading the submitted data.")
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            message,
            json!({}),
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if let Some(raw) = self.raw {
            return (self.status, Json(raw)).into_response();
        }
        let log_data = ErrorLogData {
            message: self.message.clone(),
            details: self.raw_data.clone().unwrap_or(Value::Null),
        };
        let body = json!({
            "data": self.data,
            "message": self.message,
            "status": self.status.as_u16(),
        });
        let mut response = (self.status, Json(body)).into_response();
        response.extensions_mut().insert(log_data);
        response
    }
}

/// `inflector.Sentenize` applied to every `{code,message}` leaf of an error
/// data tree (the public safe-error view).
pub fn sentenize_value(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let is_leaf = map.get("code").and_then(Value::as_str).is_some()
                && map.get("message").and_then(Value::as_str).is_some();
            if is_leaf {
                let mut out = serde_json::Map::new();
                for (key, value) in map {
                    if key == "message" {
                        let message = value.as_str().unwrap_or_default();
                        out.insert(
                            key,
                            Value::String(pb_core::validation::sentenize(message)),
                        );
                    } else {
                        out.insert(key, value);
                    }
                }
                Value::Object(out)
            } else {
                Value::Object(
                    map.into_iter()
                        .map(|(key, value)| (key, sentenize_value(value)))
                        .collect(),
                )
            }
        }
        Value::Array(items) => {
            Value::Array(items.into_iter().map(sentenize_value).collect())
        }
        other => other,
    }
}

/// A single validation failure in PocketBase's `{code,message}` shape.
///
/// The message is the raw ozzo form; [`ApiError::validation`] sentenizes it for
/// the public response.
pub fn validation_required() -> Value {
    json!({"code": "validation_required", "message": "cannot be blank"})
}

/// `validation_length_out_of_range` with the interpolated raw message.
pub fn validation_length(min: usize, max: usize) -> Value {
    json!({
        "code": "validation_length_out_of_range",
        "message": format!("the length must be between {min} and {max}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_messages_match_the_oracle_wording() {
        assert_eq!(validation_required()["message"], "cannot be blank");
        assert_eq!(
            validation_length(1, 255)["message"],
            "the length must be between 1 and 255"
        );
    }
}
