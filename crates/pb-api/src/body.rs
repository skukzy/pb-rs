//! Request body binding (`tools/router/event.go: Event.BindBody`).
//!
//! Only the JSON path is implemented; form/multipart bodies are treated as a
//! no-op and XML/other content types fail, which is a documented divergence
//! (`docs/COMPATIBILITY.md`, D11). The admin UI and the official SDKs always
//! send JSON.

use axum::http::{header, HeaderMap};
use serde_json::Value;

/// Bind a JSON request body.
///
/// * `Ok(None)` — no body (`ContentLength == 0`) or a form body (unsupported).
/// * `Ok(Some(value))` — the decoded JSON value (may be `null`).
/// * `Err(())` — the body is not valid JSON, or the content type is unsupported.
///
/// The oracle decodes a single JSON value and ignores trailing bytes, so the
/// streaming decoder is used instead of `from_slice`.
pub fn bind_json(headers: &HeaderMap, body: &[u8]) -> Result<Option<Value>, ()> {
    if body.is_empty() {
        return Ok(None);
    }

    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");

    if content_type.starts_with("application/json") {
        let mut stream = serde_json::Deserializer::from_slice(body).into_iter::<Value>();
        return match stream.next() {
            Some(Ok(value)) => Ok(Some(value)),
            _ => Err(()),
        };
    }

    if content_type.starts_with("multipart/form-data")
        || content_type.starts_with("application/x-www-form-urlencoded")
    {
        return Ok(None);
    }

    // `text/xml`, `text/plain`, … — the oracle fails to bind these.
    Err(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(content_type: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, content_type.parse().unwrap());
        headers
    }

    #[test]
    fn empty_body_is_a_no_op() {
        assert_eq!(bind_json(&headers("application/json"), b""), Ok(None));
    }

    #[test]
    fn json_is_decoded_leniently() {
        assert_eq!(
            bind_json(&headers("application/json"), b"{\"a\":1},junk"),
            Ok(Some(serde_json::json!({"a": 1})))
        );
        assert_eq!(
            bind_json(&headers("application/json; charset=utf-8"), b"null"),
            Ok(Some(Value::Null))
        );
    }

    #[test]
    fn invalid_json_and_unsupported_types_fail() {
        assert_eq!(bind_json(&headers("application/json"), b"{"), Err(()));
        assert_eq!(bind_json(&headers("text/plain"), b"a=1"), Err(()));
    }

    #[test]
    fn forms_are_a_no_op() {
        assert_eq!(
            bind_json(&headers("application/x-www-form-urlencoded"), b"name=x"),
            Ok(None)
        );
        assert_eq!(
            bind_json(&headers("multipart/form-data; boundary=x"), b"--x--"),
            Ok(None)
        );
    }
}
