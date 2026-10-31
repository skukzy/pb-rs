//! Record tokens: HS256 JWTs, exactly as `core/record_tokens.go` mints them.
//!
//! The signing key is the **concatenation** of the record's `tokenKey` and the
//! collection's token config secret, which is why rotating either invalidates
//! every issued token.

use anyhow::{Context, Result};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

pub const TYPE_AUTH: &str = "auth";
pub const TYPE_FILE: &str = "file";
pub const TYPE_VERIFICATION: &str = "verification";
pub const TYPE_PASSWORD_RESET: &str = "passwordReset";
pub const TYPE_EMAIL_CHANGE: &str = "emailChange";

/// The claims PocketBase puts in a record token.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RecordClaims {
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub id: String,
    #[serde(rename = "collectionId", default)]
    pub collection_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refreshable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_email: Option<String>,
    #[serde(default)]
    pub exp: i64,
}

impl RecordClaims {
    pub fn auth(id: &str, collection_id: &str, refreshable: bool) -> Self {
        Self {
            kind: TYPE_AUTH.into(),
            id: id.into(),
            collection_id: collection_id.into(),
            refreshable: Some(refreshable),
            email: None,
            new_email: None,
            exp: 0,
        }
    }
}

/// `security.NewJWT`: HS256 with an `exp` claim, signed with `signing_key`.
pub fn new_jwt(claims: &RecordClaims, signing_key: &str, duration_secs: i64) -> Result<String> {
    let mut claims = claims.clone();
    claims.exp = now_unix() + duration_secs;
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(signing_key.as_bytes()),
    )
    .context("sign JWT")
}

/// `security.ParseUnverifiedJWT`: read the claims without checking the signature.
///
/// The expiry is still validated (Go does this too, via
/// `jwt.WithIssuedAt()` + the default expiry validation), which is why an
/// expired token cannot be used to look up a record.
pub fn parse_unverified(token: &str) -> Result<RecordClaims> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.insecure_disable_signature_validation();
    validation.validate_exp = true;
    validation.leeway = 0;
    // Go only validates `exp` when present, so don't require it.
    validation.required_spec_claims.clear();
    let data = decode::<RecordClaims>(
        token,
        &DecodingKey::from_secret(b"unverified"),
        &validation,
    )
    .context("invalid token")?;
    Ok(data.claims)
}

/// `security.ParseJWT`: verify the signature, algorithm and expiry.
pub fn parse_jwt(token: &str, signing_key: &str) -> Result<RecordClaims> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    // Go's jwt validator allows no leeway; the crate defaults to 60 seconds.
    validation.leeway = 0;
    let data = decode::<RecordClaims>(
        token,
        &DecodingKey::from_secret(signing_key.as_bytes()),
        &validation,
    )
    .context("invalid token")?;
    Ok(data.claims)
}

/// The signing key for a record token: `tokenKey + secret`.
pub fn signing_key(token_key: &str, secret: &str) -> String {
    format!("{token_key}{secret}")
}

pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_an_auth_token() {
        let key = signing_key("tokenkey", "secret");
        let token = new_jwt(&RecordClaims::auth("abc", "col", true), &key, 60).unwrap();
        let claims = parse_jwt(&token, &key).unwrap();
        assert_eq!(claims.kind, TYPE_AUTH);
        assert_eq!(claims.id, "abc");
        assert_eq!(claims.collection_id, "col");
        assert_eq!(claims.refreshable, Some(true));
    }

    #[test]
    fn rejects_a_wrong_key() {
        let token = new_jwt(&RecordClaims::auth("abc", "col", true), "right", 60).unwrap();
        assert!(parse_jwt(&token, "wrong").is_err());
    }

    #[test]
    fn rejects_an_expired_token() {
        let token = new_jwt(&RecordClaims::auth("abc", "col", true), "k", -10).unwrap();
        assert!(parse_jwt(&token, "k").is_err());
    }
}
