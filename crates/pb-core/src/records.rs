//! Record model: a row of a collection's table, serialized the way
//! `core.Record.MarshalJSON` does.
//!
//! The API shape is `{collectionId, collectionName, ...fields}` with keys sorted
//! alphabetically (Go marshals a map with `json.Deterministic(true)`), hidden
//! fields removed, and values converted from their SQLite storage form to their
//! JSON form.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use rusqlite::{Connection, Row};
use serde_json::{Map, Value};

use crate::collections::Collection;
use crate::tokens;

#[derive(Clone, Debug)]
pub struct Record {
    pub collection: Collection,
    /// Column -> JSON value, in the collection's field declaration order.
    pub data: BTreeMap<String, Value>,
}

impl Record {
    pub fn find_auth_record_by_token(
        conn: &Connection,
        token: &str,
        valid_types: &[&str],
    ) -> Result<Option<Self>, String> {
        if token.is_empty() {
            return Err("missing token".into());
        }
        let claims = tokens::parse_unverified(token).map_err(|e| e.to_string())?;
        if claims.id.is_empty() || claims.collection_id.is_empty() || claims.kind.is_empty() {
            return Err("missing or invalid token claims".into());
        }
        if !valid_types.is_empty() && !valid_types.contains(&claims.kind.as_str()) {
            return Err(format!(
                "invalid token type {:?}, expects {:?}",
                claims.kind, valid_types
            ));
        }

        let collection = Collection::find(conn, &claims.collection_id)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "missing collection".to_string())?;
        if !collection.is_auth() {
            return Err("the token is not associated to an auth collection record".into());
        }

        let record = Self::find_by_id(conn, &collection, &claims.id)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "missing record".to_string())?;

        let base_secret = match claims.kind.as_str() {
            tokens::TYPE_AUTH => collection.token_secret("authToken").unwrap_or("").to_string(),
            tokens::TYPE_FILE => collection.token_secret("fileToken").unwrap_or("").to_string(),
            tokens::TYPE_VERIFICATION => {
                collection.token_secret("verificationToken").unwrap_or("").to_string()
            }
            tokens::TYPE_PASSWORD_RESET => {
                collection.token_secret("passwordResetToken").unwrap_or("").to_string()
            }
            tokens::TYPE_EMAIL_CHANGE => {
                collection.token_secret("emailChangeToken").unwrap_or("").to_string()
            }
            _ => return Err(format!("unknown token type {}", claims.kind)),
        };

        let signing_key = tokens::signing_key(record.token_key(), &base_secret);
        tokens::parse_jwt(token, &signing_key).map_err(|e| e.to_string())?;

        Ok(Some(record))
    }

    pub fn id(&self) -> &str {
        self.data
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
    }

    pub fn email(&self) -> &str {
        self.data
            .get("email")
            .and_then(Value::as_str)
            .unwrap_or_default()
    }

    pub fn token_key(&self) -> &str {
        self.data
            .get("tokenKey")
            .and_then(Value::as_str)
            .unwrap_or_default()
    }

    pub fn bool_field(&self, name: &str) -> bool {
        self.data
            .get(name)
            .and_then(Value::as_bool)
            .unwrap_or(false)
    }

    /// `Record.ValidatePassword`: bcrypt comparison against the stored hash.
    pub fn validate_password(&self, plain: &str) -> bool {
        let hash = self
            .data
            .get("password")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if hash.is_empty() || plain.is_empty() {
            return false;
        }
        bcrypt::verify(plain, hash).unwrap_or(false)
    }

    /// `Record.MarshalJSON`.
    pub fn to_api_json(&self) -> Value {
        let mut out = Map::new();
        out.insert(
            "collectionId".into(),
            Value::String(self.collection.id.clone()),
        );
        out.insert(
            "collectionName".into(),
            Value::String(self.collection.name.clone()),
        );

        let hidden = self.collection.hidden_fields();
        for (name, value) in &self.data {
            if hidden.contains(name) {
                continue;
            }
            out.insert(name.clone(), value.clone());
        }

        // Go serializes a map deterministically, i.e. sorted keys.
        let sorted: BTreeMap<_, _> = out.into_iter().collect();
        let mut ordered = Map::new();
        for (k, v) in sorted {
            ordered.insert(k, v);
        }
        Value::Object(ordered)
    }

    /// Load a record by primary key.
    pub fn find_by_id(conn: &Connection, collection: &Collection, id: &str) -> Result<Option<Self>> {
        Self::find_one(conn, collection, "id", id)
    }

    /// `FindAuthRecordByEmail`.
    pub fn find_by_email(
        conn: &Connection,
        collection: &Collection,
        email: &str,
    ) -> Result<Option<Self>> {
        Self::find_one(conn, collection, "email", email)
    }

    fn find_one(
        conn: &Connection,
        collection: &Collection,
        column: &str,
        value: &str,
    ) -> Result<Option<Self>> {
        let sql = format!(
            "SELECT * FROM {} WHERE {} = ?1 LIMIT 1",
            quote_ident(&collection.name),
            quote_ident(column)
        );
        let mut stmt = conn.prepare_cached(&sql)?;
        let mut rows = stmt.query([value])?;
        match rows.next()? {
            Some(row) => Ok(Some(Self::from_row(collection, row)?)),
            None => Ok(None),
        }
    }

    pub fn from_row(collection: &Collection, row: &Row<'_>) -> Result<Self> {
        let columns: Vec<String> = row
            .as_ref()
            .column_names()
            .iter()
            .map(|c| c.to_string())
            .collect();
        let types = collection.field_types();
        let mut data = BTreeMap::new();
        for (i, name) in columns.iter().enumerate() {
            let raw = row.get_ref(i)?;
            data.insert(name.clone(), column_to_json(name, raw, &types)?);
        }
        Ok(Self {
            collection: collection.clone(),
            data,
        })
    }

    /// Count records in a collection table.
    pub fn count(conn: &Connection, collection: &Collection) -> Result<i64> {
        let sql = format!("SELECT count(*) FROM {}", quote_ident(&collection.name));
        Ok(conn.query_row(&sql, [], |r| r.get(0))?)
    }
}

/// Convert a stored column to its JSON form using the field type.
///
/// SQLite only has NULL/INTEGER/REAL/TEXT/BLOB, so booleans, JSON and numbers
/// must be reinterpreted according to the collection schema.
fn column_to_json(
    name: &str,
    raw: rusqlite::types::ValueRef<'_>,
    types: &[(String, String, bool)],
) -> Result<Value> {
    use rusqlite::types::ValueRef;

    let field = types.iter().find(|(field, _, _)| field == name);
    let field_type = field.map(|(_, t, _)| t.as_str());
    let multiple = field.map(|(_, _, m)| *m).unwrap_or(false);

    let value = match raw {
        ValueRef::Null => Value::Null,
        ValueRef::Integer(i) => match field_type {
            Some("bool") => Value::Bool(i != 0),
            _ => Value::Number(i.into()),
        },
        ValueRef::Real(f) => serde_json::Number::from_f64(f)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        ValueRef::Text(bytes) => {
            let text = std::str::from_utf8(bytes).context("column is not valid utf-8")?;
            let is_json = matches!(field_type, Some("json") | Some("geoPoint"))
                || (multiple
                    && matches!(
                        field_type,
                        Some("select") | Some("file") | Some("relation")
                    ));
            if is_json {
                serde_json::from_str(text).unwrap_or(Value::Null)
            } else {
                Value::String(text.to_string())
            }
        }
        ValueRef::Blob(bytes) => Value::String(hex(bytes)),
    };

    Ok(value)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Quote a SQLite identifier.
/// Mirrors `core.GenerateDefaultRandomId` (15 chars from `[a-z0-9]`).
pub fn generate_id() -> String {
    use rand::Rng;
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..15)
        .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
        .collect()
}

pub fn quote_ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
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
    fn superuser_record_is_serialized_without_hidden_fields() {
        let conn = fresh();
        crate::superusers::ensure_installer_superuser(&conn).unwrap();
        let col = Collection::find(&conn, "_superusers").unwrap().unwrap();
        let record = Record::find_by_email(&conn, &col, "__pbinstaller@example.com")
            .unwrap()
            .unwrap();
        let json = record.to_api_json();
        let obj = json.as_object().unwrap();

        assert_eq!(json["collectionName"], "_superusers");
        assert_eq!(json["collectionId"], col.id);
        assert!(obj.get("password").is_none(), "password leaked");
        assert!(obj.get("tokenKey").is_none(), "tokenKey leaked");
        assert_eq!(json["verified"], Value::Bool(true));

        // Keys are sorted, matching Go's deterministic map marshaling.
        let keys: Vec<_> = obj.keys().cloned().collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
    }

    #[test]
    fn password_validation_uses_bcrypt() {
        let conn = fresh();
        let col = Collection::find(&conn, "_superusers").unwrap().unwrap();
        let hash = bcrypt::hash("pass12345678", 10).unwrap();
        conn.execute(
            "INSERT INTO _superusers (id, email, password, tokenKey, verified)
             VALUES ('abc123456789012', 'a@b.co', ?1, 'k', 1)",
            [&hash],
        )
        .unwrap();
        let record = Record::find_by_email(&conn, &col, "a@b.co").unwrap().unwrap();
        assert!(record.validate_password("pass12345678"));
        assert!(!record.validate_password("nope"));
        assert!(!record.validate_password(""));
    }
}
