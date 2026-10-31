//! Collection model: the `_collections` row and its API serialization.
//!
//! Two different shapes matter here:
//!
//! * the **storage** shape — `options` is a JSON column holding the type specific
//!   options (`authRule`, `authToken`, ...) as one object;
//! * the **API** shape — `Collection.MarshalJSON` inlines those options as
//!   top-level keys after `system`, and hides every token secret
//!   (`core/collection_model.go`).
//!
//! Field order in the API shape follows the Go struct declaration order, so the
//! keys are inserted in that order rather than alphabetically.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, Row};
use serde_json::{Map, Value};

pub const TYPE_BASE: &str = "base";
pub const TYPE_AUTH: &str = "auth";
pub const TYPE_VIEW: &str = "view";

/// `collectionAuthOptions` field order, which is also the JSON order.
pub const AUTH_OPTION_KEYS: &[&str] = &[
    "authRule",
    "manageRule",
    "authAlert",
    "oauth2",
    "passwordAuth",
    "mfa",
    "otp",
    "authToken",
    "passwordResetToken",
    "emailChangeToken",
    "verificationToken",
    "fileToken",
    "verificationTemplate",
    "resetPasswordTemplate",
    "confirmEmailChangeTemplate",
];

/// Token configs whose `secret` is stripped from API responses.
const TOKEN_CONFIGS: &[&str] = &[
    "authToken",
    "passwordResetToken",
    "emailChangeToken",
    "verificationToken",
    "fileToken",
];

#[derive(Clone, Debug)]
pub struct Collection {
    pub id: String,
    pub system: bool,
    /// `base`, `auth` or `view`.
    pub kind: String,
    pub name: String,
    pub fields: Value,
    pub indexes: Value,
    pub list_rule: Option<String>,
    pub view_rule: Option<String>,
    pub create_rule: Option<String>,
    pub update_rule: Option<String>,
    pub delete_rule: Option<String>,
    /// Parsed `options` column.
    pub options: Value,
    pub created: String,
    pub updated: String,
}

static COLLECTION_CACHE: LazyLock<Mutex<HashMap<usize, HashMap<String, Collection>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

static LOAD_ALL_CACHE: LazyLock<Mutex<HashMap<usize, Vec<Collection>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

impl Collection {
    /// Clear the in-memory collection cache (call after any collection mutation).
    pub fn invalidate_cache() {
        if let Ok(mut cache) = COLLECTION_CACHE.lock() {
            cache.clear();
        }
        if let Ok(mut cache) = LOAD_ALL_CACHE.lock() {
            cache.clear();
        }
    }
    fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        let options: String = row.get("options")?;
        let fields: String = row.get("fields")?;
        let indexes: String = row.get("indexes")?;
        Ok(Self {
            id: row.get("id")?,
            system: row.get::<_, i64>("system")? != 0,
            kind: row.get("type")?,
            name: row.get("name")?,
            fields: serde_json::from_str(&fields).unwrap_or_else(|_| Value::Array(vec![])),
            indexes: serde_json::from_str(&indexes).unwrap_or_else(|_| Value::Array(vec![])),
            list_rule: row.get("listRule")?,
            view_rule: row.get("viewRule")?,
            create_rule: row.get("createRule")?,
            update_rule: row.get("updateRule")?,
            delete_rule: row.get("deleteRule")?,
            options: serde_json::from_str(&options).unwrap_or_else(|_| Value::Object(Map::new())),
            created: row.get("created")?,
            updated: row.get("updated")?,
        })
    }

    pub fn is_auth(&self) -> bool {
        self.kind == TYPE_AUTH
    }

    pub fn is_view(&self) -> bool {
        self.kind == TYPE_VIEW
    }

    /// `Collection.ManageRule` (auth collections only; stored in `options`).
    pub fn manage_rule(&self) -> Option<&str> {
        self.options.get("manageRule").and_then(Value::as_str)
    }

    /// The stored `fields` array as a `FieldsList`.
    pub fn field_list(&self) -> crate::fields::FieldsList {
        crate::fields::FieldsList::from_stored(&self.fields)
    }

    /// The stored `indexes` array as strings.
    pub fn index_list(&self) -> Vec<String> {
        self.indexes
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn load_all(conn: &Connection) -> Result<Vec<Self>> {
        let key = conn as *const Connection as usize;
        if let Ok(cache) = LOAD_ALL_CACHE.lock() {
            if let Some(v) = cache.get(&key) {
                return Ok(v.clone());
            }
        }
        let mut stmt = conn.prepare_cached(
            "SELECT id, system, type, name, fields, indexes, listRule, viewRule,
                    createRule, updateRule, deleteRule, options, created, updated
             FROM _collections ORDER BY rowid ASC",
        )?;
        let rows = stmt.query_map([], Self::from_row)?;
        let result: Vec<Self> = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        if let Ok(mut cache) = LOAD_ALL_CACHE.lock() {
            cache.insert(key, result.clone());
        }
        Ok(result)
    }

    /// `FindCachedCollectionByNameOrId`: lookup by id first, then by name.
    pub fn find(conn: &Connection, id_or_name: &str) -> Result<Option<Self>> {
        let by_id = conn
            .prepare_cached(
                "SELECT id, system, type, name, fields, indexes, listRule, viewRule,
                        createRule, updateRule, deleteRule, options, created, updated
                 FROM _collections WHERE id = ?1",
            )?
            .query_row([id_or_name], Self::from_row)
            .optional()?;
        if by_id.is_some() {
            return Ok(by_id);
        }
        Ok(conn
            .prepare_cached(
                "SELECT id, system, type, name, fields, indexes, listRule, viewRule,
                        createRule, updateRule, deleteRule, options, created, updated
                 FROM _collections WHERE name = ?1",
            )?
            .query_row([id_or_name], Self::from_row)
            .optional()?)
    }

    /// A token config (`authToken`, `fileToken`, ...) from the options object.
    pub fn token_config(&self, key: &str) -> Option<&Value> {
        self.options.get(key)
    }

    /// The signing secret of a token config.
    pub fn token_secret(&self, key: &str) -> Option<&str> {
        self.options.get(key)?.get("secret")?.as_str()
    }

    /// Token lifetime in seconds.
    pub fn token_duration(&self, key: &str) -> i64 {
        self.options
            .get(key)
            .and_then(|c| c.get("duration"))
            .and_then(Value::as_i64)
            .unwrap_or(0)
    }

    /// Field name -> field type, in declaration order.
    pub fn field_types(&self) -> Vec<(String, String, bool)> {
        self.fields
            .as_array()
            .map(|fields| {
                fields
                    .iter()
                    .filter_map(|f| {
                        Some((
                            f.get("name")?.as_str()?.to_string(),
                            f.get("type")?.as_str()?.to_string(),
                            crate::fields::is_multiple(f),
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn hidden_fields(&self) -> Vec<String> {
        self.fields
            .as_array()
            .map(|fields| {
                fields
                    .iter()
                    .filter(|f| f.get("hidden").and_then(Value::as_bool).unwrap_or(false))
                    .filter_map(|f| f.get("name")?.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// `Collection.MarshalJSON`.
    pub fn to_api_json(&self) -> Value {
        let mut out = Map::new();
        let rule = |r: &Option<String>| match r {
            Some(s) => Value::String(s.clone()),
            None => Value::Null,
        };

        out.insert("id".into(), Value::String(self.id.clone()));
        out.insert("listRule".into(), rule(&self.list_rule));
        out.insert("viewRule".into(), rule(&self.view_rule));
        out.insert("createRule".into(), rule(&self.create_rule));
        out.insert("updateRule".into(), rule(&self.update_rule));
        out.insert("deleteRule".into(), rule(&self.delete_rule));
        out.insert("name".into(), Value::String(self.name.clone()));
        out.insert("type".into(), Value::String(self.kind.clone()));
        out.insert("fields".into(), self.fields.clone());
        out.insert("indexes".into(), self.indexes.clone());
        out.insert("created".into(), Value::String(self.created.clone()));
        out.insert("updated".into(), Value::String(self.updated.clone()));
        out.insert("system".into(), Value::Bool(self.system));

        match self.kind.as_str() {
            TYPE_VIEW => {
                out.insert(
                    "viewQuery".into(),
                    self.options
                        .get("viewQuery")
                        .cloned()
                        .unwrap_or(Value::String(String::new())),
                );
            }
            TYPE_AUTH => {
                for key in AUTH_OPTION_KEYS {
                    if let Some(value) = self.options.get(*key) {
                        out.insert((*key).to_string(), redact_option(key, value));
                    }
                }
            }
            _ => {}
        }

        Value::Object(out)
    }
}

/// Hide secrets exactly as `Collection.MarshalJSON` does: token secrets and
/// OAuth2 client secrets are blanked, and `omitempty` then drops the key.
fn redact_option(key: &str, value: &Value) -> Value {
    let mut value = value.clone();
    if TOKEN_CONFIGS.contains(&key) {
        if let Some(obj) = value.as_object_mut() {
            obj.remove("secret");
        }
    }
    if key == "oauth2" {
        if let Some(providers) = value
            .get_mut("providers")
            .and_then(Value::as_array_mut)
        {
            for provider in providers {
                if let Some(obj) = provider.as_object_mut() {
                    obj.remove("clientSecret");
                }
            }
        }
        // The Go model always returns an array, even when nothing is stored.
        if value.get("providers").is_none() {
            if let Some(obj) = value.as_object_mut() {
                obj.insert("providers".into(), Value::Array(vec![]));
            }
        }
    }
    value
}

/// Read a collection or fail with the API's not-found message.
pub fn require(conn: &Connection, id_or_name: &str) -> Result<Collection> {
    Collection::find(conn, id_or_name)?
        .with_context(|| format!("collection {id_or_name} not found"))
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
    fn loads_all_six_system_collections() {
        let conn = fresh();
        let all = Collection::load_all(&conn).unwrap();
        assert_eq!(all.len(), 6);
        assert!(all.iter().any(|c| c.name == "users" && c.is_auth()));
    }

    #[test]
    fn api_json_inlines_options_and_hides_secrets() {
        let conn = fresh();
        let users = Collection::find(&conn, "users").unwrap().unwrap();
        let json = users.to_api_json();
        let obj = json.as_object().unwrap();

        assert!(obj.contains_key("authToken"));
        assert!(!obj.contains_key("options"));
        assert_eq!(json["system"], Value::Bool(false));
        // `secret` must never leak through the API.
        for key in TOKEN_CONFIGS {
            assert!(
                json[*key].get("secret").is_none(),
                "{key} leaked its secret"
            );
            assert!(json[*key].get("duration").is_some(), "{key} lost its duration");
        }
    }

    #[test]
    fn api_json_keeps_rule_nulls() {
        let conn = fresh();
        let mfas = Collection::find(&conn, "_mfas").unwrap().unwrap();
        let json = mfas.to_api_json();
        assert!(json["createRule"].is_null());
        assert!(json["listRule"].is_string());
    }
}
