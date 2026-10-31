//! `core.Record` normalization + `forms.RecordUpsert`.
//!
//! PocketBase normalizes every submitted value through the field's
//! `PrepareValue`/`Set` methods, validates all collection fields, and only then
//! writes the row. This module mirrors that pipeline:
//!
//! 1. [`RecordModel::load`] applies `Set`/modifiers and restores hidden fields
//!    for callers without superuser access.
//! 2. [`RecordModel::submit`] runs the auth form validations, the field
//!    interceptors (text autogenerate, autodate) and the field validations,
//!    then INSERTs/UPDATEs the exported column values.
//!
//! Values are kept in their Go-normalized form ([`FieldValue`]) instead of raw
//! JSON so that NaN, date layout, JSON text and password hashes survive the
//! round-trip exactly like the oracle.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;
use rusqlite::Connection;
use serde_json::{Map, Value};

use crate::collections::Collection;
use crate::fields::{
    cast_to_bool, cast_to_f64, cast_to_string, field_bool, field_i64, field_name, field_str,
    field_type, file_slice_value, geo_point, is_multiple, now_date_time, prepare_json_raw,
    unique_string_slice,
};
use crate::go_json;
use crate::validation::{leaf, leaf_with_params, Errors, Node};
use crate::validators::{is_email, is_url, url_host};

/// `core.FieldNameId`.
const FIELD_NAME_ID: &str = "id";
/// `core.FieldNamePassword`.
const FIELD_NAME_PASSWORD: &str = "password";
/// `core.FieldNameTokenKey`.
const FIELD_NAME_TOKEN_KEY: &str = "tokenKey";
/// `core.FieldNameEmail`.
const FIELD_NAME_EMAIL: &str = "email";
/// `core.FieldNameEmailVisibility`.
const FIELD_NAME_EMAIL_VISIBILITY: &str = "emailVisibility";
/// `core.FieldNameVerified`.
const FIELD_NAME_VERIFIED: &str = "verified";
/// `core.autogenerateModifier`.
const AUTOGENERATE_MODIFIER: &str = ":autogenerate";
/// `core.defaultLowercaseRecordIdPattern`.
const DEFAULT_LOWERCASE_ID_PATTERN: &str = "^[a-z0-9]+$";
/// `core.DefaultJSONFieldMaxSize`.
const DEFAULT_JSON_MAX_SIZE: i64 = 1 << 20;
/// `core.DefaultEditorFieldMaxSize`.
const DEFAULT_EDITOR_MAX_SIZE: i64 = 5 << 20;
/// `bcrypt.DefaultCost`.
const DEFAULT_BCRYPT_COST: u32 = 10;

/// The field's stored/normalized value, matching the Go concrete types.
#[derive(Clone, Debug, PartialEq)]
pub enum FieldValue {
    /// text/email/url/editor.
    Text(String),
    /// number (`float64`, may be NaN/Inf until validated).
    Number(f64),
    /// bool.
    Bool(bool),
    /// date/autodate (`types.DateTime` string form, `""` = zero).
    Date(String),
    /// select/file/relation. Single-valued fields keep at most one element.
    List(Vec<String>),
    /// json (`types.JSONRaw` text; `""` = nil).
    Json(String),
    /// geoPoint (`types.GeoPoint`).
    Geo { lon: f64, lat: f64 },
    /// password (`core.PasswordFieldValue`).
    Password { hash: String, plain: String },
}

impl FieldValue {
    /// `Record.Get` (password returns the plain value, not the hash).
    pub fn to_json(&self, multiple: bool) -> Value {
        match self {
            FieldValue::Text(s) | FieldValue::Date(s) => Value::String(s.clone()),
            FieldValue::Number(f) => go_json::number(*f),
            FieldValue::Bool(b) => Value::Bool(*b),
            FieldValue::List(items) => {
                if multiple {
                    Value::Array(items.iter().cloned().map(Value::String).collect())
                } else {
                    Value::String(items.last().cloned().unwrap_or_default())
                }
            }
            FieldValue::Json(raw) => {
                if raw.is_empty() {
                    Value::Null
                } else {
                    serde_json::from_str(raw).unwrap_or_else(|_| Value::String(raw.clone()))
                }
            }
            FieldValue::Geo { lon, lat } => {
                let mut map = Map::new();
                map.insert("lon".into(), go_json::number(*lon));
                map.insert("lat".into(), go_json::number(*lat));
                Value::Object(map)
            }
            FieldValue::Password { plain, .. } => Value::String(plain.clone()),
        }
    }

    /// The SQLite value produced by `DriverValue`/`GetRaw` during `DBExport`.
    pub fn to_db(&self, _kind: &str, multiple: bool) -> rusqlite::types::Value {
        use rusqlite::types::Value as Sql;

        match self {
            FieldValue::Text(s) | FieldValue::Date(s) => Sql::Text(s.clone()),
            FieldValue::Number(f) => Sql::Real(*f),
            FieldValue::Bool(b) => Sql::Integer(if *b { 1 } else { 0 }),
            FieldValue::List(items) => {
                if multiple {
                    Sql::Text(go_json::marshal(
                        &Value::Array(items.iter().cloned().map(Value::String).collect()),
                    ))
                } else {
                    Sql::Text(items.last().cloned().unwrap_or_default())
                }
            }
            FieldValue::Json(raw) => {
                if raw.is_empty() {
                    Sql::Null
                } else {
                    Sql::Text(raw.clone())
                }
            }
            FieldValue::Geo { lon, lat } => Sql::Text(format!(
                "{{\"lon\":{},\"lat\":{}}}",
                go_json::format_float(*lon),
                go_json::format_float(*lat)
            )),
            FieldValue::Password { hash, .. } => Sql::Text(hash.clone()),
        }
    }
}

/// The access level granted to `RecordUpsert`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessLevel {
    Default,
    Manager,
    Superuser,
}

/// `Record.PublicExport` visibility flags.
#[derive(Clone, Debug, Default)]
pub struct Visibility {
    /// Field name -> forced visibility (`Record.Unhide` / `Hide`).
    pub custom: BTreeMap<String, bool>,
    /// `Record.IgnoreEmailVisibility`.
    pub ignore_email_visibility: bool,
}

impl Visibility {
    pub fn unhide_all(&mut self, names: &[String]) {
        for name in names {
            self.custom.insert(name.clone(), true);
        }
    }

    pub fn unhide(&mut self, name: &str) {
        self.custom.insert(name.to_string(), true);
    }
}

/// `core.Record` with the parts needed by the create/update pipeline.
#[derive(Clone, Debug)]
pub struct RecordModel {
    pub collection: Collection,
    data: BTreeMap<String, FieldValue>,
    original: BTreeMap<String, FieldValue>,
    pub is_new: bool,
    pub last_saved_pk: String,
    pk: String,
    access_level: AccessLevel,
    // auth form extras
    password: String,
    password_confirm: String,
    old_password: String,
    disable_password_validations: bool,
    // uploaded file names (multipart) that should bypass the "invalid new file" check
    pub uploaded_files: Vec<String>,
}

impl RecordModel {
    /// `core.NewRecord(collection)`.
    pub fn new(collection: &Collection) -> Self {
        let mut original = BTreeMap::new();
        for field in fields_of(collection) {
            let name = field_name(field);
            if name == FIELD_NAME_ID {
                continue;
            }
            original.insert(name.to_string(), prepare_value(field, None));
        }
        Self {
            collection: collection.clone(),
            data: BTreeMap::new(),
            original,
            is_new: true,
            last_saved_pk: String::new(),
            pk: String::new(),
            access_level: AccessLevel::Default,
            password: String::new(),
            password_confirm: String::new(),
            old_password: String::new(),
            disable_password_validations: false,
            uploaded_files: Vec::new(),
        }
    }

    /// `newRecordFromNullStringMap`: every column is scanned as a string and
    /// normalized through the field's `PrepareValue`.
    pub fn from_row(collection: &Collection, row: &rusqlite::Row<'_>) -> Result<Self> {
        let mut record = Self::new(collection);
        record.original.clear();
        record.is_new = false;

        let columns: Vec<String> = row
            .as_ref()
            .column_names()
            .iter()
            .map(|c| c.to_string())
            .collect();

        for field in fields_of(collection) {
            let name = field_name(field);
            let raw = columns
                .iter()
                .position(|c| c == name)
                .and_then(|idx| row.get_ref(idx).ok())
                .and_then(column_to_string);
            let value = match &raw {
                Some(text) => prepare_value(field, Some(&Value::String(text.clone()))),
                None => prepare_value(field, None),
            };
            if name == FIELD_NAME_ID {
                record.pk = match &value {
                    FieldValue::Text(s) => s.clone(),
                    _ => String::new(),
                };
            }
            record.original.insert(name.to_string(), value);
        }

        record.last_saved_pk = record.pk.clone();
        Ok(record)
    }

    /// `FindRecordById`.
    pub fn find_by_id(
        conn: &Connection,
        collection: &Collection,
        id: &str,
    ) -> Result<Option<Self>> {
        let sql = format!(
            "SELECT * FROM {} WHERE {} = ?1 LIMIT 1",
            crate::records::quote_ident(&collection.name),
            crate::records::quote_ident(FIELD_NAME_ID)
        );
        let mut stmt = conn.prepare(&sql)?;
        let mut rows = stmt.query([id])?;
        match rows.next()? {
            Some(row) => Ok(Some(Self::from_row(collection, row)?)),
            None => Ok(None),
        }
    }

    pub fn grant_access(&mut self, level: AccessLevel) {
        self.access_level = level;
    }

    pub fn access_level(&self) -> AccessLevel {
        self.access_level
    }

    pub fn has_manage_access(&self) -> bool {
        matches!(self.access_level, AccessLevel::Manager | AccessLevel::Superuser)
    }

    pub fn id(&self) -> &str {
        &self.pk
    }

    pub fn set_id(&mut self, id: impl Into<String>) {
        self.pk = id.into();
    }

    pub fn email(&self) -> String {
        match self.get_raw(FIELD_NAME_EMAIL) {
            Some(FieldValue::Text(s)) => s,
            _ => String::new(),
        }
    }

    pub fn verified(&self) -> bool {
        match self.get_raw(FIELD_NAME_VERIFIED) {
            Some(FieldValue::Bool(b)) => b,
            _ => false,
        }
    }

    pub fn set_verified(&mut self, value: bool) {
        self.set_raw(FIELD_NAME_VERIFIED, FieldValue::Bool(value));
    }

    pub fn token_key(&self) -> String {
        match self.get_raw(FIELD_NAME_TOKEN_KEY) {
            Some(FieldValue::Text(s)) => s,
            _ => String::new(),
        }
    }

    pub fn email_visibility(&self) -> bool {
        match self.get_raw(FIELD_NAME_EMAIL_VISIBILITY) {
            Some(FieldValue::Bool(b)) => b,
            _ => false,
        }
    }

    /// `Record.ValidatePassword` against the original stored hash.
    pub fn validate_password(&self, plain: &str) -> bool {
        let hash = match self.original.get(FIELD_NAME_PASSWORD) {
            Some(FieldValue::Password { hash, .. }) => hash.clone(),
            _ => String::new(),
        };
        if hash.is_empty() || plain.is_empty() {
            return false;
        }
        bcrypt::verify(plain, &hash).unwrap_or(false)
    }

    /// `Record.GetRaw`.
    pub fn get_raw(&self, name: &str) -> Option<FieldValue> {
        if name == FIELD_NAME_ID {
            return Some(FieldValue::Text(self.pk.clone()));
        }
        self.data
            .get(name)
            .or_else(|| self.original.get(name))
            .cloned()
    }

    /// `Record.Get`: schema fields with getters (password) are special-cased.
    pub fn get_json(&self, name: &str) -> Value {
        let Some(field) = find_field(&self.collection, name) else {
            return Value::Null;
        };
        match self.get_raw(name) {
            Some(value) => value.to_json(is_multiple(field)),
            None => Value::Null,
        }
    }

    /// `Record.SetRaw`.
    pub fn set_raw(&mut self, name: &str, value: FieldValue) {
        if name == FIELD_NAME_ID {
            self.pk = match value {
                FieldValue::Text(s) => s,
                _ => String::new(),
            };
            return;
        }
        self.data.insert(name.to_string(), value);
    }

    /// `Record.Fresh`.
    fn fresh(&self) -> Self {
        let mut record = self.clone();
        record.data.clear();
        for field in fields_of(&self.collection) {
            let name = field_name(field);
            if name == FIELD_NAME_ID {
                continue;
            }
            if let Some(value) = self.get_raw(name) {
                record.data.insert(name.to_string(), value);
            }
        }
        record
    }

    /// `Record.SetIfFieldExists` (returns the canonical field name on match).
    pub fn set_if_field_exists(&mut self, key: &str, value: &Value) -> Option<String> {
        let fields = fields_of(&self.collection).to_vec();
        for field in &fields {
            let name = field_name(field);
            match field_type(field) {
                "text" => {
                    if key == name {
                        self.set_raw(name, FieldValue::Text(cast_to_string(value)));
                        return Some(name.to_string());
                    }
                    if key == format!("{name}{AUTOGENERATE_MODIFIER}") {
                        let mut text = cast_to_string(value);
                        let pattern = field_str(field, "autogeneratePattern");
                        if !pattern.is_empty() {
                            if let Ok(generated) = random_string_by_regex(pattern) {
                                text.push_str(&generated);
                            }
                        }
                        self.set_raw(name, FieldValue::Text(text));
                        return Some(name.to_string());
                    }
                }
                "number" => {
                    if key == name {
                        self.set_raw(name, FieldValue::Number(cast_to_f64(value)));
                        return Some(name.to_string());
                    }
                    if key == format!("{name}+") {
                        let base = self.number_value(name);
                        self.set_raw(name, FieldValue::Number(base + cast_to_f64(value)));
                        return Some(name.to_string());
                    }
                    if key == format!("{name}-") {
                        let base = self.number_value(name);
                        self.set_raw(name, FieldValue::Number(base - cast_to_f64(value)));
                        return Some(name.to_string());
                    }
                }
                "select" | "relation" | "file" => {
                    if key == name {
                        self.set_raw(name, FieldValue::List(normalize_list(field, value)));
                        return Some(name.to_string());
                    }
                    if key == format!("+{name}") {
                        let mut items = normalize_list(field, value);
                        items.extend(self.list_value(name));
                        self.set_raw(name, FieldValue::List(normalize_single(field, items)));
                        return Some(name.to_string());
                    }
                    if key == format!("{name}+") {
                        let mut items = self.list_value(name);
                        items.extend(normalize_list(field, value));
                        self.set_raw(name, FieldValue::List(normalize_single(field, items)));
                        return Some(name.to_string());
                    }
                    if key == format!("{name}-") {
                        let remove = normalize_list(field, value);
                        let items: Vec<String> = self
                            .list_value(name)
                            .into_iter()
                            .filter(|item| !remove.contains(item))
                            .collect();
                        self.set_raw(name, FieldValue::List(normalize_single(field, items)));
                        return Some(name.to_string());
                    }
                }
                "autodate" => {
                    if key == name {
                        // `noopSetter`: submitted values are ignored.
                        return Some(name.to_string());
                    }
                }
                "password" => {
                    if key == name {
                        let plain = cast_to_string(value);
                        let hash = if plain.is_empty() {
                            String::new()
                        } else {
                            hash_password(&plain, field_i64(field, "cost"))
                        };
                        self.set_raw(name, FieldValue::Password { hash, plain });
                        return Some(name.to_string());
                    }
                }
                _ => {
                    if key == name {
                        self.set_raw(name, prepare_value(field, Some(value)));
                        return Some(name.to_string());
                    }
                }
            }
        }
        None
    }

    fn number_value(&self, name: &str) -> f64 {
        match self.get_raw(name) {
            Some(FieldValue::Number(f)) => f,
            _ => 0.0,
        }
    }

    fn list_value(&self, name: &str) -> Vec<String> {
        match self.get_raw(name) {
            Some(FieldValue::List(items)) => items,
            _ => Vec::new(),
        }
    }

    /// `Record.ReplaceModifiers`.
    pub fn replace_modifiers(&self, data: &Map<String, Value>) -> Map<String, Value> {
        if data.is_empty() {
            return data.clone();
        }
        let mut data_copy = data.clone();
        let mut record_copy = self.fresh();

        let mut keys: Vec<&String> = data.keys().collect();
        keys.sort_by_key(|k| k.len());

        for key in keys {
            if let Some(field_name) = record_copy.set_if_field_exists(key, &data[key]) {
                data_copy.remove(key);
                // `Record.Get` returns `types.JSONRaw` for JSON fields and a
                // plain `float64` for numbers; both must survive the roundtrip
                // unchanged so that later `Load` sees the same raw value
                // (JSON text whitespace is preserved, NaN/Inf stay invalid).
                let value = match find_field(&self.collection, &field_name) {
                    Some(field) if field_type(field) == "json" => {
                        match record_copy.get_raw(&field_name) {
                            Some(FieldValue::Json(raw)) if !raw.is_empty() => {
                                Value::String(raw)
                            }
                            _ => Value::Null,
                        }
                    }
                    Some(field) if field_type(field) == "number" => {
                        match record_copy.get_raw(&field_name) {
                            Some(FieldValue::Number(f)) if f.is_nan() => {
                                Value::String("NaN".to_string())
                            }
                            Some(FieldValue::Number(f)) if f.is_infinite() => {
                                Value::String(if f > 0.0 { "+Inf" } else { "-Inf" }.to_string())
                            }
                            _ => record_copy.get_json(&field_name),
                        }
                    }
                    _ => record_copy.get_json(&field_name),
                };
                data_copy.insert(field_name, value);
            }
        }
        data_copy
    }

    /// `RecordUpsert.Load`.
    pub fn load(&mut self, data: &Map<String, Value>) {
        let is_auth = self.collection.is_auth();
        let mut excluded: BTreeSet<&str> = BTreeSet::new();
        excluded.insert("expand");

        if is_auth {
            if let Some(v) = data.get(FIELD_NAME_PASSWORD) {
                self.password = cast_to_string(v);
            }
            if let Some(v) = data.get("passwordConfirm") {
                self.password_confirm = cast_to_string(v);
            }
            if let Some(v) = data.get("oldPassword") {
                self.old_password = cast_to_string(v);
            }
            excluded.insert("passwordConfirm");
            excluded.insert("oldPassword");
        }

        for (key, value) in data {
            if excluded.contains(key.as_str()) {
                continue;
            }
            let Some(field_name) = self.set_if_field_exists(key, value) else {
                continue;
            };
            if self.access_level == AccessLevel::Superuser {
                continue;
            }
            let Some(field) = find_field(&self.collection, &field_name) else {
                continue;
            };
            if field_bool(field, "hidden")
                && (!is_auth || field_name != FIELD_NAME_PASSWORD)
            {
                match self.original.get(&field_name) {
                    Some(original) => {
                        self.data.insert(field_name, original.clone());
                    }
                    None => {
                        self.data.remove(&field_name);
                    }
                }
            }
        }
    }

    /// `RecordUpsert.validateFormFields`.
    fn validate_form_fields(&mut self) -> Result<(), Errors> {
        if !self.collection.is_auth() {
            return Ok(());
        }
        self.sync_password_fields();

        let mut errors = Errors::new();
        let original_email = match self.original.get(FIELD_NAME_EMAIL) {
            Some(FieldValue::Text(s)) => s.clone(),
            _ => String::new(),
        };
        let original_verified = match self.original.get(FIELD_NAME_VERIFIED) {
            Some(FieldValue::Bool(b)) => *b,
            _ => false,
        };

        if !self.is_new
            && !self.has_manage_access()
            && self.email() != original_email
        {
            errors.insert("email".into(), values_mismatch());
        }
        if !self.has_manage_access() && self.verified() != original_verified {
            errors.insert("verified".into(), values_mismatch());
        }

        if !self.disable_password_validations
            && (self.is_new || !self.password_confirm.is_empty() || !self.old_password.is_empty())
            && self.password.is_empty()
        {
            errors.insert(FIELD_NAME_PASSWORD.into(), crate::validation::required());
        }
        if !self.disable_password_validations
            && (self.is_new || !self.password.is_empty() || !self.old_password.is_empty())
            && self.password_confirm.is_empty()
        {
            errors.insert("passwordConfirm".into(), crate::validation::required());
        }
        if !self.disable_password_validations
            && self.password_confirm != self.password
            && !errors.contains_key("passwordConfirm")
        {
            errors.insert("passwordConfirm".into(), values_mismatch());
        }
        if !self.disable_password_validations
            && !self.is_new
            && !self.has_manage_access()
            && (!self.password.is_empty() || !self.password_confirm.is_empty())
        {
            if self.old_password.is_empty() {
                errors.insert("oldPassword".into(), crate::validation::required());
            } else if !self.validate_password(&self.old_password) {
                errors.insert(
                    "oldPassword".into(),
                    leaf(
                        "validation_invalid_old_password",
                        "Missing or invalid old password.",
                    ),
                );
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    fn sync_password_fields(&mut self) {
        if !self.collection.is_auth() {
            return;
        }
        self.disable_password_validations = false;
        if let Some(FieldValue::Password { hash, plain }) = self.get_raw(FIELD_NAME_PASSWORD) {
            if (!plain.is_empty() && plain != self.password)
                || (plain.is_empty() && !hash.is_empty() && self.is_new)
            {
                self.disable_password_validations = true;
            }
        }
    }

    /// `RecordUpsert.Submit`: form validation + record save.
    pub fn submit(&mut self, conn: &Connection) -> Result<(), SubmitError> {
        if let Err(errors) = self.validate_form_fields() {
            return Err(SubmitError::Validation(errors));
        }
        if self.is_new {
            self.save_create(conn)
        } else {
            self.save_update(conn)
        }
    }

    fn save_create(&mut self, conn: &Connection) -> Result<(), SubmitError> {
        // OnRecordValidate -> callFieldInterceptors(validate)
        self.run_text_autogenerate();
        let errors = self.validate_fields(conn);
        if !errors.is_empty() {
            return Err(SubmitError::Validation(errors));
        }

        // OnRecordCreate -> callFieldInterceptors(create)
        self.run_text_autogenerate();

        // OnRecordCreateExecute -> callFieldInterceptors(createExecute)
        self.run_autodate(true);

        let data = self.db_export();
        let id = match data.get(FIELD_NAME_ID) {
            Some(rusqlite::types::Value::Text(id)) => id.clone(),
            _ => String::new(),
        };
        if id.is_empty() {
            return Err(SubmitError::Raw(
                "empty primary key is not allowed when using the DBExporter interface".to_string(),
            ));
        }

        let columns: Vec<String> = data.keys().cloned().collect();
        let placeholders: Vec<String> = (1..=columns.len()).map(|i| format!("?{i}")).collect();
        let sql = format!(
            "INSERT INTO {} ({}) VALUES ({})",
            crate::records::quote_ident(&self.collection.name),
            columns
                .iter()
                .map(|c| crate::records::quote_ident(c))
                .collect::<Vec<_>>()
                .join(", "),
            placeholders.join(", ")
        );
        let params: Vec<rusqlite::types::Value> = data.values().cloned().collect();
        if let Err(err) = conn.execute(&sql, rusqlite::params_from_iter(params)) {
            return Err(self.save_error(err));
        }

        self.after_save();
        Ok(())
    }

    fn save_update(&mut self, conn: &Connection) -> Result<(), SubmitError> {
        // OnRecordValidate -> callFieldInterceptors(validate)
        self.run_text_autogenerate();
        let errors = self.validate_fields(conn);
        if !errors.is_empty() {
            return Err(SubmitError::Validation(errors));
        }

        // OnRecordUpdateExecute -> callFieldInterceptors(updateExecute)
        self.run_autodate(false);

        // onRecordSaveExecute: auth token key refresh + cross-collection id check
        if self.collection.is_auth() {
            let last_saved = RecordModel::find_by_id(conn, &self.collection, &self.pk)
                .map_err(|e| SubmitError::Raw(e.to_string()))?;
            if let Some(last) = last_saved {
                if last.token_key() == self.token_key()
                    && (last.get_json(FIELD_NAME_PASSWORD) != self.get_json(FIELD_NAME_PASSWORD)
                        || last.email() != self.email())
                {
                    self.refresh_token_key();
                }
            }

            let auth_collections = Collection::load_all(conn)
                .map_err(|e| SubmitError::Raw(e.to_string()))?
                .into_iter()
                .filter(Collection::is_auth)
                .collect::<Vec<_>>();
            for collection in auth_collections {
                if collection.id == self.collection.id {
                    continue;
                }
                if RecordModel::find_by_id(conn, &collection, &self.pk)
                    .map_err(|e| SubmitError::Raw(e.to_string()))?
                    .is_some()
                {
                    let mut errors = Errors::new();
                    errors.insert(
                        FIELD_NAME_ID.into(),
                        leaf(
                            "validation_invalid_auth_id",
                            "Invalid or duplicated auth record id.",
                        ),
                    );
                    return Err(SubmitError::Validation(errors));
                }
            }
        }

        let data = self.db_export();
        let sets: Vec<String> = data
            .keys()
            .filter(|name| name.as_str() != FIELD_NAME_ID)
            .map(|name| format!("{} = ?", crate::records::quote_ident(name)))
            .collect();
        let mut params: Vec<rusqlite::types::Value> = data
            .iter()
            .filter(|(name, _)| name.as_str() != FIELD_NAME_ID)
            .map(|(_, value)| value.clone())
            .collect();
        params.push(rusqlite::types::Value::Text(self.pk.clone()));
        let sql = format!(
            "UPDATE {} SET {} WHERE {} = ?",
            crate::records::quote_ident(&self.collection.name),
            sets.join(", "),
            crate::records::quote_ident(FIELD_NAME_ID)
        );
        if let Err(err) = conn.execute(&sql, rusqlite::params_from_iter(params)) {
            return Err(self.save_error(err));
        }

        self.after_save();
        Ok(())
    }

    fn after_save(&mut self) {
        self.is_new = false;
        self.last_saved_pk = self.pk.clone();
        // `PasswordField.Intercept(AfterCreate/AfterUpdate)` clears the plain
        // value after the row was written.
        for field in fields_of(&self.collection) {
            if field_type(field) != "password" {
                continue;
            }
            let name = field_name(field);
            if let Some(FieldValue::Password { hash, .. }) = self.data.get(name).cloned() {
                self.data.insert(
                    name.to_string(),
                    FieldValue::Password {
                        hash,
                        plain: String::new(),
                    },
                );
            }
        }
        // Refresh the original snapshot like `PostScan` would.
        for field in fields_of(&self.collection) {
            let name = field_name(field);
            if name == FIELD_NAME_ID {
                continue;
            }
            if let Some(value) = self.data.get(name).cloned() {
                self.original.insert(name.to_string(), value);
            }
        }
    }

    fn save_error(&self, err: rusqlite::Error) -> SubmitError {
        let message = crate::schema_sync::go_sqlite_error(&err);
        if let Some(errors) =
            normalize_unique_index_error(&message, &self.collection.name, &self.field_names())
        {
            return SubmitError::Validation(errors);
        }
        SubmitError::Raw(message)
    }

    fn field_names(&self) -> Vec<String> {
        fields_of(&self.collection)
            .iter()
            .map(|f| field_name(f).to_string())
            .collect()
    }

    fn run_text_autogenerate(&mut self) {
        let fields: Vec<Value> = fields_of(&self.collection).to_vec();
        for field in fields.iter().rev() {
            if field_type(field) != "text" || !self.is_new {
                continue;
            }
            let pattern = field_str(field, "autogeneratePattern");
            if pattern.is_empty() {
                continue;
            }
            let name = field_name(field);
            let empty = matches!(self.get_raw(name), Some(FieldValue::Text(s)) if s.is_empty());
            if !empty {
                continue;
            }
            if let Ok(generated) = random_string_by_regex(pattern) {
                self.set_raw(name, FieldValue::Text(generated));
            }
        }
    }

    fn run_autodate(&mut self, create: bool) {
        let fields: Vec<Value> = fields_of(&self.collection).to_vec();
        for field in fields.iter().rev() {
            if field_type(field) != "autodate" {
                continue;
            }
            let name = field_name(field);
            let enabled = if create {
                field_bool(field, "onCreate")
            } else {
                field_bool(field, "onUpdate")
            };
            if !enabled {
                continue;
            }
            let current = match self.get_raw(name) {
                Some(FieldValue::Date(s)) => s,
                _ => String::new(),
            };
            let last_known = match self.original.get(name) {
                Some(FieldValue::Date(s)) => s.clone(),
                _ => String::new(),
            };
            if current == last_known {
                self.set_raw(name, FieldValue::Date(now_date_time()));
            }
        }
    }

    /// `onRecordValidate`: one error per collection field.
    fn validate_fields(&self, conn: &Connection) -> Errors {
        let mut errors = Errors::new();
        for field in fields_of(&self.collection) {
            if let Some(error) = self.validate_field(conn, field) {
                errors.insert(field_name(field).to_string(), error);
            }
        }
        errors
    }

    fn validate_field(&self, conn: &Connection, field: &Value) -> Option<Node> {
        let name = field_name(field);
        let value = self.get_raw(name)?;
        match field_type(field) {
            "text" => self.validate_text(conn, field, &value),
            "number" => validate_number(field, &value),
            "bool" => None,
            "email" => validate_email(field, &value),
            "url" => validate_url(field, &value),
            "date" | "autodate" => validate_date(field, &value),
            "select" => validate_select(field, &value),
            "relation" => self.validate_relation(conn, field, &value),
            "file" => self.validate_file(conn, field, &value),
            "json" => validate_json(field, &value),
            "editor" => validate_editor(field, &value),
            "password" => validate_password_field(field, &value),
            "geoPoint" => validate_geo(field, &value),
            _ => None,
        }
    }

    fn validate_text(&self, conn: &Connection, field: &Value, value: &FieldValue) -> Option<Node> {
        let FieldValue::Text(text) = value else {
            return Some(unsupported_value_type());
        };
        let primary_key = field_bool(field, "primaryKey");
        if primary_key {
            if !self.is_new {
                let old = self.last_saved_pk.as_str();
                if old != text {
                    return Some(leaf(
                        "validation_pk_change",
                        "The record primary key cannot be changed.",
                    ));
                }
                if !old.is_empty() {
                    return None;
                }
            } else if field_str(field, "pattern") != DEFAULT_LOWERCASE_ID_PATTERN {
                let exists = conn
                    .query_row(
                        &format!(
                            "SELECT (1) FROM {} WHERE id = ?1 COLLATE NOCASE LIMIT 1",
                            crate::records::quote_ident(&self.collection.name)
                        ),
                        [text],
                        |_| Ok(()),
                    )
                    .is_ok();
                if exists {
                    return Some(leaf(
                        "validation_pk_invalid",
                        "The record primary key is invalid or already exists.",
                    ));
                }
            }
        }
        validate_plain_text(field, text)
    }

    fn validate_relation(
        &self,
        conn: &Connection,
        field: &Value,
        value: &FieldValue,
    ) -> Option<Node> {
        let FieldValue::List(ids) = value else {
            return Some(unsupported_value_type());
        };
        if ids.is_empty() {
            return if field_bool(field, "required") {
                Some(crate::validation::required())
            } else {
                None
            };
        }
        let min_select = field_i64(field, "minSelect");
        if min_select > 0 && (ids.len() as i64) < min_select {
            return Some(leaf_with_params(
                "validation_not_enough_values",
                "Select at least {{.minSelect}}",
                serde_json::json!({ "minSelect": min_select }),
            ));
        }
        let max_select = field_i64(field, "maxSelect").max(1);
        if ids.len() as i64 > max_select {
            return Some(leaf_with_params(
                "validation_too_many_values",
                "Select no more than {{.maxSelect}}",
                serde_json::json!({ "maxSelect": max_select }),
            ));
        }

        let collection_id = field_str(field, "collectionId");
        let rel_collection = match Collection::find(conn, collection_id) {
            Ok(Some(collection)) => collection,
            _ => {
                return Some(leaf(
                    "validation_missing_rel_collection",
                    "Relation connection is missing or cannot be accessed",
                ))
            }
        };

        let placeholders: Vec<String> = (1..=ids.len()).map(|i| format!("?{i}")).collect();
        let sql = format!(
            "SELECT count(*) FROM {} WHERE id IN ({})",
            crate::records::quote_ident(&rel_collection.name),
            placeholders.join(", ")
        );
        let params: Vec<rusqlite::types::Value> = ids
            .iter()
            .cloned()
            .map(rusqlite::types::Value::Text)
            .collect();
        let total: i64 = conn
            .query_row(&sql, rusqlite::params_from_iter(params), |r| r.get(0))
            .unwrap_or(0);
        if total != ids.len() as i64 {
            return Some(leaf(
                "validation_missing_rel_records",
                "Failed to find all relation records with the provided ids",
            ));
        }
        None
    }

    fn validate_file(
        &self,
        conn: &Connection,
        field: &Value,
        value: &FieldValue,
    ) -> Option<Node> {
        let FieldValue::List(files) = value else {
            return Some(unsupported_value_type());
        };
        let name = field_name(field);

        // `getLatestOldValue`: re-fetch the persisted row on updates.
        let old_value = if !self.is_new {
            match RecordModel::find_by_id(conn, &self.collection, &self.last_saved_pk) {
                Ok(Some(record)) => record.get_raw(name),
                _ => self.original.get(name).cloned(),
            }
        } else {
            self.original.get(name).cloned()
        };
        let old_files = match old_value {
            Some(FieldValue::List(items)) => items,
            _ => Vec::new(),
        };

        let added: Vec<String> = files
            .iter()
            .filter(|file| !old_files.contains(file) && !self.uploaded_files.contains(file))
            .cloned()
            .collect();
        if !added.is_empty() {
            let invalid: Vec<Value> = added
                .iter()
                .map(|file| {
                    let truncated: String = file.chars().take(250).collect();
                    Value::String(truncated)
                })
                .collect();
            return Some(leaf_with_params(
                "validation_invalid_file",
                "Invalid new files: {{.invalidFiles}}.",
                serde_json::json!({ "invalidFiles": invalid }),
            ));
        }

        let max_select = field_i64(field, "maxSelect").max(1);
        if files.len() as i64 > max_select {
            return Some(leaf_with_params(
                "validation_too_many_files",
                "The maximum allowed files is {{.maxSelect}}",
                serde_json::json!({ "maxSelect": max_select }),
            ));
        }
        None
    }

    /// `Record.DBExport`: column name -> SQLite value.
    pub fn db_export(&self) -> BTreeMap<String, rusqlite::types::Value> {
        let mut result = BTreeMap::new();
        for field in fields_of(&self.collection) {
            let name = field_name(field);
            if name == FIELD_NAME_ID {
                result.insert(
                    FIELD_NAME_ID.to_string(),
                    rusqlite::types::Value::Text(self.pk.clone()),
                );
                continue;
            }
            let value = self
                .get_raw(name)
                .unwrap_or_else(|| prepare_value(field, None));
            result.insert(name.to_string(), value.to_db(field_type(field), is_multiple(field)));
        }
        result
    }

    /// `Record.RefreshTokenKey`.
    pub fn refresh_token_key(&mut self) {
        let _ = self.set_if_field_exists(
            &format!("{FIELD_NAME_TOKEN_KEY}{AUTOGENERATE_MODIFIER}"),
            &Value::String(String::new()),
        );
    }

    /// `Record.PublicExport` (schema fields only).
    pub fn to_api_json_with(&self, visibility: &Visibility) -> Value {
        let mut out = Map::new();
        out.insert(
            "collectionId".into(),
            Value::String(self.collection.id.clone()),
        );
        out.insert(
            "collectionName".into(),
            Value::String(self.collection.name.clone()),
        );

        for field in fields_of(&self.collection) {
            let name = field_name(field);
            let mut visible = visibility
                .custom
                .get(name)
                .copied()
                .unwrap_or_else(|| !field_bool(field, "hidden"));
            if !visible {
                continue;
            }
            visible = true;
            out.insert(name.to_string(), self.get_json(name));
        }

        if self.collection.is_auth() {
            out.remove(FIELD_NAME_PASSWORD);
            out.remove(FIELD_NAME_TOKEN_KEY);
            if !visibility.ignore_email_visibility && !self.email_visibility() {
                out.remove(FIELD_NAME_EMAIL);
            }
        }

        let sorted: BTreeMap<_, _> = out.into_iter().collect();
        let mut ordered = Map::new();
        for (k, v) in sorted {
            ordered.insert(k, v);
        }
        Value::Object(ordered)
    }

    /// Convenience wrapper without visibility overrides.
    pub fn to_api_json(&self) -> Value {
        self.to_api_json_with(&Visibility::default())
    }

    /// All schema field values as `Record.Get` would return them.
    ///
    /// Used by the rule evaluator; unlike `PublicExport` this includes hidden
    /// fields (rules can access them) and keeps the auth email regardless of
    /// `emailVisibility`.
    pub fn to_rule_data(&self) -> Map<String, Value> {
        let mut out = Map::new();
        for field in fields_of(&self.collection) {
            let name = field_name(field);
            out.insert(name.to_string(), self.get_json(name));
        }
        out
    }

    /// `Record.Clone` (data + original + id).
    pub fn clone_model(&self) -> Self {
        self.clone()
    }
}

/// `RecordUpsert.Submit` failure.
#[derive(Debug)]
pub enum SubmitError {
    /// `validation.Errors` -> 400 with the error tree in `data`.
    Validation(Errors),
    /// Raw driver/application error -> 400 with empty `data`.
    Raw(String),
}

fn fields_of(collection: &Collection) -> &[Value] {
    collection
        .fields
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

fn find_field<'a>(collection: &'a Collection, name: &str) -> Option<&'a Value> {
    fields_of(collection)
        .iter()
        .find(|field| field_name(field) == name)
}

fn column_to_string(raw: rusqlite::types::ValueRef<'_>) -> Option<String> {
    use rusqlite::types::ValueRef;
    match raw {
        ValueRef::Null => None,
        ValueRef::Integer(i) => Some(i.to_string()),
        ValueRef::Real(f) => Some(go_json::format_float(f)),
        ValueRef::Text(bytes) => Some(String::from_utf8_lossy(bytes).into_owned()),
        ValueRef::Blob(bytes) => Some(String::from_utf8_lossy(bytes).into_owned()),
    }
}

fn values_mismatch() -> Node {
    leaf("validation_values_mismatch", "Values don't match.")
}

fn unsupported_value_type() -> Node {
    // `validators.ErrUnsupportedValueType` has no public code/message in the
    // API; it only fires on internal misuse, never from request data.
    leaf("validation_invalid_value", "Invalid value")
}

pub(crate) fn prepare_value(field: &Value, raw: Option<&Value>) -> FieldValue {
    let null = Value::Null;
    let value = raw.unwrap_or(&null);
    match field_type(field) {
        "text" | "email" | "url" | "editor" => FieldValue::Text(cast_to_string(value)),
        "number" => FieldValue::Number(cast_to_f64(value)),
        "bool" => FieldValue::Bool(cast_to_bool(value)),
        "date" | "autodate" => FieldValue::Date(parse_date_time(value)),
        "select" | "relation" | "file" => FieldValue::List(normalize_list(field, value)),
        "json" => FieldValue::Json(prepare_json_raw(value)),
        "geoPoint" => {
            let (lon, lat) = geo_point(value);
            FieldValue::Geo { lon, lat }
        }
        "password" => FieldValue::Password {
            hash: cast_to_string(value),
            plain: String::new(),
        },
        _ => FieldValue::Text(cast_to_string(value)),
    }
}

/// `types.ParseDateTime` for a JSON value (only strings parse).
fn parse_date_time(value: &Value) -> String {
    match value {
        Value::String(s) => crate::fields::normalize_date(s),
        // Go's `DateTime.Scan` falls back to `cast.ToString` + `cast.ToTime`,
        // which cannot parse the textual form of a JSON number/bool.
        _ => String::new(),
    }
}

fn normalize_list(field: &Value, value: &Value) -> Vec<String> {
    let items = if field_type(field) == "file" {
        file_slice_value(value)
    } else {
        unique_string_slice(value)
    };
    normalize_single(field, items)
}

fn normalize_single(field: &Value, mut items: Vec<String>) -> Vec<String> {
    if is_multiple(field) {
        return items;
    }
    if items.len() > 1 {
        let last = items.pop().expect("non-empty");
        return vec![last];
    }
    items
}

/// `PasswordField` hashing (`bcrypt.GenerateFromPassword`, Go's `$2a$`).
pub fn hash_password(plain: &str, cost: i64) -> String {
    let cost = if cost <= 0 {
        DEFAULT_BCRYPT_COST
    } else {
        cost as u32
    };
    bcrypt::hash_with_result(plain, cost)
        .ok()
        .map(|result| result.format_for_version(bcrypt::Version::TwoA))
        .unwrap_or_default()
}

/// `validators.NormalizeUniqueIndexError`.
pub fn normalize_unique_index_error(
    message: &str,
    table: &str,
    field_names: &[String],
) -> Option<Errors> {
    let lower = message.to_lowercase();
    if !lower.contains("unique constraint failed") {
        return None;
    }
    let normalized = format!("{} ", lower.trim().replace(',', " "));
    let mut errors = Errors::new();
    for name in field_names {
        let needle = format!(" {}.{} ", table.to_lowercase(), name.to_lowercase());
        if normalized.contains(&needle) {
            errors.insert(
                name.clone(),
                leaf("validation_not_unique", "Value must be unique"),
            );
        }
    }
    if errors.is_empty() {
        None
    } else {
        Some(errors)
    }
}

// ---------------------------------------------------------------------------
// Field validators (`core/field_*.go`)
// ---------------------------------------------------------------------------

fn validate_plain_text(field: &Value, value: &str) -> Option<Node> {
    let required = field_bool(field, "required") || field_bool(field, "primaryKey");
    if required && value.is_empty() {
        return Some(crate::validation::required());
    }
    if value.is_empty() {
        return None;
    }

    let length = value.chars().count() as i64;
    let min = field_i64(field, "min");
    if min > 0 && length < min {
        return Some(leaf_with_params(
            "validation_min_text_constraint",
            "Must be at least {{.min}} character(s).",
            serde_json::json!({ "min": min }),
        ));
    }
    let mut max = field_i64(field, "max");
    if max == 0 {
        max = 5000;
    }
    if max > 0 && length > max {
        return Some(leaf_with_params(
            "validation_max_text_constraint",
            "Must be no more than {{.max}} character(s).",
            serde_json::json!({ "max": max }),
        ));
    }

    let pattern = field_str(field, "pattern");
    if !pattern.is_empty() && !regex_matches(pattern, value) {
        return Some(leaf("validation_invalid_format", "Invalid value format."));
    }

    if field_bool(field, "primaryKey") && pattern != DEFAULT_LOWERCASE_ID_PATTERN {
        for ch in [
            ".", "/", "\\", "|", "\"", "'", "`", "<", ">", ":", "?", "*", "%", "$", "\0", "\t",
            "\n", "\r", " ",
        ] {
            if value.contains(ch) {
                return Some(leaf_with_params(
                    "validation_forbidden_pk_character",
                    "'{{.ch}}' is not a valid primary key character.",
                    serde_json::json!({ "ch": ch }),
                ));
            }
        }

        if length <= 4 {
            for reserved in [
                "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6",
                "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7",
                "LPT8", "LPT9",
            ] {
                if value.eq_ignore_ascii_case(reserved) {
                    return Some(leaf_with_params(
                        "validation_reserved_pk",
                        "The primary key '{{.reserved}}' is reserved and cannot be used.",
                        serde_json::json!({ "reserved": reserved }),
                    ));
                }
            }
        }
    }
    None
}

fn validate_number(field: &Value, value: &FieldValue) -> Option<Node> {
    let FieldValue::Number(number) = value else {
        return Some(unsupported_value_type());
    };
    if number.is_nan() || number.is_infinite() {
        return Some(leaf(
            "validation_not_a_number",
            "The submitted number is not properly formatted",
        ));
    }
    if *number == 0.0 {
        return if field_bool(field, "required") {
            Some(crate::validation::required())
        } else {
            None
        };
    }
    if field_bool(field, "onlyInt") && *number != (*number as i64) as f64 {
        return Some(leaf(
            "validation_only_int_constraint",
            "Decimal numbers are not allowed",
        ));
    }
    if let Some(min) = field.get("min").and_then(Value::as_f64) {
        if *number < min {
            return Some(leaf_with_params(
                "validation_min_number_constraint",
                "Must be greater or equal than {{.min}}",
                serde_json::json!({ "min": go_json::number(min) }),
            ));
        }
    }
    if let Some(max) = field.get("max").and_then(Value::as_f64) {
        if *number > max {
            return Some(leaf_with_params(
                "validation_max_number_constraint",
                "Must be less or equal than {{.max}}",
                serde_json::json!({ "max": go_json::number(max) }),
            ));
        }
    }
    None
}

fn validate_email(field: &Value, value: &FieldValue) -> Option<Node> {
    let FieldValue::Text(email) = value else {
        return Some(unsupported_value_type());
    };
    if field_bool(field, "required") && email.is_empty() {
        return Some(crate::validation::required());
    }
    if email.is_empty() {
        return None;
    }
    if !is_email(email) {
        return Some(leaf(
            "validation_is_email",
            "must be a valid email address",
        ));
    }
    let domain = email.rsplit_once('@').map(|(_, d)| d).unwrap_or("");
    if domain_not_allowed(field, domain) {
        return Some(leaf(
            "validation_email_domain_not_allowed",
            "Email domain is not allowed",
        ));
    }
    None
}

fn validate_url(field: &Value, value: &FieldValue) -> Option<Node> {
    let FieldValue::Text(url) = value else {
        return Some(unsupported_value_type());
    };
    if field_bool(field, "required") && url.is_empty() {
        return Some(crate::validation::required());
    }
    if url.is_empty() {
        return None;
    }
    if !is_url(url) {
        return Some(leaf("validation_invalid_url", "Must be a valid url"));
    }
    let host = url_host(url);
    if domain_not_allowed(field, &host) {
        return Some(leaf(
            "validation_url_domain_not_allowed",
            "Url domain is not allowed",
        ));
    }
    None
}

fn domain_not_allowed(field: &Value, domain: &str) -> bool {
    let list = |key: &str| -> Vec<String> {
        field
            .get(key)
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    };
    let only = list("onlyDomains");
    let except = list("exceptDomains");
    if !only.is_empty() && !only.iter().any(|d| d == domain) {
        return true;
    }
    if !except.is_empty() && except.iter().any(|d| d == domain) {
        return true;
    }
    false
}

fn validate_date(field: &Value, value: &FieldValue) -> Option<Node> {
    let FieldValue::Date(date) = value else {
        return Some(unsupported_value_type());
    };
    if date.is_empty() {
        return if field_bool(field, "required") {
            Some(crate::validation::required())
        } else {
            None
        };
    }
    let Some(instant) = crate::fields::date_instant(date) else {
        return None;
    };

    if let Some(min) = field.get("min").and_then(Value::as_str) {
        if let Some(threshold) = crate::fields::date_instant(min) {
            if instant < threshold {
                return Some(leaf_with_params(
                    "validation_min_greater_equal_than_required",
                    format!("Must be no less than {}.", crate::fields::go_time_string(threshold)),
                    serde_json::json!({ "threshold": crate::fields::go_time_rfc3339(threshold) }),
                ));
            }
        }
    }
    if let Some(max) = field.get("max").and_then(Value::as_str) {
        if let Some(threshold) = crate::fields::date_instant(max) {
            if instant > threshold {
                return Some(leaf_with_params(
                    "validation_max_less_equal_than_required",
                    format!("Must be no greater than {}.", crate::fields::go_time_string(threshold)),
                    serde_json::json!({ "threshold": crate::fields::go_time_rfc3339(threshold) }),
                ));
            }
        }
    }
    None
}

fn validate_select(field: &Value, value: &FieldValue) -> Option<Node> {
    let FieldValue::List(items) = value else {
        return Some(unsupported_value_type());
    };
    if items.is_empty() {
        return if field_bool(field, "required") {
            Some(crate::validation::required())
        } else {
            None
        };
    }
    let max_select = field_i64(field, "maxSelect").max(1);
    if items.len() as i64 > max_select {
        return Some(leaf_with_params(
            "validation_too_many_values",
            "Select no more than {{.maxSelect}}",
            serde_json::json!({ "maxSelect": max_select }),
        ));
    }
    let values: Vec<&str> = field
        .get("values")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    for item in items {
        if !values.contains(&item.as_str()) {
            return Some(leaf_with_params(
                "validation_invalid_value",
                "Invalid value {{.value}}",
                serde_json::json!({ "value": item }),
            ));
        }
    }
    None
}

fn validate_json(field: &Value, value: &FieldValue) -> Option<Node> {
    let FieldValue::Json(raw) = value else {
        return Some(unsupported_value_type());
    };
    let mut max_size = field_i64(field, "maxSize");
    if max_size <= 0 {
        max_size = DEFAULT_JSON_MAX_SIZE;
    }
    if raw.len() as i64 > max_size {
        return Some(leaf_with_params(
            "validation_json_size_limit",
            "The maximum allowed JSON size is {{.maxSize}} bytes",
            serde_json::json!({ "maxSize": max_size }),
        ));
    }
    if !raw.is_empty() && serde_json::from_str::<Value>(raw).is_err() {
        return Some(leaf(
            "validation_invalid_json",
            "Must be a valid json value",
        ));
    }
    if field_bool(field, "required") {
        let trimmed = raw.trim();
        if matches!(trimmed, "null" | "\"\"" | "[]" | "{}" | "") {
            return Some(crate::validation::required());
        }
    }
    None
}

fn validate_editor(field: &Value, value: &FieldValue) -> Option<Node> {
    let FieldValue::Text(text) = value else {
        return Some(unsupported_value_type());
    };
    if field_bool(field, "required") && text.is_empty() {
        return Some(crate::validation::required());
    }
    let mut max_size = field_i64(field, "maxSize");
    if max_size <= 0 {
        max_size = DEFAULT_EDITOR_MAX_SIZE;
    }
    if text.len() as i64 > max_size {
        return Some(leaf_with_params(
            "validation_content_size_limit",
            "The maximum allowed content size is {{.maxSize}} bytes",
            serde_json::json!({ "maxSize": max_size }),
        ));
    }
    None
}

fn validate_password_field(field: &Value, value: &FieldValue) -> Option<Node> {
    let FieldValue::Password { hash, plain } = value else {
        return Some(unsupported_value_type());
    };
    if field_bool(field, "required") && hash.is_empty() {
        return Some(crate::validation::required());
    }
    if plain.is_empty() {
        return None;
    }
    let length = plain.chars().count() as i64;
    let min = field_i64(field, "min");
    if length < min {
        return Some(leaf(
            "validation_min_text_constraint",
            format!("Must be at least {min} character(s)"),
        ));
    }
    let mut max = field_i64(field, "max");
    if max <= 0 {
        max = 71;
    }
    if length > max {
        return Some(leaf(
            "validation_max_text_constraint",
            format!("Must be less than {max} character(s)"),
        ));
    }
    let pattern = field_str(field, "pattern");
    if !pattern.is_empty() && !regex_matches(pattern, plain) {
        return Some(leaf("validation_invalid_format", "Invalid value format"));
    }
    None
}

fn validate_geo(field: &Value, value: &FieldValue) -> Option<Node> {
    let FieldValue::Geo { lon, lat } = value else {
        return Some(unsupported_value_type());
    };
    if *lat == 0.0 && *lon == 0.0 {
        return if field_bool(field, "required") {
            Some(crate::validation::required())
        } else {
            None
        };
    }
    if *lat < -90.0 || *lat > 90.0 {
        return Some(leaf(
            "validation_invalid_latitude",
            "Latitude must be between -90 and 90 degrees.",
        ));
    }
    if *lon < -180.0 || *lon > 180.0 {
        return Some(leaf(
            "validation_invalid_longitude",
            "Longitude must be between -180 and 180 degrees.",
        ));
    }
    None
}

fn regex_matches(pattern: &str, value: &str) -> bool {
    regex::Regex::new(pattern)
        .map(|re| re.is_match(value))
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// `security.RandomStringByRegex`
// ---------------------------------------------------------------------------

/// `security.RandomStringByRegex(pattern)` with Go's `syntax.Perl` flags and
/// `defaultMaxRepeat = 6`.
pub fn random_string_by_regex(pattern: &str) -> std::result::Result<String, String> {
    let hir = regex_syntax::Parser::new()
        .parse(pattern)
        .map_err(|e| e.to_string())?;
    let mut out = String::new();
    write_random(&hir, &mut out)?;
    Ok(out)
}

fn write_random(hir: &regex_syntax::hir::Hir, out: &mut String) -> std::result::Result<(), String> {
    use regex_syntax::hir::{Class, HirKind};

    match hir.kind() {
        HirKind::Empty => Ok(()),
        HirKind::Literal(literal) => {
            let text = std::str::from_utf8(&literal.0).map_err(|e| e.to_string())?;
            out.push_str(text);
            Ok(())
        }
        HirKind::Class(Class::Unicode(class)) => {
            let ranges: Vec<(u32, u32)> = class
                .ranges()
                .iter()
                .map(|range| (range.start() as u32, range.end() as u32))
                .collect();
            out.push(random_rune(&ranges)?);
            Ok(())
        }
        HirKind::Class(Class::Bytes(class)) => {
            let ranges: Vec<(u32, u32)> = class
                .ranges()
                .iter()
                .map(|range| (range.start() as u32, range.end() as u32))
                .collect();
            out.push(random_rune(&ranges)?);
            Ok(())
        }
        HirKind::Look(_) => Ok(()),
        HirKind::Repetition(repetition) => {
            let min = repetition.min as usize;
            let max = repetition.max.map(|m| m as usize).unwrap_or(6);
            let max = if max < min { min } else { max };
            let mut count = min;
            if max != min {
                count += random_number(max - min);
            }
            for _ in 0..count {
                write_random(&repetition.sub, out)?;
            }
            Ok(())
        }
        HirKind::Capture(capture) => write_random(&capture.sub, out),
        HirKind::Concat(items) => {
            for item in items {
                write_random(item, out)?;
            }
            Ok(())
        }
        HirKind::Alternation(items) => {
            let index = random_number(items.len());
            write_random(&items[index], out)
        }
    }
}

fn random_rune(ranges: &[(u32, u32)]) -> std::result::Result<char, String> {
    let total: u32 = ranges.iter().map(|(start, end)| end - start + 1).sum();
    if total == 0 {
        return Err("no runes to choose from".to_string());
    }
    let mut pick = random_number(total as usize) as u32;
    for (start, end) in ranges {
        let size = end - start + 1;
        if pick < size {
            return char::from_u32(start + pick).ok_or_else(|| "invalid rune".to_string());
        }
        pick -= size;
    }
    Err("unreachable: failed to find a rune".to_string())
}

fn random_number(max: usize) -> usize {
    use rand::Rng;
    if max == 0 {
        return 0;
    }
    rand::thread_rng().gen_range(0..max)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fields::go_quote;
    use crate::{migrations, seed};

    fn fresh() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        migrations::migrate_data(&conn).unwrap();
        seed::seed(&conn).unwrap();
        conn
    }

    fn base_collection(_conn: &Connection) -> Collection {
        let value = serde_json::json!({
            "name": "things",
            "type": "base",
            "fields": [
                {"name":"id","type":"text","primaryKey":true,"required":true,"system":true,
                 "min":15,"max":15,"pattern":"^[a-z0-9]+$","autogeneratePattern":"[a-z0-9]{15}"},
                {"name":"title","type":"text"},
                {"name":"num","type":"number"},
                {"name":"flag","type":"bool"},
                {"name":"when","type":"date"},
                {"name":"many","type":"select","values":["a","b","c"],"maxSelect":3},
                {"name":"one","type":"select","values":["a","b","c"],"maxSelect":0},
                {"name":"js","type":"json"},
                {"name":"geo","type":"geoPoint"},
                {"name":"stamp","type":"autodate","onCreate":true,"onUpdate":true},
            ],
        });
        let fields = crate::fields::FieldsList::from_request(&value["fields"])
            .unwrap()
            .to_json();
        Collection {
            id: "pbc_test".into(),
            system: false,
            kind: "base".into(),
            name: "things".into(),
            fields,
            indexes: Value::Array(vec![]),
            list_rule: None,
            view_rule: None,
            create_rule: None,
            update_rule: None,
            delete_rule: None,
            options: Value::Object(Map::new()),
            created: String::new(),
            updated: String::new(),
        }
    }

    fn create_table(conn: &Connection, collection: &Collection) {
        conn.execute_batch(&crate::schema_sync::create_table_sql(collection))
            .unwrap();
    }

    #[test]
    fn create_normalizes_and_autogenerates() {
        let conn = fresh();
        let collection = base_collection(&conn);
        create_table(&conn, &collection);

        let mut record = RecordModel::new(&collection);
        let payload: Map<String, Value> = serde_json::from_str(
            r#"{"title":123,"num":"1.5","flag":"true","when":"2024-05-01 10:00:00.000Z",
                "many":["a","b","a"],"one":["a","b"],"js":{"b":2,"a":1.0},"geo":{"lon":1,"lat":2}}"#,
        )
        .unwrap();
        record.load(&payload);
        record.submit(&conn).unwrap();

        assert_eq!(record.id().len(), 15);
        assert_eq!(record.get_json("title"), Value::String("123".into()));
        assert_eq!(record.get_json("num"), serde_json::json!(1.5));
        assert_eq!(record.get_json("flag"), Value::Bool(true));
        assert_eq!(
            record.get_json("many"),
            serde_json::json!(["a", "b"])
        );
        assert_eq!(record.get_json("one"), Value::String("b".into()));
        assert_eq!(record.get_json("js"), serde_json::json!({"a": 1, "b": 2}));
        assert_eq!(
            record.get_json("geo"),
            serde_json::json!({"lon": 1, "lat": 2})
        );
        assert!(!record.get_json("stamp").as_str().unwrap().is_empty());
    }

    #[test]
    fn modifiers_match_go() {
        let conn = fresh();
        let collection = base_collection(&conn);
        create_table(&conn, &collection);

        let mut record = RecordModel::new(&collection);
        record.load(&serde_json::from_str(r#"{"num":10,"many":["a","b"]}"#).unwrap());
        record.submit(&conn).unwrap();

        let payload: Map<String, Value> = serde_json::from_str(
            r#"{"num+":5,"num-":2,"many+":["b","c"],"one":["a","b"]}"#,
        )
        .unwrap();
        let resolved = record.replace_modifiers(&payload);
        record.load(&resolved);
        record.submit(&conn).unwrap();
        assert_eq!(record.get_json("num"), serde_json::json!(13));
        assert_eq!(record.get_json("many"), serde_json::json!(["a", "b", "c"]));
        assert_eq!(record.get_json("one"), Value::String("b".into()));
    }

    #[test]
    fn invalid_values_report_the_oracle_codes() {
        let conn = fresh();
        let mut collection = base_collection(&conn);
        create_table(&conn, &collection);

        collection.fields = crate::fields::FieldsList::from_request(&serde_json::json!([
            {"name":"id","type":"text","primaryKey":true,"required":true,"system":true,
             "min":15,"max":15,"pattern":"^[a-z0-9]+$","autogeneratePattern":"[a-z0-9]{15}"},
            {"name":"title","type":"text","min":3,"required":true},
            {"name":"num","type":"number","min":1.5,"max":2.5,"onlyInt":true},
        ]))
        .unwrap()
        .to_json();

        let mut record = RecordModel::new(&collection);
        record.load(&serde_json::from_str(r#"{"title":"a","num":3}"#).unwrap());
        let errors = record.submit(&conn).unwrap_err();
        let SubmitError::Validation(errors) = errors else {
            panic!("expected validation errors");
        };
        assert_eq!(
            errors["title"],
            leaf_with_params(
                "validation_min_text_constraint",
                "Must be at least {{.min}} character(s).",
                serde_json::json!({"min": 3})
            )
        );
        assert_eq!(
            errors["num"],
            leaf_with_params(
                "validation_max_number_constraint",
                "Must be less or equal than {{.max}}",
                serde_json::json!({"max": go_json::number(2.5)})
            )
        );
    }

    #[test]
    fn auth_password_and_email_rules() {
        let conn = fresh();
        let collection = Collection::find(&conn, "_superusers").unwrap().unwrap();

        let mut record = RecordModel::new(&collection);
        record.load(
            &serde_json::from_str(
                r#"{"email":"bad","password":"short","passwordConfirm":"short"}"#,
            )
            .unwrap(),
        );
        let SubmitError::Validation(errors) = record.submit(&conn).unwrap_err() else {
            panic!("expected validation errors");
        };
        assert_eq!(
            errors["email"].clone(),
            leaf("validation_is_email", "must be a valid email address")
        );
        assert_eq!(
            errors["password"].clone(),
            leaf(
                "validation_min_text_constraint",
                "Must be at least 8 character(s)"
            )
        );

        let mut record = RecordModel::new(&collection);
        record.load(
            &serde_json::from_str(
                r#"{"email":"ok@example.com","password":"pass12345678","passwordConfirm":"pass12345678"}"#,
            )
            .unwrap(),
        );
        record.submit(&conn).unwrap();
        assert!(record.validate_password("pass12345678"));
        assert_eq!(record.token_key().len(), 50);
    }

    #[test]
    fn random_regex_strings_follow_the_pattern() {
        let key = random_string_by_regex("[a-zA-Z0-9]{50}").unwrap();
        assert_eq!(key.len(), 50);
        assert!(key.chars().all(|c| c.is_ascii_alphanumeric()));
        let id = random_string_by_regex("[a-z0-9]{15}").unwrap();
        assert_eq!(id.len(), 15);
        assert!(id.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
    }

    #[test]
    fn unique_errors_are_normalized() {
        let fields = vec!["id".to_string(), "email".to_string()];
        let errors = normalize_unique_index_error(
            "constraint failed: UNIQUE constraint failed: users.email (2067)",
            "users",
            &fields,
        )
        .unwrap();
        assert_eq!(
            errors["email"],
            leaf("validation_not_unique", "Value must be unique")
        );
        assert!(normalize_unique_index_error("some other error", "users", &fields).is_none());
    }

    #[test]
    fn public_export_hides_hidden_and_email() {
        let conn = fresh();
        let collection = Collection::find(&conn, "_superusers").unwrap().unwrap();
        let mut record = RecordModel::new(&collection);
        record.load(
            &serde_json::from_str(
                r#"{"email":"x@y.co","password":"pass12345678","passwordConfirm":"pass12345678"}"#,
            )
            .unwrap(),
        );
        record.submit(&conn).unwrap();

        let json = record.to_api_json();
        assert!(json.get("password").is_none());
        assert!(json.get("tokenKey").is_none());
        assert!(json.get("email").is_none(), "emailVisibility is false by default");

        let mut visibility = Visibility::default();
        visibility.ignore_email_visibility = true;
        visibility.unhide("password");
        let json = record.to_api_json_with(&visibility);
        assert_eq!(json["email"], Value::String("x@y.co".into()));
        // Auth records always delete the password/tokenKey, even when unhidden.
        assert!(json.get("password").is_none());
        assert!(json.get("tokenKey").is_none());
    }

    #[test]
    fn json_empty_values_are_stored_as_null() {
        let conn = fresh();
        let collection = base_collection(&conn);
        create_table(&conn, &collection);
        let mut record = RecordModel::new(&collection);
        record.load(&serde_json::from_str(r#"{"js":null}"#).unwrap());
        record.submit(&conn).unwrap();
        let export = record.db_export();
        assert_eq!(export["js"], rusqlite::types::Value::Null);
        assert_eq!(record.get_json("js"), Value::Null);

        let mut record = RecordModel::new(&collection);
        record.load(&serde_json::from_str(r#"{"js":""}"#).unwrap());
        record.submit(&conn).unwrap();
        assert_eq!(
            record.db_export()["js"],
            rusqlite::types::Value::Text(go_quote(""))
        );
    }
}
