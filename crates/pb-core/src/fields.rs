//! Collection fields: the `fields` JSON array and its semantics.
//!
//! Mirrors `core/field.go` and `core/fields_list.go`:
//!
//! * every field type has a fixed set of keys with zero defaults, so a request
//!   that only sends `{"name": "...", "type": "text"}` still produces the full
//!   canonical object;
//! * `FieldsList.add` generates missing ids as `type + crc32(name)` (with a
//!   `2..999` suffix on collision) and replaces an existing field in place when
//!   the name (id-less field) or the id matches;
//! * the stored JSON is key-sorted (`json.Deterministic(true)` in Go).

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use crate::ids::crc32;
use crate::validation::{branch, leaf, leaf_with_params, length, push, required, Errors, Node};

/// `core.maxSafeJSONInt`
pub const MAX_SAFE_JSON_INT: i64 = (1 << 53) - 1;

/// The `id` primary key column name (`core.FieldNameId`).
pub const FIELD_NAME_ID: &str = "id";
/// `core.FieldNamePassword`
pub const FIELD_NAME_PASSWORD: &str = "password";
/// `core.FieldNameTokenKey`
pub const FIELD_NAME_TOKEN_KEY: &str = "tokenKey";
/// `core.FieldNameEmail`
pub const FIELD_NAME_EMAIL: &str = "email";
/// `core.FieldNameEmailVisibility`
pub const FIELD_NAME_EMAIL_VISIBILITY: &str = "emailVisibility";
/// `core.FieldNameVerified`
pub const FIELD_NAME_VERIFIED: &str = "verified";

/// Names that cannot be used as a field name
/// (`core.excludeNames`: filter literals + system dynamic fields).
const EXCLUDED_NAMES: &[&str] = &[
    "null",
    "true",
    "false",
    "_rowid_",
    "collectionId",
    "collectionName",
    "expand",
];

/// Reserved auth field names (`core.reservedAuthKeys`).
pub const RESERVED_AUTH_KEYS: &[&str] = &["passwordConfirm", "oldPassword"];

/// All field types known to the oracle (`core.Fields`).
pub const TYPES: &[&str] = &[
    "text",
    "number",
    "bool",
    "email",
    "url",
    "date",
    "autodate",
    "select",
    "file",
    "relation",
    "json",
    "editor",
    "password",
    "geoPoint",
];

/// A failed JSON bind (`e.BindBody`), reported as
/// "Failed to load the submitted data due to invalid formatting.".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindError;

/// The JSON type a field setting accepts, used to emulate Go's struct
/// unmarshalling (unknown keys ignored, `null` -> zero value, mismatches fail).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ty {
    Str,
    Bool,
    Int,
    FloatOrNull,
    StrArray,
}

fn schema(kind: &str) -> Option<&'static [(&'static str, Ty)]> {
    use Ty::*;
    Some(match kind {
        "text" => &[
            ("name", Str), ("id", Str), ("system", Bool), ("hidden", Bool), ("presentable", Bool),
            ("help", Str), ("min", Int), ("max", Int), ("pattern", Str),
            ("autogeneratePattern", Str), ("required", Bool), ("primaryKey", Bool),
        ],
        "number" => &[
            ("name", Str), ("id", Str), ("system", Bool), ("hidden", Bool), ("presentable", Bool),
            ("help", Str), ("min", FloatOrNull), ("max", FloatOrNull),
            ("onlyInt", Bool), ("required", Bool),
        ],
        "bool" => &[
            ("name", Str), ("id", Str), ("system", Bool), ("hidden", Bool), ("presentable", Bool),
            ("help", Str), ("required", Bool),
        ],
        "email" | "url" => &[
            ("name", Str), ("id", Str), ("system", Bool), ("hidden", Bool), ("presentable", Bool),
            ("help", Str), ("exceptDomains", StrArray), ("onlyDomains", StrArray), ("required", Bool),
        ],
        "date" => &[
            ("name", Str), ("id", Str), ("system", Bool), ("hidden", Bool), ("presentable", Bool),
            ("help", Str), ("min", Str), ("max", Str), ("required", Bool),
        ],
        // autodate has neither `help` nor `required` (see core/field_autodate.go)
        "autodate" => &[
            ("name", Str), ("id", Str), ("system", Bool), ("hidden", Bool), ("presentable", Bool),
            ("onCreate", Bool), ("onUpdate", Bool),
        ],
        "select" => &[
            ("name", Str), ("id", Str), ("system", Bool), ("hidden", Bool), ("presentable", Bool),
            ("help", Str), ("values", StrArray), ("maxSelect", Int), ("required", Bool),
        ],
        "file" => &[
            ("name", Str), ("id", Str), ("system", Bool), ("hidden", Bool), ("presentable", Bool),
            ("help", Str), ("maxSize", Int), ("maxSelect", Int), ("mimeTypes", StrArray),
            ("thumbs", StrArray), ("protected", Bool), ("required", Bool),
        ],
        "relation" => &[
            ("name", Str), ("id", Str), ("system", Bool), ("hidden", Bool), ("presentable", Bool),
            ("help", Str), ("collectionId", Str), ("cascadeDelete", Bool),
            ("minSelect", Int), ("maxSelect", Int), ("required", Bool),
        ],
        "json" => &[
            ("name", Str), ("id", Str), ("system", Bool), ("hidden", Bool), ("presentable", Bool),
            ("help", Str), ("maxSize", Int), ("required", Bool),
        ],
        "editor" => &[
            ("name", Str), ("id", Str), ("system", Bool), ("hidden", Bool), ("presentable", Bool),
            ("help", Str), ("maxSize", Int), ("convertURLs", Bool), ("required", Bool),
        ],
        "password" => &[
            ("name", Str), ("id", Str), ("system", Bool), ("hidden", Bool), ("presentable", Bool),
            ("help", Str), ("pattern", Str), ("min", Int), ("max", Int), ("cost", Int), ("required", Bool),
        ],
        "geoPoint" => &[
            ("name", Str), ("id", Str), ("system", Bool), ("hidden", Bool), ("presentable", Bool),
            ("help", Str), ("required", Bool),
        ],
        _ => return None,
    })
}

fn put(map: &mut BTreeMap<&'static str, Value>, key: &'static str, value: Value) {
    map.insert(key, value);
}

/// The zero value of every field type, exactly as `Fields[type]()` serializes.
fn zero(kind: &str) -> Option<BTreeMap<&'static str, Value>> {
    let mut m: BTreeMap<&'static str, Value> = BTreeMap::new();
    for (key, ty) in schema(kind)? {
        let value = match (*key, ty) {
            (_, Ty::Str) => Value::String(String::new()),
            (_, Ty::Bool) => Value::Bool(false),
            (_, Ty::Int) => Value::from(0),
            (_, Ty::FloatOrNull) => Value::Null,
            (_, Ty::StrArray) => Value::Array(vec![]),
        };
        put(&mut m, key, value);
    }
    put(&mut m, "type", Value::String(kind.to_string()));
    Some(m)
}

/// Canonicalize a field object: key-sorted, with `type` present.
fn canonical(mut map: BTreeMap<String, Value>) -> Value {
    let mut out = Map::new();
    for (key, value) in std::mem::take(&mut map) {
        out.insert(key, value);
    }
    Value::Object(out)
}

/// `marshaledJSONtoFieldsList` + `fieldWithType.UnmarshalJSON`: build a canonical
/// field from a request object.
pub fn from_request(raw: &Value) -> Result<Value, BindError> {
    let obj = raw.as_object().ok_or(BindError)?;
    let kind = obj
        .get("type")
        .and_then(Value::as_str)
        .filter(|kind| schema(kind).is_some())
        .ok_or(BindError)?;

    let mut merged: BTreeMap<String, Value> = zero(kind)
        .expect("schema checked above")
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();

    for (key, value) in obj {
        let Some((canonical_key, ty)) = schema(kind)
            .expect("schema checked above")
            .iter()
            .find(|(name, _)| name == key)
        else {
            continue; // unknown keys are ignored, like Go's struct unmarshal
        };
        let coerced = coerce(*ty, value)?;
        merged.insert((*canonical_key).to_string(), coerced);
    }

    // `types.DateTime` round-trips through `DefaultDateLayout`, so a valid date
    // is stored normalized and an unparseable one collapses to the zero value.
    if kind == "date" {
        for key in ["min", "max"] {
            if let Some(Value::String(raw)) = merged.get(key).cloned() {
                merged.insert(key.to_string(), Value::String(normalize_date(&raw)));
            }
        }
    }

    Ok(canonical(merged))
}

fn coerce(ty: Ty, value: &Value) -> Result<Value, BindError> {
    match ty {
        Ty::Str => match value {
            Value::Null => Ok(Value::String(String::new())),
            Value::String(s) => Ok(Value::String(s.clone())),
            _ => Err(BindError),
        },
        Ty::Bool => match value {
            Value::Null => Ok(Value::Bool(false)),
            Value::Bool(b) => Ok(Value::Bool(*b)),
            _ => Err(BindError),
        },
        Ty::Int => match value {
            Value::Null => Ok(Value::from(0)),
            Value::Number(n) => n.as_i64().map(Value::from).ok_or(BindError),
            _ => Err(BindError),
        },
        Ty::FloatOrNull => match value {
            Value::Null => Ok(Value::Null),
            // Go marshals a `*float64` with the shortest representation, so an
            // integral value round-trips as an integer (`1`, not `1.0`).
            Value::Number(n) => Ok(match n.as_f64() {
                Some(f) if f.fract() == 0.0 && f.abs() < 9.007_199_254_740_992e15 => {
                    Value::from(f as i64)
                }
                Some(_) => value.clone(),
                None => return Err(BindError),
            }),
            _ => Err(BindError),
        },
        Ty::StrArray => match value {
            Value::Null => Ok(Value::Array(vec![])),
            Value::Array(items) => items
                .iter()
                .map(|item| match item {
                    Value::String(s) => Ok(Value::String(s.clone())),
                    _ => Err(BindError),
                })
                .collect(),
            _ => Err(BindError),
        },
    }
}

/// `FieldsList`: ordered fields with the oracle's add/replace semantics.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct FieldsList {
    items: Vec<Value>,
}

impl FieldsList {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build from already-canonical items (a stored `fields` array).
    pub fn from_items(items: Vec<Value>) -> Self {
        Self { items }
    }

    /// `FieldsList.UnmarshalJSON`: parse a request array, adding each field.
    pub fn from_request(value: &Value) -> Result<Self, BindError> {
        let array = value.as_array().ok_or(BindError)?;
        let mut list = Self::new();
        for item in array {
            list.add(from_request(item)?);
        }
        Ok(list)
    }

    /// Parse the stored `fields` JSON column. Stored rows are trusted.
    pub fn from_stored(value: &Value) -> Self {
        let items = value
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .map(|item| match item.as_object() {
                        Some(obj) => canonical(obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect()),
                        None => Value::Null,
                    })
                    .collect()
            })
            .unwrap_or_default();
        Self { items }
    }

    pub fn items(&self) -> &[Value] {
        &self.items
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn get_by_name(&self, name: &str) -> Option<&Value> {
        self.items.iter().find(|f| field_name(f) == name)
    }

    pub fn get_by_name_mut(&mut self, name: &str) -> Option<&mut Value> {
        self.items.iter_mut().find(|f| field_name(f) == name)
    }

    /// `FieldsList = NewFieldsList(Fields...)`: re-add every field so that the
    /// normalizations (default id, replace-by-name) apply again.
    pub fn renormalize(&mut self) {
        let items = std::mem::take(&mut self.items);
        for item in items {
            self.add(item);
        }
    }

    /// `NewFieldsList(field, ...existing)`: prepend after re-adding every field.
    pub fn prepend(&mut self, field: Value) {
        let mut items = std::mem::take(&mut self.items);
        items.insert(0, field);
        for item in items {
            self.add(item);
        }
    }

    pub fn get_by_id(&self, id: &str) -> Option<&Value> {
        self.items.iter().find(|f| field_id(f) == id)
    }

    pub fn names(&self) -> Vec<&str> {
        self.items.iter().map(field_name).collect()
    }

    /// `FieldsList.add(-1, field)`.
    pub fn add(&mut self, field: Value) {
        let mut field = field;
        let mut replace_by_name = false;
        let mut new_id = field_id(&field).to_string();

        if new_id.is_empty() {
            replace_by_name = true;
            let base = format!("{}{}", field_type(&field), crc32(field_name(&field)));
            new_id = base.clone();
            for i in 2..1000 {
                if self.get_by_id(&new_id).is_none() {
                    break;
                }
                new_id = format!("{base}{i}");
            }
            set_field_id(&mut field, &new_id);
        }

        for i in 0..self.items.len() {
            let existing = &self.items[i];
            let matches = if replace_by_name {
                let name = field_name(&field);
                !name.is_empty() && field_name(existing) == name
            } else {
                field_id(existing) == new_id
            };
            if matches {
                if replace_by_name {
                    // reuse the original id
                    let existing_id = field_id(existing).to_string();
                    set_field_id(&mut field, &existing_id);
                }
                self.items[i] = field;
                return;
            }
        }

        self.items.push(field);
    }

    /// The stored JSON array (`FieldsList.MarshalJSON`).
    pub fn to_json(&self) -> Value {
        Value::Array(self.items.clone())
    }
}

pub fn field_name(field: &Value) -> &str {
    field.get("name").and_then(Value::as_str).unwrap_or("")
}

pub fn field_id(field: &Value) -> &str {
    field.get("id").and_then(Value::as_str).unwrap_or("")
}

pub fn field_type(field: &Value) -> &str {
    field.get("type").and_then(Value::as_str).unwrap_or("")
}

pub fn field_bool(field: &Value, key: &str) -> bool {
    field.get(key).and_then(Value::as_bool).unwrap_or(false)
}

pub fn field_str<'a>(field: &'a Value, key: &str) -> &'a str {
    field.get(key).and_then(Value::as_str).unwrap_or("")
}

pub fn field_i64(field: &Value, key: &str) -> i64 {
    field.get(key).and_then(Value::as_i64).unwrap_or(0)
}

fn set_field_id(field: &mut Value, id: &str) {
    if let Some(obj) = field.as_object_mut() {
        obj.insert("id".to_string(), Value::String(id.to_string()));
    }
}

/// Set a string setting on a canonical field object.
pub fn set_str(field: &mut Value, key: &str, value: &str) {
    if let Some(obj) = field.as_object_mut() {
        obj.insert(key.to_string(), Value::String(value.to_string()));
    }
}

/// Set a bool setting on a canonical field object.
pub fn set_bool(field: &mut Value, key: &str, value: bool) {
    if let Some(obj) = field.as_object_mut() {
        obj.insert(key.to_string(), Value::Bool(value));
    }
}

/// Set an integer setting on a canonical field object.
pub fn set_i64(field: &mut Value, key: &str, value: i64) {
    if let Some(obj) = field.as_object_mut() {
        obj.insert(key.to_string(), Value::from(value));
    }
}

// ---------------------------------------------------------------------------
// Dates (`types.DateTime`)
// ---------------------------------------------------------------------------

/// Parse the date layouts `cast.ToTime` accepts in practice and return the
/// instant as seconds since the epoch plus its UTC `DefaultDateLayout` form.
fn parse_date_parts(value: &str) -> Option<(i64, String)> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }

    // `YYYY-MM-DD[ T]HH:MM:SS[.sss][Z|±HH:MM]` and the bare `YYYY-MM-DD`.
    let bytes = value.as_bytes();
    if bytes.len() < 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    let year: i64 = value[0..4].parse().ok()?;
    let month: i64 = value[5..7].parse().ok()?;
    let day: i64 = value[8..10].parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }

    let mut hour = 0i64;
    let mut minute = 0i64;
    let mut second = 0i64;
    let mut millis = 0i64;
    let mut offset_minutes = 0i64;

    if bytes.len() > 10 {
        if bytes[10] != b' ' && bytes[10] != b'T' {
            return None;
        }
        if bytes.len() < 19 {
            return None;
        }
        hour = value[11..13].parse().ok()?;
        minute = value[14..16].parse().ok()?;
        second = value[17..19].parse().ok()?;
        let mut rest = &value[19..];
        if let Some(fraction) = rest.strip_prefix('.') {
            let digits: String = fraction.chars().take_while(char::is_ascii_digit).collect();
            if digits.is_empty() {
                return None;
            }
            let mut padded = digits.clone();
            padded.truncate(3);
            while padded.len() < 3 {
                padded.push('0');
            }
            millis = padded.parse().ok()?;
            rest = &fraction[digits.len()..];
        }
        match rest {
            "" | "Z" | "z" => {}
            _ => {
                // ±HH:MM
                let sign = match rest.as_bytes().first() {
                    Some(b'+') => 1,
                    Some(b'-') => -1,
                    _ => return None,
                };
                let body = &rest[1..];
                let (h, m) = match body.len() {
                    5 if body.as_bytes()[2] == b':' => (&body[0..2], &body[3..5]),
                    4 => (&body[0..2], &body[2..4]),
                    2 => (body, "0"),
                    _ => return None,
                };
                let h: i64 = h.parse().ok()?;
                let m: i64 = m.parse().ok()?;
                offset_minutes = sign * (h * 60 + m);
            }
        }
    }

    // Days since 1970-01-01 (proleptic Gregorian), `civil_from_days` inverse.
    let y = year - if month <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;

    // Normalize to UTC, like `DateTime.String()` (`t.UTC().Format(layout)`).
    let total_seconds = days * 86_400 + hour * 3_600 + minute * 60 + second - offset_minutes * 60;
    let utc_days = total_seconds.div_euclid(86_400);
    let secs = total_seconds.rem_euclid(86_400);
    let (uy, um, ud) = civil_from_days(utc_days);
    let normalized = format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}Z",
        uy,
        um,
        ud,
        secs / 3_600,
        (secs % 3_600) / 60,
        secs % 60,
        millis
    );
    Some((total_seconds * 1000 + millis, normalized))
}

/// Howard Hinnant's `civil_from_days`.
pub(crate) fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Howard Hinnant's `days_from_civil` (inverse of [`civil_from_days`]).
pub(crate) fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `types.DateTime.Scan` + `String()`: normalize a date, or `""` when unparsable.
pub fn normalize_date(value: &str) -> String {
    parse_date_parts(value)
        .map(|(_, normalized)| normalized)
        .unwrap_or_default()
}

/// The instant of a date string, or `None` for the zero value.
pub fn date_instant(value: &str) -> Option<i64> {
    parse_date_parts(value).map(|(instant, _)| instant)
}

// ---------------------------------------------------------------------------
// Go `cast` / `list` helpers used by record normalization
// ---------------------------------------------------------------------------

/// `strconv.FormatFloat(f, 'f', -1, 64)` (never exponent notation).
pub fn format_float_fixed(f: f64) -> String {
    if f.is_nan() {
        return "NaN".to_string();
    }
    if f.is_infinite() {
        return if f.is_sign_negative() { "-Inf" } else { "+Inf" }.to_string();
    }
    format!("{f}")
}

/// `cast.ToString` for the values that come out of a JSON body.
pub fn cast_to_string(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.as_f64().map(format_float_fixed).unwrap_or_default(),
        Value::String(s) => s.clone(),
        // Go's cast returns an error for arrays/maps, which callers ignore.
        Value::Array(_) | Value::Object(_) => String::new(),
    }
}

/// `cast.ToFloat64`.
pub fn cast_to_f64(value: &Value) -> f64 {
    match value {
        Value::Null => 0.0,
        Value::Bool(b) => {
            if *b {
                1.0
            } else {
                0.0
            }
        }
        Value::Number(n) => n.as_f64().unwrap_or(0.0),
        Value::String(s) => {
            if s.is_empty() {
                0.0
            } else {
                s.parse::<f64>().unwrap_or(0.0)
            }
        }
        Value::Array(_) | Value::Object(_) => 0.0,
    }
}

/// `cast.ToBool`.
pub fn cast_to_bool(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().map(|f| f != 0.0).unwrap_or(false),
        Value::String(s) => matches!(
            s.as_str(),
            "1" | "t" | "T" | "TRUE" | "true" | "True" | "0" | "f" | "F" | "FALSE" | "false"
                | "False"
        ) && !matches!(s.as_str(), "0" | "f" | "F" | "FALSE" | "false" | "False"),
        Value::Array(_) | Value::Object(_) => false,
    }
}

/// `list.ToUniqueStringSlice` (non-zero unique, order preserved).
pub fn unique_string_slice(value: &Value) -> Vec<String> {
    let raw: Vec<String> = match value {
        Value::Null => Vec::new(),
        Value::String(s) => {
            if s.is_empty() {
                Vec::new()
            } else if s.contains('[') {
                match serde_json::from_str::<Vec<String>>(s) {
                    Ok(items) => items,
                    Err(_) => vec![s.clone()],
                }
            } else {
                vec![s.clone()]
            }
        }
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                if matches!(item, Value::Array(_) | Value::Object(_)) {
                    // `cast.ToStringSlice` fails as a whole.
                    return Vec::new();
                }
                out.push(cast_to_string(item));
            }
            out
        }
        Value::Object(_) => Vec::new(),
        other => vec![cast_to_string(other)],
    };

    let mut seen = std::collections::HashSet::new();
    raw.into_iter()
        .filter(|s| !s.is_empty() && seen.insert(s.clone()))
        .collect()
}

/// `FileField.toSliceValue`: flatten one-element nested arrays.
pub fn file_slice_value(value: &Value) -> Vec<String> {
    match value {
        Value::Array(items) => {
            let mut out = Vec::new();
            for item in items {
                let casted = file_slice_value(item);
                if casted.len() == 1 {
                    out.push(casted[0].clone());
                }
            }
            out
        }
        other => unique_string_slice(other),
    }
}

/// `strconv.Quote` (used by `JSONField.PrepareValue`).
pub fn go_quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\x07' => out.push_str("\\a"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x0b' => out.push_str("\\v"),
            c if is_go_print(c) => out.push(c),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\x{:02x}", c as u32)),
            c if (c as u32) < 0x10000 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push_str(&format!("\\U{:08x}", c as u32)),
        }
    }
    out.push('"');
    out
}

/// Approximation of Go's `strconv.IsPrint`.
fn is_go_print(ch: char) -> bool {
    if ch == ' ' {
        return true;
    }
    if ch.is_ascii() {
        return ch.is_ascii_graphic();
    }
    !ch.is_control()
}

/// `is.JSON.Validate`: `json.Unmarshal` into a `RawMessage`.
pub fn is_valid_json(value: &str) -> bool {
    serde_json::from_str::<Value>(value).is_ok()
}

/// `JSONField.PrepareValue` -> `types.JSONRaw` text.
pub fn prepare_json_raw(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::String(s) => {
            if s.is_empty() {
                go_quote(s)
            } else if s == "null" || s == "true" || s == "false" {
                s.clone()
            } else {
                let first = s.chars().next().unwrap_or('\0');
                let json_like = first.is_ascii_digit()
                    || first == '-'
                    || first == '"'
                    || first == '['
                    || first == '{';
                if json_like && is_valid_json(s) {
                    s.clone()
                } else {
                    go_quote(s)
                }
            }
        }
        other => crate::go_json::marshal(other),
    }
}

/// `GeoPoint.Scan`: only object notation with numeric (or missing) lon/lat is
/// accepted; everything else collapses to the zero point.
pub fn geo_point(value: &Value) -> (f64, f64) {
    fn number(value: Option<&Value>) -> Option<f64> {
        match value {
            None | Some(Value::Null) => Some(0.0),
            Some(Value::Number(n)) => n.as_f64(),
            _ => None,
        }
    }

    let object = match value {
        Value::Object(obj) => obj,
        Value::String(s) => {
            if s.is_empty() {
                return (0.0, 0.0);
            }
            match serde_json::from_str::<Value>(s) {
                Ok(Value::Object(obj)) => {
                    // Borrowed value cannot outlive this branch; handle below.
                    let lon = number(obj.get("lon"));
                    let lat = number(obj.get("lat"));
                    return match (lon, lat) {
                        (Some(lon), Some(lat)) => (lon, lat),
                        _ => (0.0, 0.0),
                    };
                }
                _ => return (0.0, 0.0),
            }
        }
        _ => return (0.0, 0.0),
    };

    match (number(object.get("lon")), number(object.get("lat"))) {
        (Some(lon), Some(lat)) => (lon, lat),
        _ => (0.0, 0.0),
    }
}

/// Format milliseconds since the epoch as `types.DefaultDateLayout`.
pub fn format_date_millis(ms: i64) -> String {
    let days = ms.div_euclid(86_400_000);
    let rem = ms.rem_euclid(86_400_000);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}Z",
        y,
        m,
        d,
        rem / 3_600_000,
        (rem % 3_600_000) / 60_000,
        (rem % 60_000) / 1_000,
        rem % 1_000
    )
}

/// `types.NowDateTime()`.
pub fn now_date_time() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format_date_millis(now.as_millis() as i64)
}

/// Go's `time.Time.String()` in UTC (`2024-01-02 03:04:05.123 +0000 UTC`).
pub fn go_time_string(ms: i64) -> String {
    let days = ms.div_euclid(86_400_000);
    let rem = ms.rem_euclid(86_400_000);
    let (y, m, d) = civil_from_days(days);
    let mut out = format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        y,
        m,
        d,
        rem / 3_600_000,
        (rem % 3_600_000) / 60_000,
        (rem % 60_000) / 1_000
    );
    let millis = rem % 1_000;
    if millis != 0 {
        let mut frac = format!("{millis:03}");
        while frac.ends_with('0') {
            frac.pop();
        }
        out.push('.');
        out.push_str(&frac);
    }
    out.push_str(" +0000 UTC");
    out
}

/// Go's `json.Marshal(time.Time)`: RFC3339 with trailing fractional zeros
/// removed.
pub fn go_time_rfc3339(ms: i64) -> String {
    let days = ms.div_euclid(86_400_000);
    let rem = ms.rem_euclid(86_400_000);
    let (y, m, d) = civil_from_days(days);
    let mut out = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        y,
        m,
        d,
        rem / 3_600_000,
        (rem % 3_600_000) / 60_000,
        (rem % 60_000) / 1_000
    );
    let millis = rem % 1_000;
    if millis != 0 {
        let mut frac = format!("{millis:03}");
        while frac.ends_with('0') {
            frac.pop();
        }
        out.push('.');
        out.push_str(&frac);
    }
    out.push('Z');
    out
}

/// `Field.IsMultiple` for the multi-valued field types.
pub fn is_multiple(field: &Value) -> bool {
    matches!(field_type(field), "select" | "file" | "relation") && field_i64(field, "maxSelect") > 1
}

/// `Field.ColumnType(app)`.
pub fn column_type(field: &Value) -> &'static str {
    match field_type(field) {
        "text" if field_bool(field, "primaryKey") => {
            "TEXT PRIMARY KEY DEFAULT ('r'||lower(hex(randomblob(7)))) NOT NULL"
        }
        "text" | "email" | "url" | "date" | "autodate" | "editor" | "password" => {
            "TEXT DEFAULT '' NOT NULL"
        }
        "number" => "NUMERIC DEFAULT 0 NOT NULL",
        "bool" => "BOOLEAN DEFAULT FALSE NOT NULL",
        "select" | "file" | "relation" if is_multiple(field) => "JSON DEFAULT '[]' NOT NULL",
        "select" | "file" | "relation" => "TEXT DEFAULT '' NOT NULL",
        "json" => "JSON DEFAULT NULL",
        "geoPoint" => r#"JSON DEFAULT '{"lon":0,"lat":0}' NOT NULL"#,
        _ => "TEXT DEFAULT '' NOT NULL",
    }
}

// ---------------------------------------------------------------------------
// Field settings validation (`Field.ValidateSettings`)
// ---------------------------------------------------------------------------

/// `fieldNameRegex` / `DefaultIdRegex`: Go's `^\w+$`.
fn is_word(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// `DefaultFieldIdValidationRule`.
fn validate_id(field: &Value) -> Option<Node> {
    let id = field_id(field);
    if id.is_empty() {
        return Some(required());
    }
    length(id, 1, 100)
}

/// `DefaultFieldNameValidationRule`.
fn validate_name(field: &Value) -> Option<Node> {
    let name = field_name(field);
    if name.is_empty() {
        return Some(required());
    }
    if let Some(err) = length(name, 1, 100) {
        return Some(err);
    }
    if !is_word(name) {
        return Some(leaf("validation_match_invalid", "must be in a valid format"));
    }
    if EXCLUDED_NAMES.contains(&name) {
        return Some(leaf("validation_not_in_invalid", "must not be in list"));
    }
    if name.to_lowercase().contains("_via_") {
        return Some(leaf(
            "validation_found_via",
            "The value cannot contain \"_via_\".",
        ));
    }
    None
}

/// `DefaultFieldHelpValidationRule`.
fn validate_help(field: &Value) -> Option<Node> {
    length(field_str(field, "help"), 1, 300)
}

/// `validators.IsRegex`.
fn validate_regex(value: &str) -> Option<Node> {
    if value.is_empty() {
        return None;
    }
    match regex::Regex::new(value) {
        Ok(_) => None,
        Err(err) => Some(leaf("validation_invalid_regex", err.to_string())),
    }
}

/// `Field.ValidateSettings(ctx, app, collection)`.
///
/// `collections` is the list of collections the field can reference (for
/// relation fields) and `current_id` is the collection being validated.
pub fn validate_settings(
    field: &Value,
    collection: &crate::collections::Collection,
    collections: &[crate::collections::Collection],
) -> Errors {
    let mut errs = Errors::new();
    push(&mut errs, "id", validate_id(field));
    push(&mut errs, "name", validate_name(field));

    match field_type(field) {
        "autodate" => {
            // no `help`, and either onCreate or onUpdate must be enabled
            if !field_bool(field, "onCreate") && !field_bool(field, "onUpdate") {
                let err = leaf("validation_required", "either onCreate or onUpdate must be enabled");
                push(&mut errs, "onCreate", Some(err.clone()));
                push(&mut errs, "onUpdate", Some(err));
            }
        }
        _ => push(&mut errs, "help", validate_help(field)),
    }

    match field_type(field) {
        "text" => {
            let primary_key = field_bool(field, "primaryKey");
            // `validation.Field(&f.Name, DefaultFieldNameValidationRule,
            //   validation.When(f.PrimaryKey, validation.In("id")))` — ozzo
            // returns the first failing rule, so only check the PK name when
            // the base name rule passed.
            if primary_key && !errs.contains_key("name") && field_name(field) != FIELD_NAME_ID {
                push(
                    &mut errs,
                    "name",
                    Some(leaf(
                        "validation_in_invalid",
                        "The primary key must be named \"id\".",
                    )),
                );
            }
            if primary_key {
                let total = collection
                    .field_list()
                    .items()
                    .iter()
                    .filter(|f| field_type(f) == "text" && field_bool(f, "primaryKey"))
                    .count();
                if total > 1 {
                    push(
                        &mut errs,
                        "primaryKey",
                        Some(leaf(
                            "validation_unsupported_composite_pk",
                            "Composite PKs are not supported and the collection must have only 1 PK.",
                        )),
                    );
                }
            }
            let min = field_i64(field, "min");
            let max = field_i64(field, "max");
            push(
                &mut errs,
                "min",
                crate::validation::min(min, 0)
                    .or_else(|| crate::validation::max(min, MAX_SAFE_JSON_INT)),
            );
            push(
                &mut errs,
                "max",
                crate::validation::min(max, min)
                    .or_else(|| crate::validation::max(max, MAX_SAFE_JSON_INT)),
            );
            // `validation.When(f.PrimaryKey, validation.Required)` then `IsRegex`.
            if !(primary_key && field_str(field, "pattern").is_empty()) {
                push(&mut errs, "pattern", validate_regex(field_str(field, "pattern")));
            } else {
                push(&mut errs, "pattern", Some(required()));
            }
            if primary_key && field_bool(field, "hidden") {
                push(&mut errs, "hidden", Some(crate::validation::empty()));
            }
            if primary_key && !field_bool(field, "required") {
                push(&mut errs, "required", Some(required()));
            }
            push(
                &mut errs,
                "autogeneratePattern",
                validate_regex(field_str(field, "autogeneratePattern")),
            );
        }
        "number" => {
            let only_int = field_bool(field, "onlyInt");
            let min = field.get("min").and_then(Value::as_f64);
            let max = field.get("max").and_then(Value::as_f64);
            let decimal = || {
                leaf(
                    "validation_only_int_constraint",
                    "Decimal numbers are not allowed",
                )
            };
            if only_int {
                if let Some(min) = min {
                    if min != (min as i64) as f64 {
                        push(&mut errs, "min", Some(decimal()));
                    }
                }
            }
            if only_int {
                if let Some(max) = max {
                    if max != (max as i64) as f64 {
                        push(&mut errs, "max", Some(decimal()));
                    }
                }
            }
            if let (Some(min), Some(max)) = (min, max) {
                if max < min {
                    push(
                        &mut errs,
                        "max",
                        Some(leaf_with_params(
                            "validation_min_number_constraint",
                            "must be greater or equal than {{.min}}",
                            serde_json::json!({ "min": number_value(min) }),
                        )),
                    );
                }
            }
        }
        "email" | "url" => {
            let except = field.get("exceptDomains").and_then(Value::as_array);
            let only = field.get("onlyDomains").and_then(Value::as_array);
            let except_empty = except.map(|v| v.is_empty()).unwrap_or(true);
            let only_empty = only.map(|v| v.is_empty()).unwrap_or(true);
            push(
                &mut errs,
                "exceptDomains",
                if only_empty {
                    validate_domains(except)
                } else if except_empty {
                    None
                } else {
                    Some(crate::validation::empty())
                },
            );
            push(
                &mut errs,
                "onlyDomains",
                if except_empty {
                    validate_domains(only)
                } else if only_empty {
                    None
                } else {
                    Some(crate::validation::empty())
                },
            );
        }
        "date" => {
            // `validation.Field(&f.Max, validation.By(checkRange(f.Min, f.Max)))`
            let min = date_instant(field_str(field, "min"));
            let max = date_instant(field_str(field, "max"));
            if let (Some(min), Some(max)) = (min, max) {
                if max < min {
                    push(
                        &mut errs,
                        "max",
                        Some(leaf("validation_date_out_of_range", "the date is out of range")),
                    );
                }
            }
        }
        "select" => {
            let values = field.get("values").and_then(Value::as_array);
            if values.map(|v| v.is_empty()).unwrap_or(true) {
                push(&mut errs, "values", Some(required()));
            }
            let max = values.map(|v| v.len()).unwrap_or(0).max(1) as i64;
            push(
                &mut errs,
                "maxSelect",
                crate::validation::min(field_i64(field, "maxSelect"), 0)
                    .or_else(|| crate::validation::max(field_i64(field, "maxSelect"), max)),
            );
        }
        "file" => {
            push(
                &mut errs,
                "maxSelect",
                crate::validation::min(field_i64(field, "maxSelect"), 0)
                    .or_else(|| crate::validation::max(field_i64(field, "maxSelect"), MAX_SAFE_JSON_INT)),
            );
            push(
                &mut errs,
                "maxSize",
                crate::validation::min(field_i64(field, "maxSize"), 0)
                    .or_else(|| crate::validation::max(field_i64(field, "maxSize"), MAX_SAFE_JSON_INT)),
            );
            push(&mut errs, "thumbs", validate_thumbs(field));
        }
        "relation" => {
            let collection_id = field_str(field, "collectionId");
            if collection_id.is_empty() {
                push(&mut errs, "collectionId", Some(required()));
            } else {
                match collections.iter().find(|c| c.id == collection_id) {
                    None => push(
                        &mut errs,
                        "collectionId",
                        Some(leaf(
                            "validation_field_relation_missing_collection",
                            "The relation collection doesn't exist.",
                        )),
                    ),
                    Some(rel) if !collection.is_view() && rel.is_view() => push(
                        &mut errs,
                        "collectionId",
                        Some(leaf(
                            "validation_relation_field_non_view_base_collection",
                            "Only view collections are allowed to have relations to other views.",
                        )),
                    ),
                    Some(_) => {}
                }
            }
            let min_select = field_i64(field, "minSelect");
            let max_select = field_i64(field, "maxSelect");
            push(&mut errs, "minSelect", crate::validation::min(min_select, 0));
            if min_select > 0 && max_select == 0 {
                push(&mut errs, "maxSelect", Some(required()));
            } else {
                push(&mut errs, "maxSelect", crate::validation::min(max_select, min_select));
            }
        }
        "json" | "editor" => {
            push(
                &mut errs,
                "maxSize",
                crate::validation::min(field_i64(field, "maxSize"), 0)
                    .or_else(|| crate::validation::max(field_i64(field, "maxSize"), MAX_SAFE_JSON_INT)),
            );
        }
        "password" => {
            let min = field_i64(field, "min");
            let max = field_i64(field, "max");
            push(
                &mut errs,
                "min",
                crate::validation::min(min, 1).or_else(|| crate::validation::max(min, 71)),
            );
            push(
                &mut errs,
                "max",
                crate::validation::min(max, min).or_else(|| crate::validation::max(max, 71)),
            );
            push(
                &mut errs,
                "cost",
                crate::validation::min(field_i64(field, "cost"), 4)
                    .or_else(|| crate::validation::max(field_i64(field, "cost"), 31)),
            );
            push(&mut errs, "pattern", validate_regex(field_str(field, "pattern")));
        }
        _ => {}
    }

    errs
}

/// `fmt`'s shortest float rendering: integral values become integers.
fn number_value(value: f64) -> Value {
    if value.fract() == 0.0 && value.abs() < 9.007_199_254_740_992e15 {
        Value::from(value as i64)
    } else {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .unwrap_or(Value::Null)
    }
}

/// `filesystem.ThumbSizeRegex`
fn is_thumb_size(value: &str) -> bool {
    let Some(rest) = value.strip_suffix(['t', 'b', 'f']) else {
        return is_plain_thumb(value);
    };
    is_plain_thumb(rest)
}

fn is_plain_thumb(value: &str) -> bool {
    let Some((w, h)) = value.split_once('x') else {
        return false;
    };
    !w.is_empty()
        && !h.is_empty()
        && w.chars().all(|c| c.is_ascii_digit())
        && h.chars().all(|c| c.is_ascii_digit())
}

/// `validation.Each(validation.NotIn(...), validation.Match(ThumbSizeRegex))`.
fn validate_thumbs(field: &Value) -> Option<Node> {
    let values = field.get("thumbs").and_then(Value::as_array)?;
    let mut errs = Errors::new();
    for (i, value) in values.iter().enumerate() {
        let thumb = value.as_str().unwrap_or("");
        let node = if ["0x0", "0x0t", "0x0b", "0x0f"].contains(&thumb) {
            Some(leaf("validation_not_in_invalid", "must not be in list"))
        } else if !is_thumb_size(thumb) {
            Some(leaf("validation_match_invalid", "must be in a valid format"))
        } else {
            None
        };
        push(&mut errs, &i.to_string(), node);
    }
    branch(errs)
}

/// `is.Domain` (`ozzo-validation/is`): at least one dot, ASCII labels and a
/// letters-only TLD, with a 255 byte cap.
fn is_domain(value: &str) -> bool {
    use std::sync::OnceLock;
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        regex::Regex::new(
            r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-zA-Z]{1,63}| xn--[a-z0-9]{1,59})$",
        )
        .expect("domain regex")
    });
    value.len() <= 255 && re.is_match(value)
}

/// `validation.Each(is.Domain)`.
fn validate_domains(values: Option<&Vec<Value>>) -> Option<Node> {
    let Some(values) = values else {
        return None;
    };
    let mut errs = Errors::new();
    for (i, value) in values.iter().enumerate() {
        let domain = value.as_str().unwrap_or("");
        push(
            &mut errs,
            &i.to_string(),
            if is_domain(domain) {
                None
            } else {
                Some(leaf("validation_is_domain", "must be a valid domain"))
            },
        );
    }
    branch(errs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn bare_fields_get_the_oracle_defaults() {
        let field = from_request(&json!({"name": "t", "type": "text"})).unwrap();
        assert_eq!(
            serde_json::to_string(&field).unwrap(),
            r#"{"autogeneratePattern":"","help":"","hidden":false,"id":"","max":0,"min":0,"name":"t","pattern":"","presentable":false,"primaryKey":false,"required":false,"system":false,"type":"text"}"#
        );

        let field = from_request(&json!({"name": "n", "type": "number"})).unwrap();
        assert_eq!(field["min"], Value::Null);
        assert_eq!(field["max"], Value::Null);

        let field = from_request(&json!({"name": "a", "type": "autodate"})).unwrap();
        assert!(field.get("help").is_none());
        assert!(field.get("required").is_none());
    }

    #[test]
    fn unknown_keys_are_ignored_and_nulls_are_zeroed() {
        let field = from_request(&json!({
            "name": "t", "type": "text", "nope": 1, "help": null, "min": 3
        }))
        .unwrap();
        assert!(field.get("nope").is_none());
        assert_eq!(field["help"], "");
        assert_eq!(field["min"], 3);
    }

    #[test]
    fn type_mismatches_fail_to_bind() {
        assert_eq!(from_request(&json!({"name": 1, "type": "text"})), Err(BindError));
        assert_eq!(from_request(&json!({"name": "x", "type": "text", "min": "3"})), Err(BindError));
        assert_eq!(from_request(&json!({"name": "x", "type": "nope"})), Err(BindError));
        assert_eq!(from_request(&json!({"name": "x"})), Err(BindError));
        // 1.5 is not an int in Go either
        assert_eq!(from_request(&json!({"name": "x", "type": "text", "min": 1.5})), Err(BindError));
    }

    #[test]
    fn ids_are_type_plus_crc32_of_the_name() {
        let mut list = FieldsList::new();
        list.add(from_request(&json!({"name": "title", "type": "text"})).unwrap());
        assert_eq!(field_id(&list.items()[0]), "text724990059");
    }

    #[test]
    fn colliding_ids_get_a_numeric_suffix() {
        // Two different names that hash to the same id: emulate by pre-seeding.
        let mut list = FieldsList::new();
        let first = from_request(&json!({"name": "a", "type": "text"})).unwrap();
        let id = field_id(&first).to_string();
        let mut seeded = first.clone();
        set_field_id(&mut seeded, &id);
        list.add(seeded);
        // A field that resolves to the same id must not replace it.
        let mut duplicate = from_request(&json!({"name": "b", "type": "text"})).unwrap();
        set_field_id(&mut duplicate, "");
        // Same name would replace, so force the same base id by renaming after add.
        let mut same = from_request(&json!({"name": "a", "type": "text"})).unwrap();
        set_field_id(&mut same, "");
        list.add(same);
        assert_eq!(list.len(), 1, "same name replaces in place");
    }

    #[test]
    fn same_name_replaces_in_place_and_keeps_the_original_id() {
        let mut list = FieldsList::new();
        list.add(from_request(&json!({"name": "x", "type": "text", "help": "one"})).unwrap());
        let id = field_id(&list.items()[0]).to_string();
        list.add(from_request(&json!({"name": "x", "type": "text", "help": "two"})).unwrap());
        assert_eq!(list.len(), 1);
        assert_eq!(field_id(&list.items()[0]), id);
        assert_eq!(field_str(&list.items()[0], "help"), "two");
    }

    #[test]
    fn explicit_ids_replace_by_id() {
        let mut list = FieldsList::new();
        list.add(from_request(&json!({"id": "same", "name": "x", "type": "text"})).unwrap());
        list.add(from_request(&json!({"id": "same", "name": "y", "type": "text"})).unwrap());
        assert_eq!(list.len(), 1);
        assert_eq!(field_name(&list.items()[0]), "y");
    }

    #[test]
    fn column_types_match_the_oracle_ddl() {
        let text = from_request(&json!({"name": "t", "type": "text"})).unwrap();
        assert_eq!(column_type(&text), "TEXT DEFAULT '' NOT NULL");
        let id = from_request(&json!({"name": "id", "type": "text", "primaryKey": true})).unwrap();
        assert_eq!(
            column_type(&id),
            "TEXT PRIMARY KEY DEFAULT ('r'||lower(hex(randomblob(7)))) NOT NULL"
        );
        let multi = from_request(&json!({"name": "s", "type": "select", "values": ["a"], "maxSelect": 2})).unwrap();
        assert_eq!(column_type(&multi), "JSON DEFAULT '[]' NOT NULL");
        let single = from_request(&json!({"name": "s", "type": "select", "values": ["a"]})).unwrap();
        assert_eq!(column_type(&single), "TEXT DEFAULT '' NOT NULL");
        let number = from_request(&json!({"name": "n", "type": "number"})).unwrap();
        assert_eq!(column_type(&number), "NUMERIC DEFAULT 0 NOT NULL");
        let geo = from_request(&json!({"name": "g", "type": "geoPoint"})).unwrap();
        assert_eq!(column_type(&geo), r#"JSON DEFAULT '{"lon":0,"lat":0}' NOT NULL"#);
        let json_field = from_request(&json!({"name": "j", "type": "json"})).unwrap();
        assert_eq!(column_type(&json_field), "JSON DEFAULT NULL");
    }

    fn stub(kind: &str) -> crate::collections::Collection {
        crate::collections::Collection {
            id: "pbc_stub".into(),
            system: false,
            kind: kind.into(),
            name: "stub".into(),
            fields: json!([]),
            indexes: json!([]),
            list_rule: None,
            view_rule: None,
            create_rule: None,
            update_rule: None,
            delete_rule: None,
            options: json!({}),
            created: String::new(),
            updated: String::new(),
        }
    }

    #[test]
    fn settings_validation_matches_the_oracle_messages() {
        let base = stub("base");
        let field = from_request(&json!({"name": "bad-name", "type": "text"})).unwrap();
        let errs = validate_settings(&field, &base, &[]);
        assert_eq!(
            errs["name"],
            leaf("validation_match_invalid", "must be in a valid format")
        );

        let field = from_request(&json!({"name": "null", "type": "text"})).unwrap();
        assert_eq!(
            validate_settings(&field, &base, &[])["name"],
            leaf("validation_not_in_invalid", "must not be in list")
        );

        let field = from_request(&json!({"name": "a_via_b", "type": "text"})).unwrap();
        assert_eq!(
            validate_settings(&field, &base, &[])["name"],
            leaf("validation_found_via", "The value cannot contain \"_via_\".")
        );

        let field = from_request(&json!({"name": "x", "type": "select"})).unwrap();
        assert_eq!(validate_settings(&field, &base, &[])["values"], required());

        let field = from_request(&json!({"name": "x", "type": "relation"})).unwrap();
        assert_eq!(validate_settings(&field, &base, &[])["collectionId"], required());

        let field = from_request(&json!({"name": "x", "type": "autodate"})).unwrap();
        let errs = validate_settings(&field, &base, &[]);
        assert_eq!(errs["onCreate"], errs["onUpdate"]);

        // A relation to a view is rejected for non-view collections.
        let mut view = stub("view");
        view.id = "pbc_view".into();
        view.kind = "view".into();
        let field = from_request(
            &json!({"name": "x", "type": "relation", "collectionId": "pbc_view"}),
        )
        .unwrap();
        let errs = validate_settings(&field, &base, std::slice::from_ref(&view));
        assert_eq!(
            errs["collectionId"],
            leaf(
                "validation_relation_field_non_view_base_collection",
                "Only view collections are allowed to have relations to other views."
            )
        );

        // Dates round-trip through the default layout and compare as instants.
        let field = from_request(&json!({
            "name": "d", "type": "date",
            "min": "2024-01-02T03:04:05Z",
            "max": "2024-01-02 03:04:04.000Z"
        }))
        .unwrap();
        assert_eq!(field_str(&field, "min"), "2024-01-02 03:04:05.000Z");
        assert_eq!(
            validate_settings(&field, &base, &[])["max"],
            leaf("validation_date_out_of_range", "the date is out of range")
        );

        // File thumbnails are validated per entry.
        let field = from_request(
            &json!({"name": "f", "type": "file", "thumbs": ["100x100", "0x0", "bogus"]}),
        )
        .unwrap();
        let errs = validate_settings(&field, &base, &[]);
        assert_eq!(
            errs["thumbs"],
            Node::Branch(Errors::from([
                ("1".to_string(), leaf("validation_not_in_invalid", "must not be in list")),
                ("2".to_string(), leaf("validation_match_invalid", "must be in a valid format")),
            ]))
        );
    }
}
