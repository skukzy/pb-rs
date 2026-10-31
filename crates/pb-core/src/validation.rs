//! ozzo-validation compatible error trees.
//!
//! PocketBase validates models with `github.com/pocketbase/ozzo-validation/v4`
//! and serializes the resulting `validation.Errors` tree verbatim into the
//! response `data`. The tree is a map whose keys are struct field names or
//! slice indexes (`"0"`, `"1"`, ...); the leaves carry a stable `code`, a
//! human readable `message` and optional `params`.
//!
//! Everything here mirrors that shape, including the fact that Go serializes
//! maps with sorted keys — hence [`Errors`] being a `BTreeMap`.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::{json, Value};

/// A single validation error (`ozzo-validation.Error`).
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ValidationError {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

/// A validation error tree: keys are field names or slice indexes.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(untagged)]
pub enum Node {
    Leaf(ValidationError),
    Branch(Errors),
}

pub type Errors = BTreeMap<String, Node>;

/// `validation.NewError(code, message)`.
pub fn leaf(code: &str, message: impl Into<String>) -> Node {
    Node::Leaf(ValidationError {
        code: code.to_string(),
        message: message.into(),
        params: None,
    })
}

/// `validation.NewError(...).SetParams(...)`.
pub fn leaf_with_params(code: &str, message: impl Into<String>, params: Value) -> Node {
    Node::Leaf(ValidationError {
        code: code.to_string(),
        message: message.into(),
        params: Some(params),
    })
}

/// `validation.ErrRequired`.
pub fn required() -> Node {
    // ozzo's raw message; the API layer sentenizes it on output.
    leaf("validation_required", "cannot be blank")
}

/// `validation.ErrInInvalid`.
pub fn invalid_in() -> Node {
    // ozzo's raw message; the API layer sentenizes it on output.
    leaf("validation_in_invalid", "must be a valid value")
}

/// `validation.ErrEmpty` (`validation.Empty`).
pub fn empty() -> Node {
    leaf("validation_empty", "must be blank")
}

/// `validation.Length(min, max)`, which skips empty values.
///
/// The message/params pair follows `buildLengthRuleError`: an exact length, an
/// open range or a bounded range each get their own code.
pub fn length(value: &str, min: usize, max: usize) -> Option<Node> {
    if value.is_empty() {
        return None;
    }
    let len = value.len(); // Go's len(string) counts bytes
    if !(min > 0 && len < min || max > 0 && len > max || min == 0 && max == 0 && len > 0) {
        return None;
    }
    let (code, message) = match (min, max) {
        (0, m) if m > 0 => ("validation_length_too_long", "the length must be no more than {{.max}}".to_string()),
        (m, 0) if m > 0 => ("validation_length_too_short", "the length must be no less than {{.min}}".to_string()),
        (m, x) if m == x => ("validation_length_invalid", "the length must be exactly {{.min}}".to_string()),
        (0, 0) => ("validation_length_empty_required", "the value must be empty".to_string()),
        _ => (
            "validation_length_out_of_range",
            "the length must be between {{.min}} and {{.max}}".to_string(),
        ),
    };
    Some(leaf_with_params(
        code,
        message,
        json!({ "min": min, "max": max }),
    ))
}

/// `validation.Min(threshold)`, which skips zero values.
pub fn min(value: i64, threshold: i64) -> Option<Node> {
    if value == 0 {
        return None;
    }
    if value < threshold {
        return Some(leaf_with_params(
            "validation_min_greater_equal_than_required",
            "must be no less than {{.threshold}}",
            json!({ "threshold": threshold }),
        ));
    }
    None
}

/// `validation.Max(threshold)`, which skips zero values.
pub fn max(value: i64, threshold: i64) -> Option<Node> {
    if value == 0 {
        return None;
    }
    if value > threshold {
        return Some(leaf_with_params(
            "validation_max_less_equal_than_required",
            "must be no greater than {{.threshold}}",
            json!({ "threshold": threshold }),
        ));
    }
    None
}

/// Insert a node when the rule produced an error.
pub fn push(errs: &mut Errors, key: &str, node: Option<Node>) {
    if let Some(node) = node {
        errs.insert(key.to_string(), node);
    }
}

/// Wrap a non-empty error map into a [`Node`].
pub fn branch(errs: Errors) -> Option<Node> {
    if errs.is_empty() {
        None
    } else {
        Some(Node::Branch(errs))
    }
}

/// `validation.Errors.Error()`: sorted keys joined with `"; "`, branches
/// rendered as `key: (nested)` and leaves interpolated without sentenizing.
pub fn errors_display(errors: &Errors) -> String {
    let mut out = String::new();
    for (i, (key, node)) in errors.iter().enumerate() {
        if i > 0 {
            out.push_str("; ");
        }
        match node {
            Node::Branch(inner) => {
                out.push_str(key);
                out.push_str(": (");
                out.push_str(&errors_display(inner));
                out.push(')');
            }
            Node::Leaf(error) => {
                out.push_str(key);
                out.push_str(": ");
                out.push_str(&interpolate(&error.message, error.params.as_ref()));
            }
        }
    }
    out
}

/// Serialize an error tree.
///
/// Go serializes maps with sorted keys (`BTreeMap` gives the same) and each
/// leaf message is passed through `inflector.Sentenize` **after** the
/// `{{.param}}` placeholders are substituted (`tools/router/error.go`).
pub fn errors_to_value(errors: &Errors) -> Value {
    let mut out = serde_json::Map::new();
    for (key, node) in errors {
        out.insert(key.clone(), node_to_value(node));
    }
    Value::Object(out)
}

/// `validation.Errors.MarshalJSON`: branches become nested objects and leaves
/// their interpolated message **without** `inflector.Sentenize`.
///
/// This is what the activity logger records as `details` (`ApiError.RawData`),
/// unlike the public response body which uses [`errors_to_value`].
pub fn errors_to_log_value(errors: &Errors) -> Value {
    let mut out = serde_json::Map::new();
    for (key, node) in errors {
        let value = match node {
            Node::Branch(inner) => errors_to_log_value(inner),
            Node::Leaf(error) => {
                Value::String(interpolate(&error.message, error.params.as_ref()))
            }
        };
        out.insert(key.clone(), value);
    }
    Value::Object(out)
}

fn node_to_value(node: &Node) -> Value {
    match node {
        Node::Branch(errors) => errors_to_value(errors),
        Node::Leaf(error) => {
            let mut out = serde_json::Map::new();
            out.insert("code".into(), Value::String(error.code.clone()));
            out.insert(
                "message".into(),
                Value::String(sentenize(&interpolate(&error.message, error.params.as_ref()))),
            );
            if let Some(params) = &error.params {
                out.insert("params".into(), params.clone());
            }
            Value::Object(out)
        }
    }
}

/// Substitute `{{.name}}` placeholders with their parameter values.
fn interpolate(message: &str, params: Option<&Value>) -> String {
    let Some(params) = params.and_then(Value::as_object) else {
        return message.to_string();
    };
    let mut out = String::with_capacity(message.len());
    let mut rest = message;
    while let Some(start) = rest.find("{{.") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 3..];
        let Some(end) = after.find("}}") else {
            out.push_str(&rest[start..]);
            return out;
        };
        let key = &after[..end];
        match params.get(key) {
            Some(value) => out.push_str(&go_value(value)),
            None => {
                out.push_str("{{.");
                out.push_str(key);
                out.push_str("}}");
            }
        }
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    out
}

/// `fmt.Sprintf("%v", value)` for the types that appear in params.
fn go_value(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Null => "<nil>".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().map(go_value).collect();
            format!("[{}]", parts.join(" "))
        }
        Value::Object(_) => "map[]".to_string(),
    }
}

/// `inflector.Sentenize`: trim, uppercase the first character, add a period.
pub fn sentenize(message: &str) -> String {
    let message = message.trim();
    if message.is_empty() {
        return String::new();
    }
    let mut chars = message.chars();
    let first = chars.next().expect("non-empty");
    let mut out: String = first.to_uppercase().collect();
    out.push_str(chars.as_str());
    let last = out.chars().last().expect("non-empty");
    if last != '.' && last != '?' && last != '!' {
        out.push('.');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_reports_the_oracle_codes() {
        assert_eq!(length("", 1, 255), None);
        assert_eq!(
            length("a", 7, 7),
            Some(leaf_with_params(
                "validation_length_invalid",
                "the length must be exactly {{.min}}",
                json!({"min": 7, "max": 7})
            ))
        );
        assert_eq!(
            length(&"a".repeat(256), 1, 255),
            Some(leaf_with_params(
                "validation_length_out_of_range",
                "the length must be between {{.min}} and {{.max}}",
                json!({"min": 1, "max": 255})
            ))
        );
        assert_eq!(
            length("abcdef", 0, 5),
            Some(leaf_with_params(
                "validation_length_too_long",
                "the length must be no more than {{.max}}",
                json!({"min": 0, "max": 5})
            ))
        );
        assert_eq!(
            length("a", 2, 0),
            Some(leaf_with_params(
                "validation_length_too_short",
                "the length must be no less than {{.min}}",
                json!({"min": 2, "max": 0})
            ))
        );
    }

    #[test]
    fn min_and_max_skip_zero() {
        assert_eq!(min(0, 1), None);
        assert_eq!(
            min(-1, 1),
            Some(leaf_with_params(
                "validation_min_greater_equal_than_required",
                "must be no less than {{.threshold}}",
                json!({"threshold": 1})
            ))
        );
        assert_eq!(max(0, 10), None);
        assert_eq!(
            max(11, 10),
            Some(leaf_with_params(
                "validation_max_less_equal_than_required",
                "must be no greater than {{.threshold}}",
                json!({"threshold": 10})
            ))
        );
    }

    #[test]
    fn trees_serialize_with_sorted_keys() {
        let mut errs = Errors::new();
        errs.insert("b".into(), required());
        errs.insert("a".into(), invalid_in());
        let value = errors_to_value(&errs);
        let keys: Vec<&String> = value.as_object().unwrap().keys().collect();
        assert_eq!(keys, vec!["a", "b"]);
        assert_eq!(value["a"]["code"], "validation_in_invalid");
    }

    #[test]
    fn messages_are_interpolated_then_sentenized() {
        assert_eq!(sentenize("the date is out of range"), "The date is out of range.");
        assert_eq!(sentenize("Must not be in list."), "Must not be in list.");
        assert_eq!(sentenize(""), "");

        let node = leaf_with_params(
            "validation_duplicated_field_name",
            "Duplicated or invalid field name {{.fieldName}}",
            json!({ "fieldName": "X" }),
        );
        let mut errs = Errors::new();
        errs.insert("2".into(), node);
        let value = errors_to_value(&errs);
        assert_eq!(
            value["2"]["message"],
            "Duplicated or invalid field name X."
        );
        assert_eq!(value["2"]["params"]["fieldName"], "X");

        assert_eq!(
            errors_to_value(&{
                let mut errs = Errors::new();
                errs.insert("min".into(), length("x", 30, 30).unwrap());
                errs
            })["min"]["message"],
            "The length must be exactly 30."
        );
    }
}
