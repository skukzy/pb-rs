//! Go-compatible JSON value handling.
//!
//! The oracle parses request bodies with `encoding/json/v2`, which stores every
//! JSON number as a `float64`, and re-marshals maps deterministically (sorted
//! keys). Numbers therefore go through a lossy `float64` round-trip and are
//! printed with Go's `strconv` rules:
//!
//! * `1.0` -> `1`
//! * `9007199254740993` -> `9007199254740992`
//! * `1e21` -> `1e+21`
//! * `1e-7` -> `1e-7`
//! * `0.000001` -> `0.000001`
//!
//! `serde_json` is compiled with `arbitrary_precision` so a [`Value::Number`]
//! keeps the exact text we build here instead of applying ryu's formatting.

use serde_json::{Map, Value};

/// `strconv.FormatFloat(f, fmt, -1, 64)` with Go's JSON `fmt` selection.
pub fn format_float(f: f64) -> String {
    if f.is_nan() || f.is_infinite() {
        // JSON cannot represent these; the oracle rejects them during
        // validation, so this is only a defensive fallback.
        return "0".to_string();
    }
    if f == 0.0 {
        return if f.is_sign_negative() { "-0" } else { "0" }.to_string();
    }

    let abs = f.abs();
    if abs < 1e-6 || abs >= 1e21 {
        let rendered = format!("{f:e}");
        let (mantissa, exponent) = rendered
            .split_once('e')
            .expect("LowerExp always contains an exponent");
        let exponent: i32 = exponent.parse().expect("numeric exponent");
        if exponent >= 0 {
            format!("{mantissa}e+{exponent}")
        } else {
            format!("{mantissa}e{exponent}")
        }
    } else {
        // Rust's Display never switches to exponent notation and prints the
        // shortest round-trippable decimal, matching `FormatFloat(f, 'f', -1)`.
        format!("{f}")
    }
}

/// Build a JSON number from an `f64` using Go's formatting.
pub fn number(f: f64) -> Value {
    let text = format_float(f);
    serde_json::from_str(&text).unwrap_or(Value::Null)
}

/// Recursively normalize a JSON value the way `encoding/json` would after a
/// `float64` round-trip: numbers are re-printed and object keys are sorted.
pub fn canonical(value: &Value) -> Value {
    match value {
        Value::Number(n) => match n.as_f64() {
            Some(f) => number(f),
            None => value.clone(),
        },
        Value::Array(items) => Value::Array(items.iter().map(canonical).collect()),
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = Map::new();
            for key in keys {
                out.insert(key.clone(), canonical(&map[key]));
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

/// `json.Marshal(value, json.Deterministic(true))`.
pub fn marshal(value: &Value) -> String {
    serde_json::to_string(&canonical(value)).unwrap_or_else(|_| "null".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floats_match_go() {
        assert_eq!(format_float(1.0), "1");
        assert_eq!(format_float(1000.0), "1000");
        assert_eq!(format_float(1.5), "1.5");
        assert_eq!(format_float(1e21), "1e+21");
        assert_eq!(format_float(1e-7), "1e-7");
        assert_eq!(format_float(1e-6), "0.000001");
        assert_eq!(format_float(9007199254740993.0), "9007199254740992");
    }

    #[test]
    fn canonical_sorts_and_normalizes() {
        let value: Value = serde_json::from_str(r#"{"b":1.0,"a":[2.50,"x"]}"#).unwrap();
        assert_eq!(marshal(&value), r#"{"a":[2.5,"x"],"b":1}"#);
    }
}
