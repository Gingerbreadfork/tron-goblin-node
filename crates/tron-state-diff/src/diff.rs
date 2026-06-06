//! Normalized JSON diff for comparing two nodes' RPC responses.
//!
//! The subtlety this handles: TRON renders protobuf messages to JSON with
//! default-valued fields **omitted** (a `0`, `false`, `""`, `[]`, `{}` field
//! simply isn't present). Two faithful nodes can legitimately differ in
//! *which* defaults they omit — e.g. one emits `"net_usage": 0` and the
//! other drops it entirely. A naive `Value == Value` would flag that as a
//! divergence. So when a key is present on one side and absent on the other,
//! we treat the absent side as that field's type default and only report a
//! mismatch if the present value is actually non-default.

use serde_json::{Map, Value};

/// A single leaf-level field that differs between the two responses.
#[derive(Debug, Clone, PartialEq)]
pub struct Mismatch {
    /// Dotted path to the field, e.g. `account_resource.energy_usage`.
    pub path: String,
    /// Rendered value on side A (`"<absent>"` if the key is missing).
    pub a: String,
    /// Rendered value on side B.
    pub b: String,
}

/// Collect every leaf field where `a` and `b` differ, after default-omission
/// normalization. Empty result ⇒ the two responses are equivalent.
pub fn diff(a: &Value, b: &Value) -> Vec<Mismatch> {
    let mut out = Vec::new();
    walk("", a, b, &mut out);
    out
}

fn walk(path: &str, a: &Value, b: &Value, out: &mut Vec<Mismatch>) {
    match (a, b) {
        (Value::Object(ma), Value::Object(mb)) => walk_objects(path, ma, mb, out),
        (Value::Array(aa), Value::Array(ba)) => {
            // TRON renders protobuf `map<…>` fields as JSON arrays of
            // `{"key":…, "value":…}` in nondeterministic (HashMap) order, so
            // a positional compare would flag pure reordering as a divergence.
            // When both sides are such kv-arrays, compare them as unordered
            // maps keyed by `key` (with the same default-omission rules as
            // objects). Real arrays (frozenV2, votes — no `key` field) keep
            // the order-sensitive positional compare below.
            if let (Some(ma), Some(mb)) = (as_kv_map(aa), as_kv_map(ba)) {
                walk_objects(path, &ma, &mb, out);
                return;
            }
            if aa.len() != ba.len() {
                out.push(Mismatch {
                    path: path.to_string(),
                    a: format!("[{} item(s)]", aa.len()),
                    b: format!("[{} item(s)]", ba.len()),
                });
                return;
            }
            for (i, (x, y)) in aa.iter().zip(ba.iter()).enumerate() {
                walk(&format!("{path}[{i}]"), x, y, out);
            }
        }
        _ => {
            if !scalar_eq(a, b) {
                out.push(Mismatch {
                    path: path.to_string(),
                    a: render(a),
                    b: render(b),
                });
            }
        }
    }
}

fn walk_objects(path: &str, ma: &Map<String, Value>, mb: &Map<String, Value>, out: &mut Vec<Mismatch>) {
    // Union of keys, sorted for stable, deterministic output.
    let mut keys: Vec<&str> = ma.keys().map(|s| s.as_str()).collect();
    for k in mb.keys() {
        if !ma.contains_key(k) {
            keys.push(k);
        }
    }
    keys.sort_unstable();

    for k in keys {
        let child = if path.is_empty() {
            k.to_string()
        } else {
            format!("{path}.{k}")
        };
        match (ma.get(k), mb.get(k)) {
            (Some(va), Some(vb)) => walk(&child, va, vb, out),
            // Present on one side only: compare against the default of the
            // present value's type. Equal ⇒ both sides agree (one just
            // omitted the default); unequal ⇒ a real, non-default value.
            (Some(va), None) => {
                if !is_default(va) {
                    let d = default_like(va);
                    walk(&child, va, &d, out);
                }
            }
            (None, Some(vb)) => {
                if !is_default(vb) {
                    let d = default_like(vb);
                    walk(&child, &d, vb, out);
                }
            }
            (None, None) => {}
        }
    }
}

/// Recognize a TRON-style proto-map rendering: a non-empty array where every
/// element is an object carrying a string `key`. Returns the `key → value`
/// map (value defaults to null if absent) so two such arrays can be compared
/// order-insensitively. `None` if the array isn't a kv-map (so the caller
/// falls back to an order-sensitive positional compare).
fn as_kv_map(arr: &[Value]) -> Option<Map<String, Value>> {
    if arr.is_empty() {
        return None;
    }
    let mut m = Map::new();
    for el in arr {
        let obj = el.as_object()?;
        let key = obj.get("key")?.as_str()?;
        let val = obj.get("value").cloned().unwrap_or(Value::Null);
        m.insert(key.to_string(), val);
    }
    Some(m)
}

/// Scalar equality. Numbers compare by value (so `5` and `5.0` are equal);
/// everything else by structural equality.
fn scalar_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => match (x.as_f64(), y.as_f64()) {
            (Some(fx), Some(fy)) => fx == fy,
            _ => x == y,
        },
        _ => a == b,
    }
}

/// True if `v` is the default for its JSON type (what TRON omits).
fn is_default(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::Bool(b) => !b,
        Value::Number(n) => n.as_f64() == Some(0.0),
        Value::String(s) => s.is_empty(),
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.is_empty(),
    }
}

/// The default value of the same JSON type as `v`.
fn default_like(v: &Value) -> Value {
    match v {
        Value::Null => Value::Null,
        Value::Bool(_) => Value::Bool(false),
        Value::Number(_) => Value::Number(0u64.into()),
        Value::String(_) => Value::String(String::new()),
        Value::Array(_) => Value::Array(Vec::new()),
        Value::Object(_) => Value::Object(Map::new()),
    }
}

fn render(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn missing_key_equals_zero_default() {
        // A omits net_usage; B has it as 0 ⇒ equivalent.
        let a = json!({ "balance": 100 });
        let b = json!({ "balance": 100, "net_usage": 0 });
        assert!(diff(&a, &b).is_empty());
    }

    #[test]
    fn missing_key_with_nonzero_value_is_a_mismatch() {
        // A omits net_usage; B has 42 ⇒ real divergence.
        let a = json!({ "balance": 100 });
        let b = json!({ "balance": 100, "net_usage": 42 });
        let d = diff(&a, &b);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].path, "net_usage");
        assert_eq!(d[0].a, "0");
        assert_eq!(d[0].b, "42");
    }

    #[test]
    fn nested_account_resource_usage_mismatch() {
        let a = json!({ "account_resource": { "energy_usage": 1000, "energy_window_size": 28800 } });
        let b = json!({ "account_resource": { "energy_usage": 999, "energy_window_size": 28800 } });
        let d = diff(&a, &b);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].path, "account_resource.energy_usage");
    }

    #[test]
    fn key_order_does_not_matter() {
        let a = json!({ "x": 1, "y": 2 });
        let b = json!({ "y": 2, "x": 1 });
        assert!(diff(&a, &b).is_empty());
    }

    #[test]
    fn array_length_and_element_diffs() {
        let a = json!({ "frozenV2": [{ "type": "BANDWIDTH", "amount": 10 }] });
        let b = json!({ "frozenV2": [{ "type": "BANDWIDTH", "amount": 10 }, { "type": "ENERGY", "amount": 5 }] });
        let d = diff(&a, &b);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].path, "frozenV2");

        let a = json!({ "frozenV2": [{ "amount": 10 }] });
        let b = json!({ "frozenV2": [{ "amount": 11 }] });
        let d = diff(&a, &b);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].path, "frozenV2[0].amount");
    }

    #[test]
    fn empty_vs_empty_account_is_a_match() {
        // Both nodes report the address as absent (empty object).
        assert!(diff(&json!({}), &json!({})).is_empty());
    }

    #[test]
    fn number_value_equality_ignores_float_repr() {
        assert!(diff(&json!({ "a": 5 }), &json!({ "a": 5.0 })).is_empty());
    }

    #[test]
    fn kv_map_arrays_compare_order_insensitively() {
        // TRON renders proto maps as [{key,value}] in nondeterministic order.
        // Same set, different order ⇒ match.
        let a = json!({ "assetV2": [{"key":"1000001","value":100},{"key":"1000002","value":200}] });
        let b = json!({ "assetV2": [{"key":"1000002","value":200},{"key":"1000001","value":100}] });
        assert!(diff(&a, &b).is_empty(), "reordered kv-map must match: {:?}", diff(&a, &b));

        // Differing value ⇒ mismatch reported at the key path.
        let a = json!({ "assetV2": [{"key":"1000001","value":100}] });
        let b = json!({ "assetV2": [{"key":"1000001","value":101}] });
        let d = diff(&a, &b);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].path, "assetV2.1000001");

        // Same keys, one side omits a zero-valued entry ⇒ match (default-omission).
        let a = json!({ "m": [{"key":"a","value":5},{"key":"b","value":0}] });
        let b = json!({ "m": [{"key":"a","value":5}] });
        assert!(diff(&a, &b).is_empty(), "omitted zero entry must match: {:?}", diff(&a, &b));

        // Real ordered arrays (no `key` field) stay order-sensitive.
        let a = json!({ "frozenV2": [{"type":"ENERGY","amount":5}] });
        let b = json!({ "frozenV2": [{"amount":5}] });
        assert!(!diff(&a, &b).is_empty());
    }
}
