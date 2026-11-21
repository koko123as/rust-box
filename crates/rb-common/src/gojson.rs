//! JSON output formatted like Go's `encoding/json` (the `contextjson` fork
//! sing-box uses): objects keep their field order, strings are escaped
//! with HTML escaping on (`<`, `>`, `&` become `\u003c`, `\u003e`,
//! `\u0026`, and U+2028/U+2029 are escaped), and indentation follows
//! `Encoder.SetIndent("", "  ")`.

/// A JSON value with ordered object fields.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    /// A number, already formatted.
    Number(String),
    String(String),
    Array(Vec<Value>),
    Object(Vec<(String, Value)>),
}

impl Value {
    pub fn uint(value: u64) -> Value {
        Value::Number(value.to_string())
    }

    pub fn string(value: impl Into<String>) -> Value {
        Value::String(value.into())
    }

    /// A `badoption.Listable`: one item is written bare, otherwise an array.
    pub fn listable(mut items: Vec<Value>) -> Value {
        if items.len() == 1 {
            items.pop().unwrap()
        } else {
            Value::Array(items)
        }
    }

    pub fn string_listable(items: &[String]) -> Value {
        Value::listable(items.iter().cloned().map(Value::String).collect())
    }
}

/// Go `appendString` with `escapeHTML` on.
pub fn escape_string(output: &mut String, text: &str) {
    output.push('"');
    escape_inner(output, text);
    output.push('"');
}

fn escape_inner(output: &mut String, text: &str) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for character in text.chars() {
        match character {
            '\\' => output.push_str("\\\\"),
            '"' => output.push_str("\\\""),
            '\u{8}' => output.push_str("\\b"),
            '\u{c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            '<' | '>' | '&' | '\u{0}'..='\u{1f}' => {
                let byte = character as u8;
                output.push_str("\\u00");
                output.push(HEX[(byte >> 4) as usize] as char);
                output.push(HEX[(byte & 0xf) as usize] as char);
            }
            '\u{2028}' => output.push_str("\\u2028"),
            '\u{2029}' => output.push_str("\\u2029"),
            other => output.push(other),
        }
    }
}

/// Like [`escape_string`] for bytes that may not be UTF-8: invalid bytes
/// become `\ufffd`, as in Go.
pub fn escape_bytes(output: &mut String, bytes: &[u8]) {
    output.push('"');
    for chunk in bytes.utf8_chunks() {
        escape_inner(output, chunk.valid());
        for _ in chunk.invalid() {
            output.push_str("\\ufffd");
        }
    }
    output.push('"');
}

fn write_indent(output: &mut String, depth: usize) {
    output.push('\n');
    for _ in 0..depth {
        output.push_str("  ");
    }
}

fn write_value(output: &mut String, value: &Value, depth: usize) {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(true) => output.push_str("true"),
        Value::Bool(false) => output.push_str("false"),
        Value::Number(number) => output.push_str(number),
        Value::String(text) => escape_string(output, text),
        Value::Array(items) => {
            if items.is_empty() {
                output.push_str("[]");
                return;
            }
            output.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                write_indent(output, depth + 1);
                write_value(output, item, depth + 1);
            }
            write_indent(output, depth);
            output.push(']');
        }
        Value::Object(fields) => {
            if fields.is_empty() {
                output.push_str("{}");
                return;
            }
            output.push('{');
            for (index, (key, item)) in fields.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                write_indent(output, depth + 1);
                escape_string(output, key);
                output.push_str(": ");
                write_value(output, item, depth + 1);
            }
            write_indent(output, depth);
            output.push('}');
        }
    }
}

fn write_compact(output: &mut String, value: &Value) {
    match value {
        Value::Array(items) => {
            output.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                write_compact(output, item);
            }
            output.push(']');
        }
        Value::Object(fields) => {
            output.push('{');
            for (index, (key, item)) in fields.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                escape_string(output, key);
                output.push(':');
                write_compact(output, item);
            }
            output.push('}');
        }
        other => write_value(output, other, 0),
    }
}

/// What `json.NewEncoder(w)` with `SetIndent("", "  ")` writes for
/// `Encode(value)`, including the trailing newline.
pub fn to_string_indent(value: &Value) -> String {
    let mut output = String::new();
    write_value(&mut output, value, 0);
    output.push('\n');
    output
}

/// What `json.Marshal` returns.
pub fn to_string(value: &Value) -> String {
    let mut output = String::new();
    write_compact(&mut output, value);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn go_formatting() {
        let value = Value::Object(vec![
            ("version".into(), Value::uint(3)),
            (
                "rules".into(),
                Value::Array(vec![Value::Object(vec![
                    ("domain".into(), Value::string("a<b>&c\u{2028}\u{1}")),
                    ("port".into(), Value::Array(vec![])),
                    ("x".into(), Value::Object(vec![])),
                ])]),
            ),
        ]);
        assert_eq!(
            to_string_indent(&value),
            "{\n  \"version\": 3,\n  \"rules\": [\n    {\n      \"domain\": \"a\\u003cb\\u003e\\u0026c\\u2028\\u0001\",\n      \"port\": [],\n      \"x\": {}\n    }\n  ]\n}\n"
        );
        assert_eq!(to_string(&value), "{\"version\":3,\"rules\":[{\"domain\":\"a\\u003cb\\u003e\\u0026c\\u2028\\u0001\",\"port\":[],\"x\":{}}]}");
        let mut output = String::new();
        escape_bytes(&mut output, b"a\xffb");
        assert_eq!(output, "\"a\\ufffdb\"");
    }
}
