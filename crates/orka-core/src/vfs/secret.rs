//! Parses a connection's keychain secret as plain text or as fields.
//!
//! One connection keeps exactly one keychain string. Most auth methods
//! store one value there (a password, a token). A few need more than
//! one field (an S3 session token, an OAuth token set), so those store
//! a single JSON object in the same slot instead of adding keychain
//! entries per connection.

use std::collections::HashMap;

/// A parsed keychain secret. A raw value that starts with `{` and
/// parses as a JSON object is [`SecretFields::Structured`]; anything
/// else is [`SecretFields::Plain`].
pub enum SecretFields {
    Plain(String),
    Structured(HashMap<String, String>),
}

impl SecretFields {
    /// Parses a raw keychain secret. A structured secret keeps only its
    /// string-valued fields; a field of another JSON type is dropped
    /// rather than failing the whole parse, so an unexpected extra
    /// field in the JSON never blocks a connect.
    pub fn parse(raw: &str) -> SecretFields {
        if raw.trim_start().starts_with('{') {
            if let Ok(serde_json::Value::Object(map)) =
                serde_json::from_str::<serde_json::Value>(raw)
            {
                let fields = map
                    .into_iter()
                    .filter_map(|(key, value)| match value {
                        serde_json::Value::String(s) => Some((key, s)),
                        _ => None,
                    })
                    .collect();
                return SecretFields::Structured(fields);
            }
        }
        SecretFields::Plain(raw.to_string())
    }

    /// The secret as one plain string. `None` for a structured secret.
    pub fn plain(&self) -> Option<&str> {
        match self {
            SecretFields::Plain(s) => Some(s),
            SecretFields::Structured(_) => None,
        }
    }

    /// One named field from a structured secret. `None` for a plain
    /// secret or a field the JSON does not carry.
    pub fn field(&self, name: &str) -> Option<&str> {
        match self {
            SecretFields::Plain(_) => None,
            SecretFields::Structured(fields) => fields.get(name).map(String::as_str),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_string_parses_as_plain() {
        let parsed = SecretFields::parse("hunter2");
        assert_eq!(parsed.plain(), Some("hunter2"));
        assert_eq!(parsed.field("anything"), None);
    }

    #[test]
    fn json_object_parses_as_structured() {
        let parsed = SecretFields::parse(r#"{"secret_access_key":"abc","session_token":"xyz"}"#);
        assert_eq!(parsed.plain(), None);
        assert_eq!(parsed.field("secret_access_key"), Some("abc"));
        assert_eq!(parsed.field("session_token"), Some("xyz"));
        assert_eq!(parsed.field("missing"), None);
    }

    #[test]
    fn malformed_json_object_falls_back_to_plain() {
        // Starts with '{' but is not valid JSON: treated as a literal
        // secret rather than an error, so a password that happens to
        // start with a brace still works.
        let parsed = SecretFields::parse("{not json");
        assert_eq!(parsed.plain(), Some("{not json"));
    }

    #[test]
    fn json_array_is_not_structured() {
        // Valid JSON but not an object: treated as plain text.
        let parsed = SecretFields::parse(r#"["a","b"]"#);
        assert_eq!(parsed.plain(), Some(r#"["a","b"]"#));
    }

    #[test]
    fn non_string_field_is_dropped_not_fatal() {
        let parsed = SecretFields::parse(r#"{"token":"abc","expires_at_ms":123}"#);
        assert_eq!(parsed.field("token"), Some("abc"));
        assert_eq!(parsed.field("expires_at_ms"), None);
    }

    #[test]
    fn leading_whitespace_still_detects_json() {
        let parsed = SecretFields::parse(r#"  {"token":"abc"}"#);
        assert_eq!(parsed.field("token"), Some("abc"));
    }
}
