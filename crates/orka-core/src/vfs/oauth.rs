//! OAuth sign-in and token refresh for the OAuth-based connectors.
//!
//! [`sign_in`] runs the interactive PKCE loopback flow and returns the
//! resulting [`TokenSet`]. The caller stores its JSON as the
//! connection's keychain secret. [`ensure_fresh_token`] loads that
//! secret, refreshes it when it is close to expiry, and returns a
//! valid access token; a refresh writes the updated [`TokenSet`] back
//! through [`SecretProvider::set_secret`].
//!
//! This module defines the shape only. Both functions return an error
//! until the flows are implemented.

use super::connections::SecretProvider;
use serde::{Deserialize, Serialize};

/// An OAuth identity provider. `Azure` carries the tenant because the
/// authorize and token endpoints are per-tenant; Google and Dropbox
/// use one fixed endpoint for every account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Provider {
    Google,
    Dropbox,
    Azure { tenant_id: String },
}

/// A refreshable OAuth credential, stored as the connection's keychain
/// secret in JSON form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenSet {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at_ms: u64,
    /// Some desktop OAuth clients (Google's among them) require the
    /// client secret on a refresh call even though the app is a
    /// "public" installed client. Optional because most providers
    /// need only the client id.
    pub client_secret: Option<String>,
}

impl TokenSet {
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string(self).map_err(|e| format!("cannot encode token set: {e}"))
    }

    pub fn from_json(raw: &str) -> Result<Self, String> {
        serde_json::from_str(raw).map_err(|e| format!("cannot decode token set: {e}"))
    }
}

/// Runs the interactive PKCE loopback flow: opens the system browser
/// at the provider's authorize endpoint and waits for the redirect on
/// a local server. Blocks the calling thread until the user finishes
/// in the browser, cancels, or the flow times out.
pub fn sign_in(
    _provider: Provider,
    _client_id: &str,
    _client_secret: Option<&str>,
) -> Result<TokenSet, String> {
    Err("not implemented".to_string())
}

/// Returns a valid access token for `connection_id`, refreshing it
/// first when it is within 60 seconds of `expires_at_ms`. A refresh
/// stores the new [`TokenSet`] back through
/// [`SecretProvider::set_secret`] before returning.
pub fn ensure_fresh_token(
    _provider: Provider,
    _client_id: &str,
    _connection_id: &str,
    _secrets: &dyn SecretProvider,
) -> Result<String, String> {
    Err("not implemented".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_set_round_trips_through_json() {
        let set = TokenSet {
            access_token: "access".to_string(),
            refresh_token: Some("refresh".to_string()),
            expires_at_ms: 1_700_000_000_000,
            client_secret: Some("shh".to_string()),
        };
        let json = set.to_json().unwrap();
        assert_eq!(TokenSet::from_json(&json).unwrap(), set);
    }

    #[test]
    fn token_set_round_trips_with_optional_fields_absent() {
        let set = TokenSet {
            access_token: "access".to_string(),
            refresh_token: None,
            expires_at_ms: 0,
            client_secret: None,
        };
        let json = set.to_json().unwrap();
        assert_eq!(TokenSet::from_json(&json).unwrap(), set);
    }

    #[test]
    fn from_json_rejects_malformed_input() {
        assert!(TokenSet::from_json("not json").is_err());
        assert!(TokenSet::from_json(r#"{"access_token":"a"}"#).is_err());
    }
}
