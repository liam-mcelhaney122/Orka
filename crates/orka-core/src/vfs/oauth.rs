//! OAuth sign-in and token refresh for the OAuth-based connectors.
//!
//! [`sign_in`] runs the interactive PKCE loopback flow and returns the
//! resulting [`TokenSet`]. The caller stores its JSON as the
//! connection's keychain secret. [`ensure_fresh_token`] loads that
//! secret, refreshes it when it is close to expiry, and returns a
//! valid access token; a refresh writes the updated [`TokenSet`] back
//! through [`SecretProvider::set_secret`].
//!
//! [`TokenSource`] and [`call_with_auth_retry`] give the REST backends
//! (gdrive, dropbox) one shared place to resolve a bearer token lazily
//! and to retry once after an HTTP 401, instead of repeating that
//! policy in each backend.

use super::connections::SecretProvider;
use super::http;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// How long [`sign_in`] waits for the browser redirect before giving up.
const LOOPBACK_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// A stored token counts as expired once it is within this many
/// milliseconds of `expires_at_ms`. Gives a request built with the
/// token a little headroom to reach the server before it lapses.
const REFRESH_SKEW_MS: u64 = 60_000;

/// The page shown in the browser tab after the loopback redirect. Kept
/// tiny; the user only glances at it before returning to the app.
const SIGN_IN_COMPLETE_HTML: &str =
    "<!doctype html><html><body><p>Sign-in finished. You can close this tab and return to Orka.</p></body></html>";
const SIGN_IN_FAILED_HTML: &str =
    "<!doctype html><html><body><p>Sign-in did not finish. You can close this tab and return to Orka.</p></body></html>";

/// An OAuth identity provider. `Azure` carries the tenant because the
/// authorize and token endpoints are per-tenant; Google and Dropbox
/// use one fixed endpoint for every account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Provider {
    Google,
    Dropbox,
    Azure { tenant_id: String },
}

impl Provider {
    fn authorize_endpoint(&self) -> String {
        match self {
            Provider::Google => "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
            Provider::Dropbox => "https://www.dropbox.com/oauth2/authorize".to_string(),
            Provider::Azure { tenant_id } => format!(
                "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize"
            ),
        }
    }

    fn token_endpoint(&self) -> String {
        match self {
            Provider::Google => "https://oauth2.googleapis.com/token".to_string(),
            Provider::Dropbox => "https://api.dropboxapi.com/oauth2/token".to_string(),
            Provider::Azure { tenant_id } => {
                format!("https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token")
            }
        }
    }

    /// Provider-specific query parameters appended to the authorize
    /// URL, beyond the PKCE and redirect parameters every provider
    /// shares.
    fn extra_authorize_params(&self) -> Vec<(&'static str, String)> {
        match self {
            Provider::Google => vec![
                (
                    "scope",
                    "https://www.googleapis.com/auth/drive".to_string(),
                ),
                ("access_type", "offline".to_string()),
                ("prompt", "consent".to_string()),
            ],
            Provider::Dropbox => vec![("token_access_type", "offline".to_string())],
            Provider::Azure { .. } => vec![(
                "scope",
                "https://storage.azure.com/user_impersonation offline_access".to_string(),
            )],
        }
    }
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

    /// True once `expires_at_ms` is within [`REFRESH_SKEW_MS`] of now.
    fn needs_refresh(&self, now_ms: u64) -> bool {
        needs_refresh(self.expires_at_ms, now_ms)
    }
}

/// True once `expires_at_ms` is within [`REFRESH_SKEW_MS`] of `now_ms`.
/// A free function (not just a `TokenSet` method) so a backend that
/// caches its own short-lived token, such as a Google service-account
/// JWT exchange, can apply the same skew without going through a
/// [`TokenSet`].
pub(crate) fn needs_refresh(expires_at_ms: u64, now_ms: u64) -> bool {
    expires_at_ms <= now_ms.saturating_add(REFRESH_SKEW_MS)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A pluggable access-token source for a REST backend. Wraps either a
/// bearer token pasted once (the legacy `OAuthToken` auth method) or
/// an OAuth app that refreshes lazily through [`ensure_fresh_token`].
/// Cloning is cheap: a fixed token clones a `String`, an OAuth app
/// clones an `Arc` and two small strings.
#[derive(Clone)]
pub enum TokenSource {
    Fixed(String),
    OAuthApp {
        provider: Provider,
        client_id: String,
        connection_id: String,
        secrets: Arc<dyn SecretProvider>,
    },
}

impl TokenSource {
    /// A token for the next request. Cheap when no refresh is due: a
    /// fixed token is returned as-is, and an OAuth app only reaches
    /// the network when its stored token is close to expiry.
    pub fn token(&self) -> Result<String, String> {
        match self {
            TokenSource::Fixed(token) => Ok(token.clone()),
            TokenSource::OAuthApp {
                provider,
                client_id,
                connection_id,
                secrets,
            } => ensure_fresh_token(provider.clone(), client_id, connection_id, secrets.as_ref()),
        }
    }

    /// A token for a retry after an HTTP 401. A fixed token has
    /// nothing to refresh and is returned unchanged, so the retry
    /// reproduces the same failure instead of looping.
    pub fn refresh(&self) -> Result<String, String> {
        self.token()
    }
}

/// Runs one HTTP call against a [`TokenSource`], retrying exactly once
/// with a forced refresh when the first attempt fails with HTTP 401.
/// `call` must build a fresh request on every invocation; `ureq`
/// consumes a request builder on send, so the same builder cannot be
/// reused for the retry.
pub fn call_with_auth_retry<T>(
    tokens: &TokenSource,
    mut call: impl FnMut(&str) -> Result<T, ureq::Error>,
) -> Result<T, String> {
    let token = tokens.token()?;
    match call(&token) {
        Ok(value) => Ok(value),
        Err(ureq::Error::Status(401, _)) => {
            let token = tokens.refresh()?;
            call(&token).map_err(http::error_string)
        }
        Err(e) => Err(http::error_string(e)),
    }
}

/// A verifier/challenge pair for the PKCE authorization-code flow
/// (RFC 7636). The verifier stays on this side; only the challenge (its
/// SHA-256 hash) goes in the authorize URL.
struct Pkce {
    verifier: String,
    challenge: String,
}

/// 32 random bytes, base64url-encoded without padding: 43 characters,
/// which meets RFC 7636's 43-character minimum verifier length using
/// only unreserved characters.
fn generate_pkce() -> Result<Pkce, String> {
    let verifier = random_url_safe_token(32)?;
    let digest = Sha256::digest(verifier.as_bytes());
    let challenge = URL_SAFE_NO_PAD.encode(digest);
    Ok(Pkce {
        verifier,
        challenge,
    })
}

/// A random base64url token of `byte_len` raw bytes, read from the OS
/// CSPRNG. Used for the PKCE verifier and the redirect state parameter.
fn random_url_safe_token(byte_len: usize) -> Result<String, String> {
    let mut buf = vec![0u8; byte_len];
    getrandom::getrandom(&mut buf).map_err(|e| format!("cannot generate random bytes: {e}"))?;
    Ok(URL_SAFE_NO_PAD.encode(buf))
}

/// Builds the provider's authorize URL for the PKCE flow.
fn authorize_url(
    provider: &Provider,
    client_id: &str,
    redirect_uri: &str,
    state: &str,
    code_challenge: &str,
) -> String {
    let mut url = format!(
        "{}?client_id={}&redirect_uri={}&response_type=code&state={}&code_challenge={}&code_challenge_method=S256",
        provider.authorize_endpoint(),
        http::url_encode(client_id),
        http::url_encode(redirect_uri),
        http::url_encode(state),
        http::url_encode(code_challenge),
    );
    for (key, value) in provider.extra_authorize_params() {
        url.push('&');
        url.push_str(key);
        url.push('=');
        url.push_str(&http::url_encode(&value));
    }
    url
}

/// Opens `url` in the system's default browser.
fn open_in_browser(url: &str) -> Result<(), String> {
    std::process::Command::new("open")
        .arg(url)
        .status()
        .map_err(|e| format!("cannot open the browser: {e}"))?;
    Ok(())
}

/// The query parameters the loopback redirect carries.
#[derive(Debug, Default, PartialEq, Eq)]
struct RedirectParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

/// Parses `code`, `state`, and `error` from the request line of the
/// loopback redirect, for example
/// `"GET /callback?code=abc&state=xyz HTTP/1.1"`. Returns the default
/// (all `None`) for a line with no query string, so a malformed or
/// unrelated request never panics the loopback server.
fn parse_redirect_request_line(line: &str) -> RedirectParams {
    let path = line.split_whitespace().nth(1).unwrap_or("");
    let query = match path.split_once('?') {
        Some((_, q)) => q,
        None => return RedirectParams::default(),
    };
    let mut params = RedirectParams::default();
    for pair in query.split('&') {
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
        let decoded = percent_decode(value);
        match key {
            "code" => params.code = Some(decoded),
            "state" => params.state = Some(decoded),
            "error" => params.error = Some(decoded),
            _ => {}
        }
    }
    params
}

/// Decodes `%XX` escapes and `+` as space in one query value. A
/// malformed escape (a `%` without two following hex digits) passes
/// through literally rather than failing the whole decode.
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 3 <= bytes.len() => {
                match u8::from_str_radix(&value[i + 1..i + 3], 16) {
                    Ok(byte) => {
                        out.push(byte);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Reads the loopback HTTP request, replies with a small confirmation
/// page, and returns the parsed redirect parameters. Draining the
/// request headers before writing the response lets the browser read
/// a clean reply instead of a connection reset.
fn handle_redirect_connection(mut stream: TcpStream) -> Result<RedirectParams, String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| format!("cannot configure the redirect connection: {e}"))?;
    let cloned = stream
        .try_clone()
        .map_err(|e| format!("cannot read the redirect connection: {e}"))?;
    let mut reader = BufReader::new(cloned);
    let mut request_line = String::new();
    reader
        .read_line(&mut request_line)
        .map_err(|e| format!("cannot read the browser redirect: {e}"))?;
    let mut header_line = String::new();
    loop {
        header_line.clear();
        match reader.read_line(&mut header_line) {
            Ok(0) => break,
            Ok(_) if header_line == "\r\n" || header_line == "\n" => break,
            Ok(_) => continue,
            Err(_) => break,
        }
    }
    let params = parse_redirect_request_line(&request_line);
    let body = if params.error.is_none() {
        SIGN_IN_COMPLETE_HTML
    } else {
        SIGN_IN_FAILED_HTML
    };
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
    Ok(params)
}

/// Blocks until one connection arrives on `listener` or `timeout`
/// elapses. Polls a non-blocking listener rather than spawning an
/// accept thread, so a timed-out sign-in leaves nothing running.
fn accept_redirect(listener: &TcpListener, timeout: Duration) -> Result<RedirectParams, String> {
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("cannot configure the loopback listener: {e}"))?;
    let deadline = Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok((stream, _)) => return handle_redirect_connection(stream),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err("sign-in timed out waiting for the browser".to_string());
                }
                std::thread::sleep(Duration::from_millis(200));
            }
            Err(e) => return Err(format!("loopback accept failed: {e}")),
        }
    }
}

/// Builds a [`TokenSet`] from a token-endpoint JSON response. Shared by
/// the initial code exchange and every refresh, so `expires_at_ms`
/// computation and the refresh-token carry-over rule (a response that
/// omits `refresh_token` keeps the previous one) live in one place.
fn token_set_from_json(
    value: &serde_json::Value,
    existing_refresh_token: Option<&str>,
    client_secret: Option<&str>,
) -> Result<TokenSet, String> {
    let access_token = value
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "token response is missing access_token".to_string())?
        .to_string();
    let refresh_token = value
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .or_else(|| existing_refresh_token.map(str::to_string));
    let expires_in = value.get("expires_in").and_then(|v| v.as_u64()).unwrap_or(3600);
    let expires_at_ms = now_ms().saturating_add(expires_in.saturating_mul(1000));
    Ok(TokenSet {
        access_token,
        refresh_token,
        expires_at_ms,
        client_secret: client_secret.map(str::to_string),
    })
}

/// Exchanges an authorization `code` for a [`TokenSet`] at the
/// provider's token endpoint.
fn exchange_code(
    provider: &Provider,
    client_id: &str,
    client_secret: Option<&str>,
    code: &str,
    code_verifier: &str,
    redirect_uri: &str,
) -> Result<TokenSet, String> {
    let mut form: Vec<(&str, &str)> = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", client_id),
        ("code_verifier", code_verifier),
    ];
    if let Some(secret) = client_secret {
        form.push(("client_secret", secret));
    }
    let response = http::agent()
        .post(&provider.token_endpoint())
        .send_form(&form)
        .map_err(http::error_string)?;
    let value: serde_json::Value = response
        .into_json()
        .map_err(|e| format!("token response was not valid JSON: {e}"))?;
    token_set_from_json(&value, None, client_secret)
}

/// Runs the interactive PKCE loopback flow: opens the system browser
/// at the provider's authorize endpoint and waits for the redirect on
/// a local server. Blocks the calling thread until the user finishes
/// in the browser, cancels, or the flow times out.
pub fn sign_in(
    provider: Provider,
    client_id: &str,
    client_secret: Option<&str>,
) -> Result<TokenSet, String> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|e| format!("cannot open a local port for sign-in: {e}"))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("cannot read the local sign-in port: {e}"))?
        .port();
    let redirect_uri = format!("http://127.0.0.1:{port}/callback");
    let pkce = generate_pkce()?;
    let state = random_url_safe_token(16)?;
    let url = authorize_url(&provider, client_id, &redirect_uri, &state, &pkce.challenge);

    open_in_browser(&url)?;

    let params = accept_redirect(&listener, LOOPBACK_TIMEOUT)?;
    if let Some(error) = params.error {
        return Err(format!("sign-in was not completed: {error}"));
    }
    if params.state.as_deref() != Some(state.as_str()) {
        return Err("sign-in failed: the redirect state did not match".to_string());
    }
    let code = params
        .code
        .ok_or_else(|| "sign-in failed: the redirect had no authorization code".to_string())?;

    exchange_code(
        &provider,
        client_id,
        client_secret,
        &code,
        &pkce.verifier,
        &redirect_uri,
    )
}

/// Returns a valid access token for `connection_id`, refreshing it
/// first when it is within 60 seconds of `expires_at_ms`. A refresh
/// stores the new [`TokenSet`] back through
/// [`SecretProvider::set_secret`] before returning.
pub fn ensure_fresh_token(
    provider: Provider,
    client_id: &str,
    connection_id: &str,
    secrets: &dyn SecretProvider,
) -> Result<String, String> {
    let raw = secrets
        .get_secret(connection_id)
        .ok_or_else(|| "no token stored for this connection".to_string())?;
    let token_set = TokenSet::from_json(&raw)?;
    if !token_set.needs_refresh(now_ms()) {
        return Ok(token_set.access_token);
    }
    let refresh_token = token_set
        .refresh_token
        .as_deref()
        .ok_or_else(|| "stored token has no refresh token to renew it with".to_string())?;

    let mut form: Vec<(&str, &str)> = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", client_id),
    ];
    if let Some(secret) = &token_set.client_secret {
        form.push(("client_secret", secret));
    }
    let response = http::agent()
        .post(&provider.token_endpoint())
        .send_form(&form)
        .map_err(http::error_string)?;
    let value: serde_json::Value = response
        .into_json()
        .map_err(|e| format!("refresh response was not valid JSON: {e}"))?;
    let refreshed = token_set_from_json(
        &value,
        token_set.refresh_token.as_deref(),
        token_set.client_secret.as_deref(),
    )?;

    secrets.set_secret(connection_id, &refreshed.to_json()?);
    Ok(refreshed.access_token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

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

    #[test]
    fn expiry_flags_a_token_within_the_refresh_skew() {
        let now = 1_000_000_u64;
        assert!(needs_refresh(now, now));
        assert!(needs_refresh(now + REFRESH_SKEW_MS, now));
        assert!(needs_refresh(now + REFRESH_SKEW_MS - 1, now));
        assert!(!needs_refresh(now + REFRESH_SKEW_MS + 1, now));
        assert!(!needs_refresh(now + 3_600_000, now));
    }

    #[test]
    fn expiry_flags_an_already_expired_token() {
        assert!(needs_refresh(500, 1_000));
    }

    #[test]
    fn pkce_verifier_and_challenge_derive_correctly() {
        let pkce = generate_pkce().unwrap();
        // RFC 7636: 43-128 characters, unreserved charset only.
        assert!(pkce.verifier.len() >= 43 && pkce.verifier.len() <= 128);
        assert!(pkce
            .verifier
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        // The challenge is the base64url(SHA-256(verifier)), recomputed
        // here from scratch as an independent check.
        let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(pkce.verifier.as_bytes()));
        assert_eq!(pkce.challenge, expected);
        // No padding characters, and every challenge is unique.
        assert!(!pkce.challenge.contains('='));
        let other = generate_pkce().unwrap();
        assert_ne!(pkce.verifier, other.verifier);
    }

    #[test]
    fn random_token_has_no_padding_and_varies() {
        let a = random_url_safe_token(16).unwrap();
        let b = random_url_safe_token(16).unwrap();
        assert_ne!(a, b);
        assert!(!a.contains('='));
        assert!(!a.contains('+'));
        assert!(!a.contains('/'));
    }

    #[test]
    fn authorize_url_carries_pkce_and_state_for_every_provider() {
        for provider in [
            Provider::Google,
            Provider::Dropbox,
            Provider::Azure {
                tenant_id: "common".to_string(),
            },
        ] {
            let url = authorize_url(
                &provider,
                "client-1",
                "http://127.0.0.1:9/callback",
                "state-1",
                "challenge-1",
            );
            assert!(url.starts_with(&provider.authorize_endpoint()), "{url}");
            assert!(url.contains("client_id=client-1"), "{url}");
            assert!(url.contains("response_type=code"), "{url}");
            assert!(url.contains("state=state-1"), "{url}");
            assert!(url.contains("code_challenge=challenge-1"), "{url}");
            assert!(url.contains("code_challenge_method=S256"), "{url}");
            assert!(
                url.contains(&format!(
                    "redirect_uri={}",
                    http::url_encode("http://127.0.0.1:9/callback")
                )),
                "{url}"
            );
        }
    }

    #[test]
    fn google_authorize_url_requests_offline_drive_access() {
        let url = authorize_url(&Provider::Google, "c", "http://127.0.0.1:1/cb", "s", "ch");
        assert!(url.contains(&http::url_encode("https://www.googleapis.com/auth/drive")));
        assert!(url.contains("access_type=offline"));
        assert!(url.contains("prompt=consent"));
    }

    #[test]
    fn dropbox_authorize_url_requests_offline_token_access() {
        let url = authorize_url(&Provider::Dropbox, "c", "http://127.0.0.1:1/cb", "s", "ch");
        assert!(url.contains("token_access_type=offline"));
    }

    #[test]
    fn azure_authorize_url_uses_the_tenant_and_storage_scope() {
        let url = authorize_url(
            &Provider::Azure {
                tenant_id: "my-tenant".to_string(),
            },
            "c",
            "http://127.0.0.1:1/cb",
            "s",
            "ch",
        );
        assert!(url.starts_with(
            "https://login.microsoftonline.com/my-tenant/oauth2/v2.0/authorize?"
        ));
        assert!(url.contains(&http::url_encode(
            "https://storage.azure.com/user_impersonation offline_access"
        )));
    }

    #[test]
    fn azure_token_endpoint_uses_the_tenant() {
        let provider = Provider::Azure {
            tenant_id: "my-tenant".to_string(),
        };
        assert_eq!(
            provider.token_endpoint(),
            "https://login.microsoftonline.com/my-tenant/oauth2/v2.0/token"
        );
    }

    #[test]
    fn redirect_line_extracts_code_and_state() {
        let params =
            parse_redirect_request_line("GET /callback?code=abc123&state=xyz789 HTTP/1.1\r\n");
        assert_eq!(params.code.as_deref(), Some("abc123"));
        assert_eq!(params.state.as_deref(), Some("xyz789"));
        assert_eq!(params.error, None);
    }

    #[test]
    fn redirect_line_decodes_percent_and_plus_encoded_values() {
        let params = parse_redirect_request_line(
            "GET /callback?code=a%2Fb%3Dc&state=has+space HTTP/1.1\r\n",
        );
        assert_eq!(params.code.as_deref(), Some("a/b=c"));
        assert_eq!(params.state.as_deref(), Some("has space"));
    }

    #[test]
    fn redirect_line_extracts_error_and_no_code() {
        let params = parse_redirect_request_line(
            "GET /callback?error=access_denied&state=xyz HTTP/1.1\r\n",
        );
        assert_eq!(params.error.as_deref(), Some("access_denied"));
        assert_eq!(params.code, None);
    }

    #[test]
    fn redirect_line_with_no_query_yields_all_none() {
        let params = parse_redirect_request_line("GET /callback HTTP/1.1\r\n");
        assert_eq!(params, RedirectParams::default());
    }

    #[test]
    fn redirect_line_ignores_unrelated_favicon_request() {
        let params = parse_redirect_request_line("GET /favicon.ico HTTP/1.1\r\n");
        assert_eq!(params, RedirectParams::default());
    }

    #[test]
    fn percent_decode_handles_a_trailing_malformed_escape() {
        // A '%' with no two hex digits after it passes through as-is
        // rather than panicking on the out-of-range slice.
        assert_eq!(percent_decode("abc%"), "abc%");
        assert_eq!(percent_decode("abc%2"), "abc%2");
        assert_eq!(percent_decode("abc%zz"), "abc%zz");
    }

    /// Serves one loopback HTTP request end to end, exactly as
    /// [`accept_redirect`] does for the real sign-in flow, so the
    /// listener bind, non-blocking accept loop, and response-writing
    /// path all run against a real (but local-only) socket.
    #[test]
    fn accept_redirect_parses_a_real_loopback_request() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = std::thread::spawn(move || {
            use std::io::Read;
            let mut stream = TcpStream::connect(addr).unwrap();
            stream
                .write_all(b"GET /callback?code=xyz&state=abc HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                .unwrap();
            let mut body = String::new();
            stream.read_to_string(&mut body).unwrap();
            body
        });
        let params = accept_redirect(&listener, Duration::from_secs(5)).unwrap();
        assert_eq!(params.code.as_deref(), Some("xyz"));
        assert_eq!(params.state.as_deref(), Some("abc"));
        let body = client.join().unwrap();
        assert!(body.contains("Sign-in finished"), "{body}");
    }

    #[test]
    fn accept_redirect_times_out_when_nothing_connects() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let err = accept_redirect(&listener, Duration::from_millis(50)).unwrap_err();
        assert!(err.contains("timed out"), "got: {err}");
    }

    struct RecordingSecrets {
        stored: Mutex<HashMap<String, String>>,
    }

    impl RecordingSecrets {
        fn seeded(connection_id: &str, value: &str) -> Self {
            let mut map = HashMap::new();
            map.insert(connection_id.to_string(), value.to_string());
            Self {
                stored: Mutex::new(map),
            }
        }
    }

    impl SecretProvider for RecordingSecrets {
        fn get_secret(&self, connection_id: &str) -> Option<String> {
            self.stored.lock().unwrap().get(connection_id).cloned()
        }

        fn set_secret(&self, connection_id: &str, value: &str) {
            self.stored
                .lock()
                .unwrap()
                .insert(connection_id.to_string(), value.to_string());
        }
    }

    #[test]
    fn ensure_fresh_token_returns_the_stored_token_without_a_network_call() {
        let far_future = now_ms() + 3_600_000;
        let set = TokenSet {
            access_token: "still-good".to_string(),
            refresh_token: Some("r".to_string()),
            expires_at_ms: far_future,
            client_secret: None,
        };
        let secrets = RecordingSecrets::seeded("conn", &set.to_json().unwrap());
        let token = ensure_fresh_token(Provider::Google, "client", "conn", &secrets).unwrap();
        assert_eq!(token, "still-good");
    }

    #[test]
    fn ensure_fresh_token_fails_without_a_stored_secret() {
        struct NoSecrets;
        impl SecretProvider for NoSecrets {
            fn get_secret(&self, _connection_id: &str) -> Option<String> {
                None
            }
        }
        let err = ensure_fresh_token(Provider::Google, "client", "conn", &NoSecrets).unwrap_err();
        assert!(err.contains("no token stored"), "got: {err}");
    }

    #[test]
    fn ensure_fresh_token_fails_when_expired_with_no_refresh_token() {
        let set = TokenSet {
            access_token: "stale".to_string(),
            refresh_token: None,
            expires_at_ms: 0,
            client_secret: None,
        };
        let secrets = RecordingSecrets::seeded("conn", &set.to_json().unwrap());
        let err = ensure_fresh_token(Provider::Google, "client", "conn", &secrets).unwrap_err();
        assert!(err.contains("no refresh token"), "got: {err}");
    }

    #[test]
    fn token_source_fixed_returns_the_pasted_token_unchanged() {
        let source = TokenSource::Fixed("pasted-token".to_string());
        assert_eq!(source.token().unwrap(), "pasted-token");
        assert_eq!(source.refresh().unwrap(), "pasted-token");
    }

    #[test]
    fn token_source_oauth_app_reads_through_ensure_fresh_token() {
        let far_future = now_ms() + 3_600_000;
        let set = TokenSet {
            access_token: "app-token".to_string(),
            refresh_token: Some("r".to_string()),
            expires_at_ms: far_future,
            client_secret: None,
        };
        let secrets: Arc<dyn SecretProvider> =
            Arc::new(RecordingSecrets::seeded("conn", &set.to_json().unwrap()));
        let source = TokenSource::OAuthApp {
            provider: Provider::Dropbox,
            client_id: "client".to_string(),
            connection_id: "conn".to_string(),
            secrets,
        };
        assert_eq!(source.token().unwrap(), "app-token");
    }

    #[test]
    fn call_with_auth_retry_succeeds_without_a_retry() {
        let tokens = TokenSource::Fixed("t1".to_string());
        let mut calls = 0;
        let result: Result<u32, String> = call_with_auth_retry(&tokens, |token| {
            calls += 1;
            assert_eq!(token, "t1");
            Ok(7)
        });
        assert_eq!(result, Ok(7));
        assert_eq!(calls, 1);
    }

    /// Serves `statuses.len()` responses in order, one per accepted
    /// connection, on a local loopback port. Used to prove
    /// [`call_with_auth_retry`] retries exactly once against a real
    /// HTTP 401 status (not just a transport-level failure).
    fn serve_statuses(statuses: &'static [&'static str]) -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for status in statuses {
                let Ok((mut stream, _)) = listener.accept() else {
                    break;
                };
                let mut buf = [0u8; 1];
                let mut seen = String::new();
                while !seen.contains("\r\n\r\n") {
                    match std::io::Read::read(&mut stream, &mut buf) {
                        Ok(0) => break,
                        Ok(_) => seen.push(buf[0] as char),
                        Err(_) => break,
                    }
                }
                let body = "{}";
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
                std::thread::sleep(Duration::from_millis(50));
            }
        });
        port
    }

    #[test]
    fn call_with_auth_retry_succeeds_after_one_401() {
        let port = serve_statuses(&["401 Unauthorized", "200 OK"]);
        let tokens = TokenSource::Fixed("t1".to_string());
        let mut calls = 0;
        let result: Result<String, String> = call_with_auth_retry(&tokens, |_token| {
            calls += 1;
            http::agent()
                .get(&format!("http://127.0.0.1:{port}/"))
                .call()
                .map(http::read_body_string)
        });
        assert_eq!(calls, 2, "must retry exactly once");
        assert_eq!(result, Ok("{}".to_string()));
    }

    #[test]
    fn call_with_auth_retry_gives_up_after_a_second_401() {
        let port = serve_statuses(&["401 Unauthorized", "401 Unauthorized"]);
        let tokens = TokenSource::Fixed("t1".to_string());
        let mut calls = 0;
        let result: Result<String, String> = call_with_auth_retry(&tokens, |_token| {
            calls += 1;
            http::agent()
                .get(&format!("http://127.0.0.1:{port}/"))
                .call()
                .map(http::read_body_string)
        });
        assert_eq!(calls, 2, "must not retry a second time");
        assert!(result.unwrap_err().contains("401"));
    }
}
