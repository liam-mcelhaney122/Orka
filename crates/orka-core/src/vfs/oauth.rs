//! OAuth sign-in and token refresh for the OAuth-based connectors.
//!
//! [`sign_in`] runs the interactive PKCE loopback flow and returns the
//! resulting [`TokenSet`]. The caller stores its JSON as the
//! connection's keychain secret. [`ensure_fresh_token`] loads that
//! secret, refreshes it when it is close to expiry, and returns a
//! valid access token; [`refresh_stored_token`] forces that renewal
//! even when the token does not look close to expiry, for a retry
//! after an HTTP 401. A refresh writes the updated [`TokenSet`] back
//! through [`SecretProvider::set_secret`].
//!
//! [`sign_in`] is a thin wrapper over [`sign_in_with_opener`], which
//! takes the browser-launch step as a function. A test passes a fake
//! opener to drive the loopback flow with no real browser. The
//! authorize and token endpoints for every provider go through
//! [`super::endpoints`], so a test can also point them at a local
//! server.
//!
//! [`TokenSource`] gives every REST backend (gdrive, dropbox, ADLS)
//! one shared place to resolve a bearer token lazily and cache it in
//! memory. [`call_with_auth_retry`] (and [`call_with_auth_retry_and`],
//! for a backend that needs its own hint on the final error) shares
//! the retry-once-after-401 policy the same way; Dropbox uses it
//! directly, and gdrive's own retry wraps [`TokenSource`] to also
//! cover its Google-service-account token source.

use super::connections::SecretProvider;
use super::http;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex, OnceLock};
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
            Provider::Google => super::endpoints::google_auth_endpoint(),
            Provider::Dropbox => super::endpoints::dropbox_auth_endpoint(),
            Provider::Azure { tenant_id } => format!(
                "{}/{tenant_id}/oauth2/v2.0/authorize",
                super::endpoints::azure_login_base()
            ),
        }
    }

    fn token_endpoint(&self) -> String {
        match self {
            Provider::Google => super::endpoints::google_token_endpoint(),
            Provider::Dropbox => super::endpoints::dropbox_token_endpoint(),
            Provider::Azure { tenant_id } => {
                format!(
                    "{}/{tenant_id}/oauth2/v2.0/token",
                    super::endpoints::azure_login_base()
                )
            }
        }
    }

    /// Provider-specific query parameters appended to the authorize
    /// URL, beyond the PKCE and redirect parameters every provider
    /// shares.
    fn extra_authorize_params(&self) -> Vec<(&'static str, String)> {
        match self {
            Provider::Google => vec![
                ("scope", "https://www.googleapis.com/auth/drive".to_string()),
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

    /// Checks a provider's own identifiers before they enter a URL.
    /// Only Azure carries caller-supplied text (the tenant id); Google
    /// and Dropbox have no per-connection identifier to check.
    fn validate(&self) -> Result<(), String> {
        match self {
            Provider::Azure { tenant_id } => validate_azure_tenant_id(tenant_id),
            Provider::Google | Provider::Dropbox => Ok(()),
        }
    }
}

/// Accepts only letters, digits, `.`, `-`, and `_`, which covers both
/// forms Azure issues a tenant id in: a GUID and a domain name. The
/// tenant id goes straight into a URL path segment, so anything else
/// must be rejected before that URL is built.
fn validate_azure_tenant_id(tenant_id: &str) -> Result<(), String> {
    let is_valid = !tenant_id.is_empty()
        && tenant_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'));
    if is_valid {
        Ok(())
    } else {
        Err(format!("invalid Azure tenant ID: {tenant_id}"))
    }
}

/// A refreshable OAuth credential, stored as the connection's keychain
/// secret in JSON form. No `Debug` derive: every field but the expiry
/// is a secret, and a stray `{:?}` in a log must never print one.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
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
/// clones an `Arc`, two small strings, and a shared token cache.
#[derive(Clone)]
pub enum TokenSource {
    Fixed(String),
    OAuthApp {
        provider: Provider,
        client_id: String,
        connection_id: String,
        secrets: Arc<dyn SecretProvider>,
        /// The most recently resolved token and its real expiry.
        /// [`TokenSource::token`] only reads the keychain when this is
        /// empty or has gone stale, instead of on every request.
        cache: Arc<Mutex<Option<FreshToken>>>,
    },
}

impl TokenSource {
    /// A token for the next request. Cheap when no refresh is due: a
    /// fixed token is returned as-is, and an OAuth app only reaches
    /// the keychain when its in-memory cache is empty or close to
    /// expiry.
    pub fn token(&self) -> Result<String, String> {
        match self {
            TokenSource::Fixed(token) => Ok(token.clone()),
            TokenSource::OAuthApp {
                provider,
                client_id,
                connection_id,
                secrets,
                cache,
            } => {
                if let Some(cached) = cache.lock().unwrap().as_ref() {
                    if !needs_refresh(cached.expires_at_ms, now_ms()) {
                        return Ok(cached.access_token.clone());
                    }
                }
                let fresh = ensure_fresh_token_with(
                    provider.clone(),
                    client_id,
                    connection_id,
                    secrets.as_ref(),
                    false,
                )?;
                let token = fresh.access_token.clone();
                *cache.lock().unwrap() = Some(fresh);
                Ok(token)
            }
        }
    }

    /// A token for a retry after an HTTP 401. A fixed token has
    /// nothing to refresh and is returned unchanged, so the retry
    /// reproduces the same failure instead of looping. An OAuth app
    /// forces a fresh token even when the stored one does not look
    /// close to expiry: the server just rejected it, so the client's
    /// own expiry guess is not trustworthy anymore.
    pub fn refresh(&self) -> Result<String, String> {
        match self {
            TokenSource::Fixed(token) => Ok(token.clone()),
            TokenSource::OAuthApp {
                provider,
                client_id,
                connection_id,
                secrets,
                cache,
            } => {
                let fresh = ensure_fresh_token_with(
                    provider.clone(),
                    client_id,
                    connection_id,
                    secrets.as_ref(),
                    true,
                )?;
                let token = fresh.access_token.clone();
                *cache.lock().unwrap() = Some(fresh);
                Ok(token)
            }
        }
    }
}

/// Runs one HTTP call against a [`TokenSource`], retrying exactly once
/// with a forced refresh when the first attempt fails with HTTP 401.
/// `call` must build a fresh request on every invocation; `ureq`
/// consumes a request builder on send, so the same builder cannot be
/// reused for the retry.
pub fn call_with_auth_retry<T>(
    tokens: &TokenSource,
    call: impl FnMut(&str) -> Result<T, ureq::Error>,
) -> Result<T, String> {
    call_with_auth_retry_and(tokens, http::error_string, call)
}

/// [`call_with_auth_retry`], but with `format_error` used in place of
/// [`http::error_string`] for the final failure. Lets a backend keep
/// its own hint on a failure that survives the retry (Dropbox's
/// expired-token message, for example) while still sharing the retry
/// policy itself.
pub fn call_with_auth_retry_and<T>(
    tokens: &TokenSource,
    format_error: impl Fn(ureq::Error) -> String,
    mut call: impl FnMut(&str) -> Result<T, ureq::Error>,
) -> Result<T, String> {
    let token = tokens.token()?;
    match call(&token) {
        Ok(value) => Ok(value),
        Err(ureq::Error::Status(401, _)) => {
            let token = tokens.refresh()?;
            call(&token).map_err(format_error)
        }
        Err(e) => Err(format_error(e)),
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
    let status = std::process::Command::new("open")
        .arg(url)
        .status()
        .map_err(|e| format!("cannot open the browser: {e}"))?;
    open_status_result(status)
}

/// Turns a finished `open` command's exit status into a result. Pure
/// over the status, so a non-zero exit is testable without actually
/// launching `open`.
fn open_status_result(status: std::process::ExitStatus) -> Result<(), String> {
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "cannot open the browser: the open command exited with {status}"
        ))
    }
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
            b'%' if i + 3 <= bytes.len() => match u8::from_str_radix(&value[i + 1..i + 3], 16) {
                Ok(byte) => {
                    out.push(byte);
                    i += 3;
                }
                Err(_) => {
                    out.push(bytes[i]);
                    i += 1;
                }
            },
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

/// Reads the loopback HTTP request, replies, and returns the parsed
/// redirect parameters. Draining the request headers before writing
/// the response lets the browser read a clean reply instead of a
/// connection reset.
///
/// Returns `None` for a request that carries neither `code` nor
/// `state`, such as the browser's automatic favicon fetch on the
/// redirect tab: that request is not the OAuth redirect, so it gets a
/// 404 and the caller keeps waiting for the real one instead of ending
/// the sign-in flow on it.
fn handle_redirect_connection(mut stream: TcpStream) -> Result<Option<RedirectParams>, String> {
    // The accepted stream can inherit the listener's non-blocking mode
    // on macOS, which would make the read below fail immediately with
    // `WouldBlock` instead of waiting up to the timeout set next.
    stream
        .set_nonblocking(false)
        .map_err(|e| format!("cannot configure the redirect connection: {e}"))?;
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
    if params.code.is_none() && params.state.is_none() {
        let response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.flush();
        return Ok(None);
    }
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
    Ok(Some(params))
}

/// Blocks until the real OAuth redirect arrives on `listener` or
/// `timeout` elapses. Polls a non-blocking listener rather than
/// spawning an accept thread, so a timed-out sign-in leaves nothing
/// running. An unrelated connection (a favicon fetch, a stray probe)
/// does not end the wait; only one carrying `code` or `state` does.
fn accept_redirect(listener: &TcpListener, timeout: Duration) -> Result<RedirectParams, String> {
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("cannot configure the loopback listener: {e}"))?;
    let deadline = Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                if let Some(params) = handle_redirect_connection(stream)? {
                    return Ok(params);
                }
                if Instant::now() >= deadline {
                    return Err("sign-in timed out waiting for the browser".to_string());
                }
            }
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
    let expires_in = value
        .get("expires_in")
        .and_then(|v| v.as_u64())
        .unwrap_or(3600);
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
    let response = http::agent()?
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
    sign_in_with_opener(provider, client_id, client_secret, &open_in_browser)
}

/// [`sign_in`] with the browser launch replaced by `opener`, so a test
/// can drive the flow without a real browser.
///
/// `opener` must return promptly: the loopback listener only starts
/// accepting the redirect after `opener` returns, so a test opener
/// that answers the redirect itself must do that HTTP work on a
/// separate thread rather than before returning.
pub fn sign_in_with_opener(
    provider: Provider,
    client_id: &str,
    client_secret: Option<&str>,
    opener: &dyn Fn(&str) -> Result<(), String>,
) -> Result<TokenSet, String> {
    provider.validate()?;
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

    opener(&url)?;

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

/// A resolved access token together with the real expiry the token
/// endpoint reported. Lets a caller cache the token itself, keyed on
/// its true lifetime, instead of re-reading the keychain (and the
/// stored token's own expiry) on every request.
#[derive(Clone)]
pub struct FreshToken {
    pub access_token: String,
    pub expires_at_ms: u64,
}

impl std::fmt::Debug for FreshToken {
    /// Redacts the access token; only the expiry is useful in a log or
    /// a failed test assertion.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FreshToken")
            .field("access_token", &"<redacted>")
            .field("expires_at_ms", &self.expires_at_ms)
            .finish()
    }
}

/// True when a stored token must be refreshed before use. `force`
/// always requires a refresh, regardless of `expires_at_ms`: the
/// caller just saw an HTTP 401 for this exact token, so the client's
/// own expiry guess is not trustworthy anymore and must not gate the
/// refresh. Otherwise the normal expiry skew applies. Pure so the
/// decision is testable without a network call.
fn should_refresh(force: bool, expires_at_ms: u64, now_ms: u64) -> bool {
    force || needs_refresh(expires_at_ms, now_ms)
}

/// Resolves a valid access token for `connection_id`, together with
/// its real expiry. `force` skips the expiry check and always renews
/// the token when a refresh token is on file, so a caller retrying
/// after an HTTP 401 does not resend the same rejected token
/// unchanged. [`ensure_fresh_token`] calls this with `force: false`;
/// [`refresh_stored_token`] calls this with `force: true`. A refresh
/// stores the new [`TokenSet`] back through
/// [`SecretProvider::set_secret`] before returning.
/// The lock that serializes a refresh for one connection id, process
/// wide. Two backends (or two pump threads on the same backend) can
/// both hit an HTTP 401 for the same connection at once; without this,
/// both could race to POST the same refresh grant, and most providers
/// invalidate a refresh token the moment it is used, so the loser
/// would fail with `invalid_grant` instead of reusing the winner's
/// result.
fn refresh_lock_for(connection_id: &str) -> Arc<Mutex<()>> {
    static LOCKS: OnceLock<Mutex<HashMap<String, Arc<Mutex<()>>>>> = OnceLock::new();
    let locks = LOCKS.get_or_init(|| Mutex::new(HashMap::new()));
    locks
        .lock()
        .unwrap()
        .entry(connection_id.to_string())
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone()
}

fn ensure_fresh_token_with(
    provider: Provider,
    client_id: &str,
    connection_id: &str,
    secrets: &dyn SecretProvider,
    force: bool,
) -> Result<FreshToken, String> {
    let raw = secrets
        .get_secret(connection_id)
        .ok_or_else(|| "no token stored for this connection".to_string())?;
    let token_set = TokenSet::from_json(&raw)?;
    if !should_refresh(force, token_set.expires_at_ms, now_ms()) {
        return Ok(FreshToken {
            access_token: token_set.access_token,
            expires_at_ms: token_set.expires_at_ms,
        });
    }

    // Serialize the refresh per connection: two pump threads racing a
    // 401 for the same connection must not both rotate the stored
    // refresh token, since most providers invalidate one the moment
    // it is used.
    let lock = refresh_lock_for(connection_id);
    let _guard = lock.lock().unwrap();

    // Another thread may have refreshed this connection while this
    // one waited for the lock. Its result already covers this call,
    // so there is no need to rotate the refresh token a second time.
    if let Some(current_raw) = secrets.get_secret(connection_id) {
        if current_raw != raw {
            let reloaded = TokenSet::from_json(&current_raw)?;
            return Ok(FreshToken {
                access_token: reloaded.access_token,
                expires_at_ms: reloaded.expires_at_ms,
            });
        }
    }

    let refresh_token = token_set.refresh_token.as_deref().ok_or_else(|| {
        "stored token has no refresh token; sign in again to renew this connection".to_string()
    })?;
    provider.validate()?;

    let mut form: Vec<(&str, &str)> = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", client_id),
    ];
    if let Some(secret) = &token_set.client_secret {
        form.push(("client_secret", secret));
    }
    let response = http::agent()?
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
    Ok(FreshToken {
        access_token: refreshed.access_token,
        expires_at_ms: refreshed.expires_at_ms,
    })
}

/// Resolves a valid access token for `connection_id`, refreshing it
/// first when it is within 60 seconds of `expires_at_ms`. The result
/// carries the token's real expiry so a caller can cache it directly.
pub fn ensure_fresh_token(
    provider: Provider,
    client_id: &str,
    connection_id: &str,
    secrets: &dyn SecretProvider,
) -> Result<FreshToken, String> {
    ensure_fresh_token_with(provider, client_id, connection_id, secrets, false)
}

/// Forces a refresh of the stored token for `connection_id`, even when
/// it does not look close to expiry. Use this after an HTTP 401: the
/// server just rejected the current access token, so it must be
/// replaced rather than resent on a retry.
pub fn refresh_stored_token(
    provider: Provider,
    client_id: &str,
    connection_id: &str,
    secrets: &dyn SecretProvider,
) -> Result<FreshToken, String> {
    ensure_fresh_token_with(provider, client_id, connection_id, secrets, true)
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
        // TokenSet carries no Debug impl, so assert_eq! (which needs
        // one to print a failure) is not available here; PartialEq
        // alone is enough to check the round trip.
        assert!(TokenSet::from_json(&json).unwrap() == set);
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
        assert!(TokenSet::from_json(&json).unwrap() == set);
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
    fn should_refresh_forces_regardless_of_expiry() {
        assert!(should_refresh(true, u64::MAX, 0));
        assert!(should_refresh(true, 0, 0));
    }

    #[test]
    fn should_refresh_defers_to_expiry_when_not_forced() {
        let now = 1_000_000_u64;
        assert!(!should_refresh(false, now + REFRESH_SKEW_MS + 1, now));
        assert!(should_refresh(false, now + REFRESH_SKEW_MS, now));
        assert!(should_refresh(false, now - 1, now));
    }

    #[test]
    fn open_status_result_fails_clearly_on_a_nonzero_exit() {
        use std::os::unix::process::ExitStatusExt;
        assert!(open_status_result(std::process::ExitStatus::from_raw(0)).is_ok());
        let err =
            open_status_result(std::process::ExitStatus::from_raw(1 << 8)).expect_err("must fail");
        assert!(err.contains("cannot open the browser"), "got: {err}");
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
        // Asserts the production login.microsoftonline.com host, so
        // this holds the environment lock: a concurrent test that
        // overrides ORKA_ENDPOINT_AZURE_LOGIN must not run at the
        // same time (see vfs::endpoints::test_support).
        crate::vfs::endpoints::test_support::with_no_overrides(|| {
            let url = authorize_url(
                &Provider::Azure {
                    tenant_id: "my-tenant".to_string(),
                },
                "c",
                "http://127.0.0.1:1/cb",
                "s",
                "ch",
            );
            assert!(url
                .starts_with("https://login.microsoftonline.com/my-tenant/oauth2/v2.0/authorize?"));
            assert!(url.contains(&http::url_encode(
                "https://storage.azure.com/user_impersonation offline_access"
            )));
        });
    }

    #[test]
    fn azure_token_endpoint_uses_the_tenant() {
        // See the comment on the sibling authorize-URL test above.
        crate::vfs::endpoints::test_support::with_no_overrides(|| {
            let provider = Provider::Azure {
                tenant_id: "my-tenant".to_string(),
            };
            assert_eq!(
                provider.token_endpoint(),
                "https://login.microsoftonline.com/my-tenant/oauth2/v2.0/token"
            );
        });
    }

    #[test]
    fn azure_tenant_id_accepts_guid_and_domain_forms() {
        assert!(Provider::Azure {
            tenant_id: "11111111-2222-3333-4444-555555555555".to_string(),
        }
        .validate()
        .is_ok());
        assert!(Provider::Azure {
            tenant_id: "contoso.onmicrosoft.com".to_string(),
        }
        .validate()
        .is_ok());
        assert!(Provider::Azure {
            tenant_id: "under_score".to_string(),
        }
        .validate()
        .is_ok());
    }

    #[test]
    fn azure_tenant_id_rejects_empty_and_unexpected_characters() {
        let err = Provider::Azure {
            tenant_id: String::new(),
        }
        .validate()
        .expect_err("must fail");
        assert!(err.contains("invalid Azure tenant ID"), "got: {err}");

        let err = Provider::Azure {
            tenant_id: "tenant/../evil".to_string(),
        }
        .validate()
        .expect_err("must fail");
        assert!(err.contains("invalid Azure tenant ID"), "got: {err}");

        let err = Provider::Azure {
            tenant_id: "tenant?whoami".to_string(),
        }
        .validate()
        .expect_err("must fail");
        assert!(err.contains("invalid Azure tenant ID"), "got: {err}");
    }

    #[test]
    fn google_and_dropbox_have_no_tenant_id_to_validate() {
        assert!(Provider::Google.validate().is_ok());
        assert!(Provider::Dropbox.validate().is_ok());
    }

    #[test]
    fn refresh_rejects_a_malformed_tenant_id_before_building_a_url() {
        let set = TokenSet {
            access_token: "stale".to_string(),
            refresh_token: Some("r".to_string()),
            expires_at_ms: 0,
            client_secret: None,
        };
        let secrets = RecordingSecrets::seeded("conn", &set.to_json().unwrap());
        let bad = Provider::Azure {
            tenant_id: "tenant/../evil".to_string(),
        };
        let err = ensure_fresh_token(bad, "client", "conn", &secrets).expect_err("must fail");
        assert!(err.contains("invalid Azure tenant ID"), "got: {err}");
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
        let params =
            parse_redirect_request_line("GET /callback?error=access_denied&state=xyz HTTP/1.1\r\n");
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
    fn accept_redirect_skips_an_unrelated_request_then_parses_the_real_one() {
        // The browser's automatic favicon fetch on the redirect tab
        // carries neither `code` nor `state` and must not end the
        // sign-in flow; the real redirect that follows must still be
        // read and parsed.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = std::thread::spawn(move || {
            use std::io::Read;
            let mut probe = TcpStream::connect(addr).unwrap();
            probe
                .write_all(b"GET /favicon.ico HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                .unwrap();
            let mut probe_body = String::new();
            probe.read_to_string(&mut probe_body).unwrap();

            let mut real = TcpStream::connect(addr).unwrap();
            real.write_all(b"GET /callback?code=xyz&state=abc HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                .unwrap();
            let mut real_body = String::new();
            real.read_to_string(&mut real_body).unwrap();
            (probe_body, real_body)
        });
        let params = accept_redirect(&listener, Duration::from_secs(5)).unwrap();
        assert_eq!(params.code.as_deref(), Some("xyz"));
        let (probe_body, real_body) = client.join().unwrap();
        assert!(probe_body.starts_with("HTTP/1.1 404"), "{probe_body}");
        assert!(real_body.contains("Sign-in finished"), "{real_body}");
    }

    #[test]
    fn accept_redirect_times_out_when_nothing_connects() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let err = accept_redirect(&listener, Duration::from_millis(50)).unwrap_err();
        assert!(err.contains("timed out"), "got: {err}");
    }

    struct RecordingSecrets {
        stored: Mutex<HashMap<String, String>>,
        get_calls: Mutex<u32>,
    }

    impl RecordingSecrets {
        fn seeded(connection_id: &str, value: &str) -> Self {
            let mut map = HashMap::new();
            map.insert(connection_id.to_string(), value.to_string());
            Self {
                stored: Mutex::new(map),
                get_calls: Mutex::new(0),
            }
        }

        /// How many times [`SecretProvider::get_secret`] has run. Lets
        /// a test prove an in-memory cache skips the keychain instead
        /// of reading it on every request.
        fn get_call_count(&self) -> u32 {
            *self.get_calls.lock().unwrap()
        }
    }

    impl SecretProvider for RecordingSecrets {
        fn get_secret(&self, connection_id: &str) -> Option<String> {
            *self.get_calls.lock().unwrap() += 1;
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
        let fresh = ensure_fresh_token(Provider::Google, "client", "conn", &secrets).unwrap();
        assert_eq!(fresh.access_token, "still-good");
        assert_eq!(fresh.expires_at_ms, far_future);
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
    fn refresh_stored_token_fails_without_a_refresh_token_even_when_not_expired() {
        // A token that looks fresh must still be rejected under a
        // forced refresh: force exists precisely so a token the
        // server just rejected with a 401 is never resent unchanged.
        let far_future = now_ms() + 3_600_000;
        let set = TokenSet {
            access_token: "still-good".to_string(),
            refresh_token: None,
            expires_at_ms: far_future,
            client_secret: None,
        };
        let secrets = RecordingSecrets::seeded("conn", &set.to_json().unwrap());
        let err = refresh_stored_token(Provider::Google, "client", "conn", &secrets).unwrap_err();
        assert!(err.contains("no refresh token"), "got: {err}");
        assert!(err.contains("sign in again"), "got: {err}");
    }

    /// Returns a different secret on its second call. Simulates
    /// another thread refreshing the same connection while this one
    /// waits for the per-connection lock.
    struct SecretsThatChangeOnSecondRead {
        calls: Mutex<u32>,
        first: String,
        second: String,
    }

    impl SecretProvider for SecretsThatChangeOnSecondRead {
        fn get_secret(&self, _connection_id: &str) -> Option<String> {
            let mut calls = self.calls.lock().unwrap();
            *calls += 1;
            Some(if *calls == 1 {
                self.first.clone()
            } else {
                self.second.clone()
            })
        }
    }

    #[test]
    fn ensure_fresh_token_picks_up_a_concurrent_refresh_instead_of_rotating_again() {
        let expired = TokenSet {
            access_token: "old".to_string(),
            refresh_token: Some("r1".to_string()),
            expires_at_ms: 0,
            client_secret: None,
        };
        let refreshed_elsewhere = TokenSet {
            access_token: "new-from-other-thread".to_string(),
            refresh_token: Some("r2".to_string()),
            expires_at_ms: now_ms() + 3_600_000,
            client_secret: None,
        };
        let secrets = SecretsThatChangeOnSecondRead {
            calls: Mutex::new(0),
            first: expired.to_json().unwrap(),
            second: refreshed_elsewhere.to_json().unwrap(),
        };
        // If this incorrectly attempted a network refresh instead of
        // noticing the secret changed, it would fail (or hang) trying
        // to reach Google's real token endpoint with no mock server.
        let fresh = ensure_fresh_token(Provider::Google, "client", "conn-race", &secrets).unwrap();
        assert_eq!(fresh.access_token, "new-from-other-thread");
        assert_eq!(
            *secrets.calls.lock().unwrap(),
            2,
            "exactly the initial read and the post-lock re-read; no third call"
        );
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
            cache: Arc::new(Mutex::new(None)),
        };
        assert_eq!(source.token().unwrap(), "app-token");
    }

    #[test]
    fn token_source_oauth_app_caches_in_memory_between_requests() {
        let far_future = now_ms() + 3_600_000;
        let set = TokenSet {
            access_token: "app-token".to_string(),
            refresh_token: Some("r".to_string()),
            expires_at_ms: far_future,
            client_secret: None,
        };
        let secrets = Arc::new(RecordingSecrets::seeded("conn", &set.to_json().unwrap()));
        let source = TokenSource::OAuthApp {
            provider: Provider::Dropbox,
            client_id: "client".to_string(),
            connection_id: "conn".to_string(),
            secrets: secrets.clone(),
            cache: Arc::new(Mutex::new(None)),
        };
        assert_eq!(source.token().unwrap(), "app-token");
        assert_eq!(source.token().unwrap(), "app-token");
        assert_eq!(source.token().unwrap(), "app-token");
        assert_eq!(
            secrets.get_call_count(),
            1,
            "a fresh in-memory cache must skip the keychain on later requests"
        );
    }

    #[test]
    fn token_source_oauth_app_refresh_forces_even_when_not_expired() {
        let far_future = now_ms() + 3_600_000;
        let set = TokenSet {
            access_token: "app-token".to_string(),
            refresh_token: None,
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
            cache: Arc::new(Mutex::new(None)),
        };
        // token() returns the cached value; it looks fresh and needs
        // no refresh token to do so.
        assert_eq!(source.token().unwrap(), "app-token");
        // refresh() forces a renewal even though the token looks
        // fresh, and fails clearly because there is no refresh token
        // to renew it with. Before this fix, refresh() just called
        // token() and would have returned "app-token" unchanged.
        let err = source.refresh().unwrap_err();
        assert!(err.contains("no refresh token"), "got: {err}");
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
                .unwrap()
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
                .unwrap()
                .get(&format!("http://127.0.0.1:{port}/"))
                .call()
                .map(http::read_body_string)
        });
        assert_eq!(calls, 2, "must not retry a second time");
        assert!(result.unwrap_err().contains("401"));
    }

    // --- sign_in_with_opener ----------------------------------------------

    /// Splits `key=value` query pairs out of a URL's query string and
    /// percent-decodes each value, reusing the same decoder the real
    /// loopback redirect handler uses.
    fn query_pairs(url: &str) -> HashMap<String, String> {
        let query = url.split_once('?').map(|(_, q)| q).unwrap_or("");
        query
            .split('&')
            .filter_map(|pair| pair.split_once('='))
            .map(|(k, v)| (k.to_string(), percent_decode(v)))
            .collect()
    }

    /// A fake browser: reads `redirect_uri` and `state` off the
    /// authorize URL, then answers the loopback redirect on a
    /// separate thread with `code`, exactly as [`sign_in_with_opener`]
    /// requires (the opener itself must return before the listener
    /// accepts a connection).
    fn fake_browser_opener(code: &'static str) -> impl Fn(&str) -> Result<(), String> {
        move |url: &str| {
            let params = query_pairs(url);
            let redirect_uri = params
                .get("redirect_uri")
                .cloned()
                .ok_or_else(|| "authorize URL has no redirect_uri".to_string())?;
            let state = params
                .get("state")
                .cloned()
                .ok_or_else(|| "authorize URL has no state".to_string())?;
            let authority = redirect_uri
                .trim_start_matches("http://")
                .split('/')
                .next()
                .unwrap_or("")
                .to_string();
            std::thread::spawn(move || {
                let Ok(mut stream) = TcpStream::connect(&authority) else {
                    return;
                };
                let request = format!(
                    "GET /callback?state={state}&code={code} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
                );
                let _ = stream.write_all(request.as_bytes());
                let mut drain = Vec::new();
                let _ = std::io::Read::read_to_end(&mut stream, &mut drain);
            });
            Ok(())
        }
    }

    /// Serves one JSON token response on a local port and returns the
    /// port. Used as a fake `ORKA_ENDPOINT_GOOGLE_TOKEN` target so the
    /// code-exchange step in [`sign_in_with_opener`] has somewhere to
    /// reach.
    fn serve_token_response(body: &'static str) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let Ok((stream, _)) = listener.accept() else {
                return;
            };
            let mut reader = BufReader::new(stream.try_clone().expect("clone the stream"));
            let mut request_line = String::new();
            let _ = reader.read_line(&mut request_line);
            // The client is still writing its form-encoded body; a
            // response sent before that body is fully read can reset
            // the connection before the client reads the response.
            // Reading the exact Content-Length keeps both sides in
            // step.
            let mut content_length = 0usize;
            loop {
                let mut line = String::new();
                match reader.read_line(&mut line) {
                    Ok(0) => break,
                    Ok(_) if line == "\r\n" || line == "\n" => break,
                    Ok(_) => {
                        if let Some(rest) =
                            line.to_ascii_lowercase().strip_prefix("content-length:")
                        {
                            content_length = rest.trim().parse().unwrap_or(0);
                        }
                    }
                    Err(_) => break,
                }
            }
            let mut drained = vec![0u8; content_length];
            let _ = std::io::Read::read_exact(&mut reader, &mut drained);
            let mut stream = stream;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        });
        port
    }

    #[test]
    fn sign_in_with_opener_reaches_the_code_exchange() {
        use crate::vfs::endpoints::test_support::with_var;
        let body = r#"{"access_token":"tok-abc","refresh_token":"refresh-1","expires_in":3600}"#;
        let port = serve_token_response(body);
        let result = with_var(
            "ORKA_ENDPOINT_GOOGLE_TOKEN",
            &format!("http://127.0.0.1:{port}/token"),
            || {
                let opener = fake_browser_opener("abc");
                sign_in_with_opener(Provider::Google, "client-id", None, &opener)
            },
        );
        let token = result.expect("sign-in must reach and complete the code exchange");
        assert_eq!(token.access_token, "tok-abc");
        assert_eq!(token.refresh_token.as_deref(), Some("refresh-1"));
    }

    #[test]
    fn sign_in_with_opener_returns_an_opener_error_as_is() {
        // TokenSet carries no Debug impl (its client_secret is a
        // secret), so unwrap_err() is not available here.
        let opener = |_: &str| Err("browser is not available".to_string());
        let err = sign_in_with_opener(Provider::Google, "client-id", None, &opener)
            .err()
            .expect("must fail");
        assert_eq!(err, "browser is not available");
    }
}
