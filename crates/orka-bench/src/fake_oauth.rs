//! A fake OAuth 2.0 authorization server for tests.
//!
//! [`FakeOAuth`] serves the routes a real Google, Dropbox, or Azure
//! endpoint would: the PKCE authorize/token exchange, a refresh grant,
//! Azure's client-credentials grant, and Google's service-account
//! JWT-bearer grant. One running instance answers both a plain path
//! (`/authorize`, `/token`) and Azure's tenant-scoped path
//! (`/{tenant}/oauth2/v2.0/authorize`, `/{tenant}/oauth2/v2.0/token`),
//! so a test can stand this server in for any of the three providers.

use crate::fake_http::{Handler, Request, Response, Server};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::pkcs8::DecodePublicKey;
use rsa::sha2::Sha256;
use rsa::signature::Verifier;
use rsa::RsaPublicKey;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Settings for one [`FakeOAuth`] instance. Covers everything a test
/// needs to steer: the credentials it must present, how long a minted
/// access token lives, whether a refresh rotates the refresh token,
/// the key that verifies a service-account JWT, and whether PKCE is
/// required on the authorize step.
pub struct OAuthConfig {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub access_token_lifetime_secs: u64,
    pub rotate_refresh_tokens: bool,
    pub service_account_public_key_pem: Option<String>,
    pub require_pkce: bool,
}

impl OAuthConfig {
    /// Settings for `client_id`, with every other field at a
    /// reasonable default: no client secret, a one-hour access token,
    /// no refresh-token rotation, no service account configured, and
    /// PKCE required (the common case for every provider this fake
    /// stands in for).
    pub fn new(client_id: impl Into<String>) -> OAuthConfig {
        OAuthConfig {
            client_id: client_id.into(),
            ..OAuthConfig::default()
        }
    }

    /// Sets the client secret a token exchange must present.
    pub fn with_client_secret(mut self, client_secret: impl Into<String>) -> OAuthConfig {
        self.client_secret = Some(client_secret.into());
        self
    }

    /// Sets how long a minted access token stays valid.
    pub fn with_access_token_lifetime_secs(mut self, secs: u64) -> OAuthConfig {
        self.access_token_lifetime_secs = secs;
        self
    }

    /// Sets whether a refresh grant rotates the refresh token.
    pub fn with_rotate_refresh_tokens(mut self, rotate: bool) -> OAuthConfig {
        self.rotate_refresh_tokens = rotate;
        self
    }

    /// Sets the PEM public key that verifies a service-account
    /// JWT-bearer assertion.
    pub fn with_service_account_public_key_pem(mut self, pem: impl Into<String>) -> OAuthConfig {
        self.service_account_public_key_pem = Some(pem.into());
        self
    }

    /// Sets whether the authorize step requires a PKCE challenge.
    pub fn with_require_pkce(mut self, require: bool) -> OAuthConfig {
        self.require_pkce = require;
        self
    }
}

impl Default for OAuthConfig {
    fn default() -> OAuthConfig {
        OAuthConfig {
            client_id: String::new(),
            client_secret: None,
            access_token_lifetime_secs: 3600,
            rotate_refresh_tokens: false,
            service_account_public_key_pem: None,
            require_pkce: true,
        }
    }
}

/// The shared, mutable set of tokens this fake has issued. Kept
/// separate from the rest of the fake's state so a resource fake built
/// later (one that answers, say, fake Drive or Dropbox API calls) can
/// hold a clone and check bearer tokens against the same store this
/// server's `/token` route fills in.
#[derive(Clone, Default)]
pub struct TokenStore {
    inner: Arc<Mutex<TokenStoreState>>,
}

#[derive(Default)]
struct TokenStoreState {
    valid_access_tokens: HashSet<String>,
    valid_refresh_tokens: HashSet<String>,
}

impl TokenStore {
    fn new() -> TokenStore {
        TokenStore::default()
    }

    fn add_access_token(&self, token: &str) {
        self.inner.lock().unwrap().valid_access_tokens.insert(token.to_string());
    }

    fn add_refresh_token(&self, token: &str) {
        self.inner.lock().unwrap().valid_refresh_tokens.insert(token.to_string());
    }

    fn remove_refresh_token(&self, token: &str) {
        self.inner.lock().unwrap().valid_refresh_tokens.remove(token);
    }

    /// True when `token` is a refresh token this fake has issued and
    /// not yet invalidated.
    fn refresh_token_is_valid(&self, token: &str) -> bool {
        self.inner.lock().unwrap().valid_refresh_tokens.contains(token)
    }

    /// True when `token` is an access token this fake has issued and
    /// [`FakeOAuth::expire_access_token`] has not since revoked it.
    pub fn is_valid_access_token(&self, token: &str) -> bool {
        self.inner.lock().unwrap().valid_access_tokens.contains(token)
    }

    /// Marks an access token invalid immediately, without waiting for
    /// its lifetime to elapse. A resource fake built on top of this
    /// store can use this to force a client's next call down its
    /// 401-and-retry path deterministically instead of racing a timer.
    pub fn expire_access_token(&self, token: &str) {
        self.inner.lock().unwrap().valid_access_tokens.remove(token);
    }

    fn all_access_tokens(&self) -> Vec<String> {
        self.inner.lock().unwrap().valid_access_tokens.iter().cloned().collect()
    }
}

/// One authorization code this fake has minted, and what it takes to
/// redeem it.
struct IssuedCode {
    code_challenge: Option<String>,
    redirect_uri: String,
    used: bool,
}

/// State shared across every connection this fake serves.
struct OAuthState {
    config: OAuthConfig,
    codes: Mutex<HashMap<String, IssuedCode>>,
    grants: Mutex<Vec<String>>,
    tokens: TokenStore,
    /// This server's own `/token` URL, filled in once
    /// [`FakeOAuth::start`] knows the OS-assigned port. A JWT-bearer
    /// assertion's `aud` claim must equal this, the same way a real
    /// Google token endpoint only accepts an assertion audienced to
    /// itself. It starts empty because the port is not known until
    /// after the listener binds, which happens inside `Server::start`,
    /// after the handler (and so this state) already had to exist.
    own_token_url: OnceLock<String>,
}

/// A fake OAuth 2.0 authorization server bound to a loopback port.
pub struct FakeOAuth {
    server: Server,
    state: Arc<OAuthState>,
}

impl FakeOAuth {
    /// Starts the server on an OS-assigned loopback port.
    pub fn start(config: OAuthConfig) -> FakeOAuth {
        let state = Arc::new(OAuthState {
            config,
            codes: Mutex::new(HashMap::new()),
            grants: Mutex::new(Vec::new()),
            tokens: TokenStore::new(),
            own_token_url: OnceLock::new(),
        });
        let handler_state = Arc::clone(&state);
        let handler: Handler = Arc::new(move |req: &Request| route(req, &handler_state));
        let server = Server::start(handler);
        // The port is only known now that the listener has bound, so
        // the token URL a JWT-bearer assertion must be audienced to
        // can only be recorded here, after the handler closure above
        // already captured `state` by reference.
        let _ = state.own_token_url.set(format!("{}/token", server.base_url()));
        FakeOAuth { server, state }
    }

    /// This server's base URL.
    pub fn base_url(&self) -> String {
        self.server.base_url()
    }

    /// The bare authorize endpoint (`/authorize`).
    pub fn authorize_url(&self) -> String {
        format!("{}/authorize", self.base_url())
    }

    /// The bare token endpoint (`/token`).
    pub fn token_url(&self) -> String {
        format!("{}/token", self.base_url())
    }

    /// The Azure-style tenant-scoped token endpoint
    /// (`/{tenant}/oauth2/v2.0/token`).
    pub fn token_url_for_tenant(&self, tenant: &str) -> String {
        format!("{}/{tenant}/oauth2/v2.0/token", self.base_url())
    }

    /// True when `token` is a currently valid access token this fake
    /// issued.
    pub fn is_valid_access_token(&self, token: &str) -> bool {
        self.state.tokens.is_valid_access_token(token)
    }

    /// Marks an access token invalid immediately. See
    /// [`TokenStore::expire_access_token`].
    pub fn expire_access_token(&self, token: &str) {
        self.state.tokens.expire_access_token(token);
    }

    /// Marks a refresh token invalid immediately, so a later refresh
    /// grant using it is rejected.
    pub fn revoke_refresh_token(&self, token: &str) {
        self.state.tokens.remove_refresh_token(token);
    }

    /// Every access token this fake has issued and not since expired.
    pub fn issued_access_tokens(&self) -> Vec<String> {
        self.state.tokens.all_access_tokens()
    }

    /// The grant type of every `/token` call this fake has handled, in
    /// arrival order. Lets a test count, for example, how many
    /// refresh calls a client made.
    pub fn token_grants(&self) -> Vec<String> {
        self.state.grants.lock().unwrap().clone()
    }

    /// Every request this fake has received, in arrival order.
    pub fn requests(&self) -> Vec<Request> {
        self.server.requests()
    }

    /// A handle to this fake's token-validity store, shareable with a
    /// resource fake built later that needs to check bearer tokens
    /// against the same tokens this server issued.
    pub fn token_store(&self) -> TokenStore {
        self.state.tokens.clone()
    }
}

/// Dispatches one request to the authorize or token handler, in
/// either its bare or Azure tenant-scoped form.
fn route(req: &Request, state: &Arc<OAuthState>) -> Response {
    if let Some(tenant) = tenant_scoped_suffix(&req.path, "/oauth2/v2.0/authorize") {
        return handle_authorize(req, state, Some(&tenant));
    }
    if let Some(tenant) = tenant_scoped_suffix(&req.path, "/oauth2/v2.0/token") {
        return handle_token(req, state, Some(&tenant));
    }
    match req.path.as_str() {
        "/authorize" => handle_authorize(req, state, None),
        "/token" => handle_token(req, state, None),
        _ => Response::text(404, "not found"),
    }
}

/// Extracts the tenant segment from a path ending in `suffix`, e.g.
/// `("/mytenant/oauth2/v2.0/token", "/oauth2/v2.0/token")` yields
/// `Some("mytenant")`. Returns `None` for a path that does not end in
/// `suffix` at all, so [`route`] can tell a tenant-scoped request from
/// a bare one.
fn tenant_scoped_suffix(path: &str, suffix: &str) -> Option<String> {
    let tenant = path.strip_suffix(suffix)?;
    Some(tenant.trim_matches('/').to_string())
}

/// Handles `GET /authorize` (bare or tenant-scoped; the tenant itself
/// is not checked here, only on the `client_credentials` token grant).
fn handle_authorize(req: &Request, state: &Arc<OAuthState>, _tenant: Option<&str>) -> Response {
    let redirect_uri = req.query_param("redirect_uri").map(str::to_string);
    let state_param = req.query_param("state").map(str::to_string);

    let error = authorize_error(req, state);
    match (error, redirect_uri) {
        (None, Some(redirect_uri)) => {
            let code = random_token(24);
            state.codes.lock().unwrap().insert(
                code.clone(),
                IssuedCode {
                    code_challenge: req.query_param("code_challenge").map(str::to_string),
                    redirect_uri: redirect_uri.clone(),
                    used: false,
                },
            );
            let state_qs = state_param.as_deref().unwrap_or("");
            Response::redirect(&format!(
                "{redirect_uri}?code={}&state={}",
                url_encode(&code),
                url_encode(state_qs)
            ))
        }
        (Some(description), Some(redirect_uri)) => {
            let state_qs = state_param.as_deref().unwrap_or("");
            Response::redirect(&format!(
                "{redirect_uri}?error=invalid_request&error_description={}&state={}",
                url_encode(&description),
                url_encode(state_qs)
            ))
        }
        (error, None) => {
            // No redirect URI to send the error to; the only honest
            // reply is a direct 400.
            let description = error.unwrap_or_else(|| "redirect_uri is required".to_string());
            Response::json(
                400,
                &serde_json::json!({"error": "invalid_request", "error_description": description}),
            )
        }
    }
}

/// Validates an authorize request against `state.config`, returning a
/// human-readable description of the first problem found, or `None`
/// when the request is well-formed.
fn authorize_error(req: &Request, state: &Arc<OAuthState>) -> Option<String> {
    if req.query_param("client_id") != Some(state.config.client_id.as_str()) {
        return Some("client_id does not match".to_string());
    }
    if req.query_param("response_type") != Some("code") {
        return Some("response_type must be code".to_string());
    }
    let redirect_uri = req.query_param("redirect_uri")?;
    if !redirect_uri.starts_with("http://127.0.0.1:") {
        return Some("redirect_uri must be a loopback address".to_string());
    }
    if req.query_param("state").is_none() {
        return Some("state is required".to_string());
    }
    if state.config.require_pkce {
        if req.query_param("code_challenge").is_none() {
            return Some("code_challenge is required".to_string());
        }
        if req.query_param("code_challenge_method") != Some("S256") {
            return Some("code_challenge_method must be S256".to_string());
        }
    }
    None
}

/// Handles `POST /token` (bare or tenant-scoped), branching on the
/// form-encoded `grant_type`.
fn handle_token(req: &Request, state: &Arc<OAuthState>, tenant: Option<&str>) -> Response {
    let form = req.form();
    let get = |key: &str| form.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str());
    let grant_type = get("grant_type").unwrap_or("");
    state.grants.lock().unwrap().push(grant_type.to_string());

    match grant_type {
        "authorization_code" => handle_authorization_code_grant(state, get),
        "refresh_token" => handle_refresh_token_grant(state, get),
        "client_credentials" => handle_client_credentials_grant(state, get, tenant),
        "urn:ietf:params:oauth:grant-type:jwt-bearer" => handle_jwt_bearer_grant(state, get),
        _ => invalid_request(400, "unsupported_grant_type", "grant_type is not recognized"),
    }
}

/// A `400` error body in the shape every grant handler below uses.
fn invalid_request(status: u16, error: &str, description: &str) -> Response {
    Response::json(status, &serde_json::json!({"error": error, "error_description": description}))
}

fn handle_authorization_code_grant<'a>(
    state: &Arc<OAuthState>,
    get: impl Fn(&str) -> Option<&'a str>,
) -> Response {
    let Some(code) = get("code") else {
        return invalid_request(400, "invalid_request", "code is required");
    };
    let Some(code_verifier) = get("code_verifier") else {
        return invalid_request(400, "invalid_request", "code_verifier is required");
    };
    let Some(redirect_uri) = get("redirect_uri") else {
        return invalid_request(400, "invalid_request", "redirect_uri is required");
    };

    // The code is consumed on this lookup: a second exchange attempt
    // must fail even if every other field is correct, since a real
    // provider never lets an authorization code be redeemed twice.
    let issued = state.codes.lock().unwrap().remove(code);
    let Some(issued) = issued else {
        return invalid_request(400, "invalid_grant", "authorization code is unknown or already used");
    };
    if issued.used {
        return invalid_request(400, "invalid_grant", "authorization code was already used");
    }
    if issued.redirect_uri != redirect_uri {
        return invalid_request(400, "invalid_grant", "redirect_uri does not match the authorize request");
    }
    if let Some(challenge) = &issued.code_challenge {
        if !pkce_challenge_matches(challenge, code_verifier) {
            return invalid_request(400, "invalid_grant", "code_verifier does not match code_challenge");
        }
    }
    if let Some(error) = check_client_secret(state, &get) {
        return error;
    }

    let access_token = random_token(32);
    let refresh_token = random_token(32);
    state.tokens.add_access_token(&access_token);
    state.tokens.add_refresh_token(&refresh_token);
    Response::json(
        200,
        &serde_json::json!({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": state.config.access_token_lifetime_secs,
            "refresh_token": refresh_token,
        }),
    )
}

fn handle_refresh_token_grant<'a>(
    state: &Arc<OAuthState>,
    get: impl Fn(&str) -> Option<&'a str>,
) -> Response {
    let Some(refresh_token) = get("refresh_token") else {
        return invalid_request(400, "invalid_request", "refresh_token is required");
    };
    if !state.tokens.refresh_token_is_valid(refresh_token) {
        return invalid_request(400, "invalid_grant", "refresh_token is unknown or revoked");
    }
    if let Some(error) = check_client_secret(state, &get) {
        return error;
    }

    let access_token = random_token(32);
    state.tokens.add_access_token(&access_token);

    // Rotating invalidates the old refresh token and hands back a new
    // one, matching a provider that treats a refresh token as single
    // use. Not rotating omits `refresh_token` from the response
    // entirely: the client keeps using the one it already has, which
    // mirrors a provider that issues a refresh token only once and
    // expects the caller to hold onto it.
    let new_refresh_token = if state.config.rotate_refresh_tokens {
        state.tokens.remove_refresh_token(refresh_token);
        let new_token = random_token(32);
        state.tokens.add_refresh_token(&new_token);
        Some(new_token)
    } else {
        None
    };

    let mut body = serde_json::json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": state.config.access_token_lifetime_secs,
    });
    if let Some(new_refresh_token) = new_refresh_token {
        body["refresh_token"] = serde_json::Value::String(new_refresh_token);
    }
    Response::json(200, &body)
}

fn handle_client_credentials_grant<'a>(
    state: &Arc<OAuthState>,
    get: impl Fn(&str) -> Option<&'a str>,
    tenant: Option<&str>,
) -> Response {
    if let Some(tenant) = tenant {
        if tenant.is_empty() {
            return invalid_request(400, "invalid_request", "tenant is required");
        }
    }
    if get("client_id") != Some(state.config.client_id.as_str()) {
        return invalid_request(400, "invalid_client", "client_id does not match");
    }
    if get("client_secret") != state.config.client_secret.as_deref() {
        return invalid_request(400, "invalid_client", "client_secret does not match");
    }
    if get("scope").unwrap_or("").is_empty() {
        return invalid_request(400, "invalid_request", "scope is required");
    }

    let access_token = random_token(32);
    state.tokens.add_access_token(&access_token);
    Response::json(
        200,
        &serde_json::json!({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": state.config.access_token_lifetime_secs,
        }),
    )
}

fn handle_jwt_bearer_grant<'a>(
    state: &Arc<OAuthState>,
    get: impl Fn(&str) -> Option<&'a str>,
) -> Response {
    let Some(assertion) = get("assertion") else {
        return invalid_request(400, "invalid_request", "assertion is required");
    };
    let Some(public_key_pem) = &state.config.service_account_public_key_pem else {
        return invalid_request(400, "invalid_grant", "no service account public key is configured");
    };
    let expected_aud = state.own_token_url.get().map(String::as_str).unwrap_or("");
    match verify_jwt_bearer(assertion, public_key_pem, expected_aud) {
        Ok(()) => {
            let access_token = random_token(32);
            state.tokens.add_access_token(&access_token);
            Response::json(
                200,
                &serde_json::json!({
                    "access_token": access_token,
                    "token_type": "Bearer",
                    "expires_in": state.config.access_token_lifetime_secs,
                }),
            )
        }
        Err(description) => invalid_request(400, "invalid_grant", &description),
    }
}

/// Verifies a service-account JWT-bearer assertion: splits it into its
/// three dot-separated parts, checks the RS256 signature over
/// `header.claims` against `public_key_pem`, and checks `aud`, `exp`,
/// and `scope`.
fn verify_jwt_bearer(jwt: &str, public_key_pem: &str, expected_aud: &str) -> Result<(), String> {
    let mut parts = jwt.split('.');
    let header_b64 = parts.next().ok_or("assertion is not a JWT")?;
    let claims_b64 = parts.next().ok_or("assertion is not a JWT")?;
    let signature_b64 = parts.next().ok_or("assertion is not a JWT")?;
    if parts.next().is_some() {
        return Err("assertion has too many segments".to_string());
    }

    let claims_json = URL_SAFE_NO_PAD
        .decode(claims_b64)
        .map_err(|_| "assertion claims are not valid base64url".to_string())?;
    let claims: serde_json::Value = serde_json::from_slice(&claims_json)
        .map_err(|_| "assertion claims are not valid JSON".to_string())?;

    let scope = claims.get("scope").and_then(|v| v.as_str()).unwrap_or("");
    if scope.is_empty() {
        return Err("assertion scope is missing or empty".to_string());
    }
    let exp = claims.get("exp").and_then(|v| v.as_u64()).ok_or("assertion exp is missing")?;
    if exp <= now_secs() {
        return Err("assertion has expired".to_string());
    }
    let aud = claims.get("aud").and_then(|v| v.as_str()).unwrap_or("");
    if aud != expected_aud {
        return Err("assertion aud does not match the token endpoint".to_string());
    }

    let public_key = RsaPublicKey::from_public_key_pem(public_key_pem)
        .map_err(|_| "service account public key is not a valid PEM key".to_string())?;
    let verifying_key = VerifyingKey::<Sha256>::new(public_key);
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature_b64)
        .map_err(|_| "assertion signature is not valid base64url".to_string())?;
    let signature = Signature::try_from(signature_bytes.as_slice())
        .map_err(|_| "assertion signature is malformed".to_string())?;
    let signing_input = format!("{header_b64}.{claims_b64}");
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| "assertion signature does not verify".to_string())
}

/// Checks a form-encoded `client_secret` against `state.config`, when
/// the fake is configured to require one. Shared by the
/// authorization-code and refresh grants, which both accept a secret
/// the same way.
fn check_client_secret<'a>(
    state: &Arc<OAuthState>,
    get: &impl Fn(&str) -> Option<&'a str>,
) -> Option<Response> {
    match &state.config.client_secret {
        Some(expected) if get("client_secret") != Some(expected.as_str()) => {
            Some(invalid_request(400, "invalid_client", "client_secret does not match"))
        }
        _ => None,
    }
}

/// True when `code_verifier`'s SHA-256 digest, base64url-encoded
/// without padding, equals `challenge` — the S256 PKCE check from
/// RFC 7636.
fn pkce_challenge_matches(challenge: &str, code_verifier: &str) -> bool {
    use sha2::{Digest, Sha256 as Sha256Hasher};
    let digest = Sha256Hasher::digest(code_verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest) == challenge
}

/// A random base64url token (no padding) of `byte_len` raw bytes, used
/// for authorization codes and issued tokens. Falls back to a
/// timestamp-seeded value on the extremely unlikely chance the OS
/// CSPRNG call fails, since a fake server has no caller to propagate
/// that error to and must not panic a connection thread over it.
fn random_token(byte_len: usize) -> String {
    let mut buf = vec![0u8; byte_len];
    if getrandom::getrandom(&mut buf).is_err() {
        let fallback = now_secs().to_be_bytes();
        for (i, byte) in buf.iter_mut().enumerate() {
            *byte = fallback[i % fallback.len()];
        }
    }
    URL_SAFE_NO_PAD.encode(buf)
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Percent-encodes a query or redirect parameter value. Escapes
/// everything outside the unreserved RFC 3986 set so a code, state, or
/// error description with arbitrary bytes lands safely inside a URL.
fn url_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs1v15::SigningKey;
    use rsa::pkcs8::EncodePublicKey;
    use rsa::signature::{SignatureEncoding, Signer};
    use rsa::RsaPrivateKey;

    /// A PKCE verifier/challenge pair, built the same way the real
    /// client does, for driving the authorize/token round trip.
    struct Pkce {
        verifier: String,
        challenge: String,
    }

    fn generate_pkce() -> Pkce {
        let verifier = random_token(32);
        let digest = {
            use sha2::{Digest, Sha256};
            Sha256::digest(verifier.as_bytes())
        };
        let challenge = URL_SAFE_NO_PAD.encode(digest);
        Pkce { verifier, challenge }
    }

    /// Runs the authorize step and returns the authorization code from
    /// the redirect, following it manually so the query string is
    /// inspected directly rather than trusting `ureq` to chase a
    /// cross-origin redirect on its own.
    fn authorize_and_get_code(oauth: &FakeOAuth, pkce: &Pkce, redirect_uri: &str, state: &str) -> String {
        let url = format!(
            "{}?client_id={}&redirect_uri={}&response_type=code&state={}&code_challenge={}&code_challenge_method=S256",
            oauth.authorize_url(),
            oauth.state_client_id(),
            url_encode(redirect_uri),
            state,
            pkce.challenge,
        );
        // `redirects(0)` makes `ureq` hand back the 3xx response
        // itself instead of an error or a followed redirect, which is
        // what this helper needs: the `Location` header, unfollowed.
        let agent = ureq::AgentBuilder::new().redirects(0).build();
        let response = agent.get(&url).call().unwrap();
        assert_eq!(response.status(), 302, "expected a redirect from /authorize");
        let location = response.header("Location").unwrap().to_string();
        let query = location.split_once('?').unwrap().1;
        let params: HashMap<_, _> = query
            .split('&')
            .filter_map(|pair| pair.split_once('='))
            .collect();
        assert_eq!(params.get("state").copied(), Some(state));
        params.get("code").expect("redirect must carry a code").to_string()
    }

    impl FakeOAuth {
        /// Test-only accessor for the configured client id, so the
        /// authorize-URL builder above does not need its own copy.
        fn state_client_id(&self) -> &str {
            &self.state.config.client_id
        }
    }

    #[test]
    fn full_pkce_flow_issues_a_working_access_token() {
        let oauth = FakeOAuth::start(OAuthConfig::new("test-client"));
        let pkce = generate_pkce();
        let redirect_uri = "http://127.0.0.1:9/callback";
        let code = authorize_and_get_code(&oauth, &pkce, redirect_uri, "xyz");

        let response: serde_json::Value = ureq::post(&oauth.token_url())
            .send_form(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", redirect_uri),
                ("client_id", "test-client"),
                ("code_verifier", &pkce.verifier),
            ])
            .unwrap()
            .into_json()
            .unwrap();

        let access_token = response["access_token"].as_str().unwrap();
        assert!(oauth.is_valid_access_token(access_token));
        assert_eq!(response["token_type"], "Bearer");
    }

    #[test]
    fn wrong_code_verifier_is_rejected() {
        let oauth = FakeOAuth::start(OAuthConfig::new("test-client"));
        let pkce = generate_pkce();
        let redirect_uri = "http://127.0.0.1:9/callback";
        let code = authorize_and_get_code(&oauth, &pkce, redirect_uri, "xyz");

        let err = ureq::post(&oauth.token_url())
            .send_form(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", redirect_uri),
                ("client_id", "test-client"),
                ("code_verifier", "not-the-real-verifier"),
            ])
            .unwrap_err();
        assert!(matches!(err, ureq::Error::Status(400, _)));
    }

    #[test]
    fn refresh_with_rotation_invalidates_the_old_token() {
        let oauth = FakeOAuth::start(OAuthConfig::new("test-client").with_rotate_refresh_tokens(true));
        let pkce = generate_pkce();
        let redirect_uri = "http://127.0.0.1:9/callback";
        let code = authorize_and_get_code(&oauth, &pkce, redirect_uri, "xyz");
        let first: serde_json::Value = ureq::post(&oauth.token_url())
            .send_form(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", redirect_uri),
                ("client_id", "test-client"),
                ("code_verifier", &pkce.verifier),
            ])
            .unwrap()
            .into_json()
            .unwrap();
        let old_refresh = first["refresh_token"].as_str().unwrap().to_string();

        let second: serde_json::Value = ureq::post(&oauth.token_url())
            .send_form(&[("grant_type", "refresh_token"), ("refresh_token", &old_refresh)])
            .unwrap()
            .into_json()
            .unwrap();
        let new_refresh = second["refresh_token"].as_str().expect("rotation must return a new refresh token");
        assert_ne!(new_refresh, old_refresh);

        // The old refresh token must no longer work.
        let err = ureq::post(&oauth.token_url())
            .send_form(&[("grant_type", "refresh_token"), ("refresh_token", &old_refresh)])
            .unwrap_err();
        assert!(matches!(err, ureq::Error::Status(400, _)));

        // The new one must.
        ureq::post(&oauth.token_url())
            .send_form(&[("grant_type", "refresh_token"), ("refresh_token", new_refresh)])
            .unwrap();
    }

    #[test]
    fn refresh_without_rotation_keeps_the_same_refresh_token_working() {
        let oauth = FakeOAuth::start(OAuthConfig::new("test-client").with_rotate_refresh_tokens(false));
        let pkce = generate_pkce();
        let redirect_uri = "http://127.0.0.1:9/callback";
        let code = authorize_and_get_code(&oauth, &pkce, redirect_uri, "xyz");
        let first: serde_json::Value = ureq::post(&oauth.token_url())
            .send_form(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", redirect_uri),
                ("client_id", "test-client"),
                ("code_verifier", &pkce.verifier),
            ])
            .unwrap()
            .into_json()
            .unwrap();
        let refresh_token = first["refresh_token"].as_str().unwrap().to_string();

        let second: serde_json::Value = ureq::post(&oauth.token_url())
            .send_form(&[("grant_type", "refresh_token"), ("refresh_token", &refresh_token)])
            .unwrap()
            .into_json()
            .unwrap();
        assert!(second.get("refresh_token").is_none(), "a non-rotating refresh must omit refresh_token");

        // The same refresh token still works a second time.
        ureq::post(&oauth.token_url())
            .send_form(&[("grant_type", "refresh_token"), ("refresh_token", &refresh_token)])
            .unwrap();
    }

    #[test]
    fn client_credentials_grant_checks_the_secret() {
        let oauth = FakeOAuth::start(OAuthConfig::new("sp-client").with_client_secret("sp-secret"));

        let ok: serde_json::Value = ureq::post(&oauth.token_url_for_tenant("mytenant"))
            .send_form(&[
                ("grant_type", "client_credentials"),
                ("client_id", "sp-client"),
                ("client_secret", "sp-secret"),
                ("scope", "https://storage.azure.com/.default"),
            ])
            .unwrap()
            .into_json()
            .unwrap();
        assert!(ok["access_token"].as_str().is_some());

        let err = ureq::post(&oauth.token_url_for_tenant("mytenant"))
            .send_form(&[
                ("grant_type", "client_credentials"),
                ("client_id", "sp-client"),
                ("client_secret", "wrong-secret"),
                ("scope", "https://storage.azure.com/.default"),
            ])
            .unwrap_err();
        assert!(matches!(err, ureq::Error::Status(400, _)));
    }

    /// Builds a service-account-style JWT: `base64url(header) +
    /// "." + base64url(claims) + "." + base64url(signature)`, signed
    /// RS256, matching how the real client builds one. RSASSA-PKCS1-v1_5
    /// is deterministic, so signing needs no randomness, matching
    /// `orka-core`'s own `sign_rs256`.
    fn build_jwt(private_key: &RsaPrivateKey, aud: &str, scope: &str, exp: u64) -> String {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT"}"#);
        let claims = serde_json::json!({
            "iss": "svc@example.iam.gserviceaccount.com",
            "scope": scope,
            "aud": aud,
            "iat": 0,
            "exp": exp,
        })
        .to_string();
        let claims = URL_SAFE_NO_PAD.encode(claims);
        let signing_input = format!("{header}.{claims}");
        let signing_key = SigningKey::<Sha256>::new(private_key.clone());
        let signature = signing_key.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
    }

    #[test]
    fn jwt_bearer_grant_accepts_a_correctly_signed_assertion() {
        let private_key = RsaPrivateKey::new(&mut rand_core::OsRng, 2048).unwrap();
        let public_key_pem = private_key.to_public_key().to_public_key_pem(Default::default()).unwrap();
        let oauth = FakeOAuth::start(
            OAuthConfig::new("svc").with_service_account_public_key_pem(public_key_pem),
        );

        let jwt = build_jwt(&private_key, &oauth.token_url(), "https://www.googleapis.com/auth/drive", now_secs() + 3600);
        let response: serde_json::Value = ureq::post(&oauth.token_url())
            .send_form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", &jwt),
            ])
            .unwrap()
            .into_json()
            .unwrap();
        assert!(oauth.is_valid_access_token(response["access_token"].as_str().unwrap()));
    }

    #[test]
    fn jwt_bearer_grant_rejects_a_wrong_signing_key() {
        let private_key = RsaPrivateKey::new(&mut rand_core::OsRng, 2048).unwrap();
        let public_key_pem = private_key.to_public_key().to_public_key_pem(Default::default()).unwrap();
        let oauth = FakeOAuth::start(
            OAuthConfig::new("svc").with_service_account_public_key_pem(public_key_pem),
        );

        let other_key = RsaPrivateKey::new(&mut rand_core::OsRng, 2048).unwrap();
        let jwt = build_jwt(&other_key, &oauth.token_url(), "https://www.googleapis.com/auth/drive", now_secs() + 3600);
        let err = ureq::post(&oauth.token_url())
            .send_form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", &jwt),
            ])
            .unwrap_err();
        assert!(matches!(err, ureq::Error::Status(400, _)));
    }

    #[test]
    fn requests_are_logged() {
        let oauth = FakeOAuth::start(OAuthConfig::new("test-client"));
        let _ = ureq::get(&format!("{}/authorize?client_id=x", oauth.base_url())).call();
        assert!(!oauth.requests().is_empty());
    }
}
