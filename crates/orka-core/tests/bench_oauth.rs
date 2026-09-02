//! Bench for the interactive OAuth PKCE sign-in flow
//! ([`orka_core::vfs::oauth::sign_in_with_opener`]), across all three
//! providers, against a fake OAuth server instead of a real browser
//! and a real identity provider.
//!
//! Each provider gets its own [`FakeOAuth`] and its own endpoint
//! override variables (`ORKA_ENDPOINT_GOOGLE_*`,
//! `ORKA_ENDPOINT_DROPBOX_*`, `ORKA_ENDPOINT_AZURE_LOGIN`), all set
//! once from [`fixtures`]. The mechanics tests (wrong state, a stray
//! connection, a provider error) do not depend on which provider they
//! run against, so they reuse the Google fake rather than starting a
//! fourth server; they only ever check for a match or an error
//! substring, never an exact call count, so sharing that fake with the
//! Google happy-path test is safe under the default parallel test
//! runner.
//!
//! Every opener below stands in for the system browser
//! [`sign_in_with_opener`] would otherwise launch: it must return
//! immediately, so the real HTTP work happens on a spawned thread,
//! exactly as the loopback listener requires (it only starts accepting
//! the redirect after the opener call returns).

use orka_bench::fake_oauth::{FakeOAuth, OAuthConfig};
use orka_core::vfs::oauth::{sign_in_with_opener, Provider};
use std::collections::HashMap;
use std::io::Write;
use std::net::TcpStream;
use std::sync::OnceLock;

const GOOGLE_CLIENT_ID: &str = "bench-google-client";
const DROPBOX_CLIENT_ID: &str = "bench-dropbox-client";
const AZURE_CLIENT_ID: &str = "bench-azure-client";
const AZURE_TENANT: &str = "bench-tenant";

struct Fixtures {
    google: FakeOAuth,
    dropbox: FakeOAuth,
    azure: FakeOAuth,
}

/// Starts the three fake OAuth servers and points every provider's
/// endpoint overrides at them. Runs exactly once for the whole binary:
/// the override variables are process-global, and
/// `sign_in_with_opener` reads them at call time, so every test must
/// resolve to this same set of servers.
fn fixtures() -> &'static Fixtures {
    static FIXTURES: OnceLock<Fixtures> = OnceLock::new();
    FIXTURES.get_or_init(|| {
        let google = FakeOAuth::start(OAuthConfig::new(GOOGLE_CLIENT_ID));
        let dropbox = FakeOAuth::start(OAuthConfig::new(DROPBOX_CLIENT_ID));
        let azure = FakeOAuth::start(OAuthConfig::new(AZURE_CLIENT_ID));

        // SAFETY: `OnceLock::get_or_init` runs this closure at most
        // once, and no test calls `sign_in_with_opener` before calling
        // `fixtures()` first, so no reader ever observes a partially
        // set environment.
        unsafe {
            std::env::set_var("ORKA_ENDPOINT_GOOGLE_AUTH", google.authorize_url());
            std::env::set_var("ORKA_ENDPOINT_GOOGLE_TOKEN", google.token_url());
            std::env::set_var("ORKA_ENDPOINT_DROPBOX_AUTH", dropbox.authorize_url());
            std::env::set_var("ORKA_ENDPOINT_DROPBOX_TOKEN", dropbox.token_url());
            // Azure's endpoints are per-tenant paths appended onto one
            // login origin (see `oauth::Provider::authorize_endpoint`
            // and `token_endpoint`); the override is that bare origin.
            std::env::set_var("ORKA_ENDPOINT_AZURE_LOGIN", azure.base_url());
        }
        Fixtures {
            google,
            dropbox,
            azure,
        }
    })
}

/// Splits `key=value` query pairs out of a URL's query string and
/// percent-decodes each value.
fn query_pairs(url: &str) -> HashMap<String, String> {
    let query = url.split_once('?').map(|(_, q)| q).unwrap_or("");
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .map(|(k, v)| (k.to_string(), percent_decode(v)))
        .collect()
}

/// Decodes `%XX` escapes and `+` as space. A malformed escape passes
/// through literally instead of failing the whole decode, matching the
/// decoder `oauth.rs` itself uses for the same redirect query string.
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

/// Percent-encodes a query or redirect parameter value.
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// Replaces one query parameter's value in `url`, leaving every other
/// parameter (and their relative order) unchanged.
fn replace_query_param(url: &str, key: &str, new_value: &str) -> String {
    let (base, query) = url.split_once('?').unwrap_or((url, ""));
    let rebuilt: Vec<String> = query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            if k == key {
                format!("{k}={}", percent_encode(new_value))
            } else {
                format!("{k}={v}")
            }
        })
        .collect();
    format!("{base}?{}", rebuilt.join("&"))
}

/// The `Location` header from an unfollowed redirect at `url`: the
/// real browser's first hop, from the provider's authorize endpoint to
/// the loopback `redirect_uri`.
fn follow_to_location(url: &str) -> Option<String> {
    let agent = ureq::AgentBuilder::new().redirects(0).build();
    let response = agent.get(url).call().ok()?;
    response.header("Location").map(str::to_string)
}

/// An opener that behaves exactly like a real browser: it requests the
/// authorize URL, follows the one redirect it gets back (without
/// `ureq` auto-following, so the `Location` header is inspected
/// directly) to the loopback `redirect_uri`, and requests that in
/// turn. Returns immediately; the two HTTP calls run on a spawned
/// thread, as every opener here must.
fn happy_path_opener() -> impl Fn(&str) -> Result<(), String> {
    move |authorize_url: &str| {
        let authorize_url = authorize_url.to_string();
        std::thread::spawn(move || {
            let Some(location) = follow_to_location(&authorize_url) else {
                return;
            };
            let _ = ureq::get(&location).call();
        });
        Ok(())
    }
}

/// Every request path segment that this file's fixture builder above
/// leaves fully general, filtered for the authorize step (the one
/// carrying `code_challenge_method`).
fn authorize_requests(fake: &FakeOAuth) -> Vec<orka_bench::fake_http::Request> {
    fake.requests()
        .into_iter()
        .filter(|r| r.path.ends_with("/authorize") || r.path.ends_with("/oauth2/v2.0/authorize"))
        .collect()
}

fn token_requests(fake: &FakeOAuth) -> Vec<orka_bench::fake_http::Request> {
    fake.requests()
        .into_iter()
        .filter(|r| r.path.ends_with("/token"))
        .collect()
}

/// Runs the happy-path opener for `provider` against `fake` and
/// checks: the returned token set is one `fake` considers valid, the
/// authorize step carried PKCE's `S256` challenge method, and the
/// token exchange carried `code_verifier`.
fn assert_happy_path(provider: Provider, client_id: &str, fake: &FakeOAuth) {
    let opener = happy_path_opener();
    let token =
        sign_in_with_opener(provider, client_id, None, &opener).expect("sign-in must succeed");
    assert!(
        fake.is_valid_access_token(&token.access_token),
        "the returned access token must be valid"
    );
    assert!(
        token.refresh_token.is_some(),
        "the authorization-code grant must also return a refresh token"
    );

    let authorize_calls = authorize_requests(fake);
    assert!(
        authorize_calls
            .iter()
            .any(|r| r.query_param("code_challenge_method") == Some("S256")),
        "the authorize step must carry PKCE's S256 challenge method"
    );
    let token_calls = token_requests(fake);
    assert!(
        token_calls
            .iter()
            .any(|r| r.form().iter().any(|(k, _)| k == "code_verifier")),
        "the token exchange must carry the PKCE code_verifier"
    );
}

// --- 1. Happy path, one test per provider -------------------------------

#[test]
fn google_happy_path_completes_sign_in() {
    let fx = fixtures();
    assert_happy_path(Provider::Google, GOOGLE_CLIENT_ID, &fx.google);
}

#[test]
fn dropbox_happy_path_completes_sign_in() {
    let fx = fixtures();
    assert_happy_path(Provider::Dropbox, DROPBOX_CLIENT_ID, &fx.dropbox);
}

#[test]
fn azure_happy_path_with_a_tenant_completes_sign_in() {
    let fx = fixtures();
    assert_happy_path(
        Provider::Azure {
            tenant_id: AZURE_TENANT.to_string(),
        },
        AZURE_CLIENT_ID,
        &fx.azure,
    );
}

// --- 2. Wrong state ------------------------------------------------------

/// An opener that behaves like a browser being handed a tampered
/// redirect: it follows the real authorize redirect, then delivers the
/// loopback callback with `state` replaced by a value the caller never
/// generated, before the callback ever reaches the loopback listener.
fn wrong_state_opener() -> impl Fn(&str) -> Result<(), String> {
    move |authorize_url: &str| {
        let authorize_url = authorize_url.to_string();
        std::thread::spawn(move || {
            let Some(location) = follow_to_location(&authorize_url) else {
                return;
            };
            let tampered = replace_query_param(&location, "state", "a-state-nobody-generated");
            let _ = ureq::get(&tampered).call();
        });
        Ok(())
    }
}

#[test]
fn a_mismatched_redirect_state_is_rejected() {
    let fx = fixtures();
    let opener = wrong_state_opener();
    let err = sign_in_with_opener(Provider::Google, GOOGLE_CLIENT_ID, None, &opener)
        .err()
        .expect("a mismatched state must fail sign-in");
    assert!(err.contains("state"), "got: {err}");
    let _ = fx;
}

// --- 3. A stray connection before the real redirect ----------------------

/// The host:port of the loopback `redirect_uri` an authorize URL
/// carries, e.g. `"127.0.0.1:54321"` from
/// `redirect_uri=http://127.0.0.1:54321/callback`.
fn redirect_authority(authorize_url: &str) -> Option<String> {
    let redirect_uri = query_pairs(authorize_url).get("redirect_uri")?.clone();
    let after_scheme = redirect_uri.trim_start_matches("http://");
    after_scheme.split('/').next().map(str::to_string)
}

/// An opener that first opens a throwaway connection to the loopback
/// listener and sends an unrelated request (mimicking, say, the
/// browser's own favicon probe on the redirect tab), then completes
/// the real flow exactly as [`happy_path_opener`] does. The listener
/// must not end the sign-in on the stray connection: only a request
/// carrying `code` or `state` may do that.
fn stray_connection_then_happy_path_opener() -> impl Fn(&str) -> Result<(), String> {
    move |authorize_url: &str| {
        let authorize_url = authorize_url.to_string();
        std::thread::spawn(move || {
            if let Some(authority) = redirect_authority(&authorize_url) {
                if let Ok(mut stream) = TcpStream::connect(&authority) {
                    let _ = stream.write_all(b"GET / HTTP/1.0\r\nConnection: close\r\n\r\n");
                }
            }
            let Some(location) = follow_to_location(&authorize_url) else {
                return;
            };
            let _ = ureq::get(&location).call();
        });
        Ok(())
    }
}

#[test]
fn a_stray_connection_before_the_redirect_does_not_end_the_sign_in() {
    let fx = fixtures();
    let opener = stray_connection_then_happy_path_opener();
    let token = sign_in_with_opener(Provider::Google, GOOGLE_CLIENT_ID, None, &opener)
        .expect("the real redirect, once it arrives, must still complete sign-in");
    assert!(fx.google.is_valid_access_token(&token.access_token));
}

// --- 4. No redirect at all: the sign-in times out ------------------------

/// `sign_in_with_opener`'s loopback wait is a fixed five minutes
/// (`oauth::LOOPBACK_TIMEOUT`, private to that module and not exposed
/// through any test hook or environment override), so there is no way
/// to shorten it from a test. This is left `#[ignore]`, documenting
/// the timeout behavior without paying its cost on every run; run it
/// explicitly with `cargo test -- --ignored` to see it wait out the
/// real five minutes.
#[test]
#[ignore = "waits out oauth::LOOPBACK_TIMEOUT (5 minutes); no test hook shortens it"]
fn no_redirect_times_out() {
    let opener = |_url: &str| Ok(());
    let err = sign_in_with_opener(Provider::Google, GOOGLE_CLIENT_ID, None, &opener)
        .err()
        .expect("no redirect ever arriving must eventually fail");
    assert!(err.contains("timed out"), "got: {err}");
}

// --- 5. Provider error ----------------------------------------------------

/// An opener simulating a provider that never issues a code at all
/// (the user declined consent): it reads `redirect_uri` and `state`
/// directly off the authorize URL (the way a real provider's own
/// redirect would carry them) and answers the loopback listener with
/// `error=access_denied`, without visiting the fake authorize endpoint.
fn provider_denies_opener() -> impl Fn(&str) -> Result<(), String> {
    move |authorize_url: &str| {
        let params = query_pairs(authorize_url);
        let redirect_uri = params.get("redirect_uri").cloned().unwrap_or_default();
        let state = params.get("state").cloned().unwrap_or_default();
        std::thread::spawn(move || {
            let callback = format!(
                "{redirect_uri}?error=access_denied&state={}",
                percent_encode(&state)
            );
            let _ = ureq::get(&callback).call();
        });
        Ok(())
    }
}

#[test]
fn a_provider_error_is_reported() {
    let fx = fixtures();
    let opener = provider_denies_opener();
    let err = sign_in_with_opener(Provider::Google, GOOGLE_CLIENT_ID, None, &opener)
        .err()
        .expect("a provider-side denial must fail sign-in");
    assert!(err.contains("access_denied"), "got: {err}");
    let _ = fx;
}
