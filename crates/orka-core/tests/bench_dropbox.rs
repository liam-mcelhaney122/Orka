//! Dropbox connector bench: the pasted-token and OAuth-app sign-in
//! paths against a fake Dropbox API and a fake OAuth server.
//!
//! One fake Dropbox and one fake OAuth server serve the whole binary,
//! started once behind a [`OnceLock`]: `ORKA_ENDPOINT_DROPBOX_API`,
//! `ORKA_ENDPOINT_DROPBOX_CONTENT`, and `ORKA_ENDPOINT_DROPBOX_TOKEN`
//! are process-global, so two fakes racing to set them would be a
//! bug. Every test below carves out its own uniquely named root
//! folder and, where a request carries no path of its own (a
//! `list_folder/continue` cursor, a refresh grant), relies on being
//! the only test that ever produces that particular traffic — noted
//! at each such assertion — so the tests stay correct under the
//! default parallel test runner, with no `--test-threads=1` needed.

mod support;

use orka_bench::fake_dropbox::{DropboxConfig, FakeDropbox};
use orka_bench::fake_oauth::{FakeOAuth, OAuthConfig};
use orka_core::vfs::connections::{AuthMethod, BackendFactory, ConnectionConfig, SecretProvider};
use orka_core::vfs::dropbox::DropboxFactory;
use orka_core::vfs::oauth::TokenSet;
use orka_core::vfs::Scheme;
use orka_core::ListOptions;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use support::conformance;

/// The bearer token every pasted-token test connects with, except
/// [`expired_pasted_token_reports_the_expired_hint`], which
/// deliberately uses a different one.
const PASTED_TOKEN: &str = "bench-pasted-token-abc123";

/// The OAuth client id the fake OAuth server and the OAuth-app
/// connections in this file both use.
const OAUTH_CLIENT_ID: &str = "bench-oauth-client";

/// The refresh grant type string, as the token endpoint reports it in
/// [`FakeOAuth::token_grants`].
const REFRESH_GRANT: &str = "refresh_token";

/// The fake Dropbox and fake OAuth server every test shares. Built
/// once per test binary run, since the endpoint overrides it
/// configures are process-wide environment variables.
struct Fixtures {
    dropbox: FakeDropbox,
    oauth: FakeOAuth,
}

fn fixtures() -> &'static Fixtures {
    static FIXTURES: OnceLock<Fixtures> = OnceLock::new();
    FIXTURES.get_or_init(|| {
        // Rotating refresh tokens lets the OAuth-app test observe
        // rotation without a second OAuth server.
        let oauth =
            FakeOAuth::start(OAuthConfig::new(OAUTH_CLIENT_ID).with_rotate_refresh_tokens(true));
        let dropbox = FakeDropbox::start(DropboxConfig {
            static_bearer: Some(PASTED_TOKEN.to_string()),
            token_store: Some(oauth.token_store()),
            // A low page size forces the pagination test below across
            // several pages. Every other test's listings stay correct
            // either way: the backend's own pagination loop keeps
            // following `has_more`/`cursor` until it runs out.
            page_size: 3,
        });
        // SAFETY: `OnceLock::get_or_init` runs this closure at most
        // once, and no test connects a backend before calling
        // `fixtures()` first, so no reader ever observes a partially
        // set environment.
        unsafe {
            std::env::set_var("ORKA_ENDPOINT_DROPBOX_API", dropbox.base_url());
            std::env::set_var("ORKA_ENDPOINT_DROPBOX_CONTENT", dropbox.base_url());
            std::env::set_var("ORKA_ENDPOINT_DROPBOX_TOKEN", oauth.token_url());
        }
        Fixtures { dropbox, oauth }
    })
}

/// A fresh, empty root folder (Dropbox path form) for one test, unique
/// across the whole binary run.
fn unique_root(label: &str) -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let root = format!("/{label}-{n}");
    fixtures().dropbox.seed_folder(&root);
    root
}

fn connection_config(id: &str, auth: AuthMethod) -> ConnectionConfig {
    ConnectionConfig {
        id: id.to_string(),
        display_name: "Dropbox".to_string(),
        scheme: Scheme::Dropbox,
        host: "dropbox.com".to_string(),
        port: 443,
        username: String::new(),
        initial_path: "/".to_string(),
        auth,
    }
}

/// An in-memory [`SecretProvider`] that records every `set_secret`
/// call, so a test can prove a token refresh wrote the new token set
/// back through the same seam the real keychain uses.
#[derive(Default)]
struct RecordingSecrets {
    stored: Mutex<HashMap<String, String>>,
    set_calls: Mutex<Vec<(String, String)>>,
}

impl RecordingSecrets {
    fn seeded(id: &str, value: &str) -> Self {
        let mut stored = HashMap::new();
        stored.insert(id.to_string(), value.to_string());
        Self {
            stored: Mutex::new(stored),
            set_calls: Mutex::new(Vec::new()),
        }
    }

    fn set_call_count(&self) -> usize {
        self.set_calls.lock().unwrap().len()
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
        self.set_calls
            .lock()
            .unwrap()
            .push((connection_id.to_string(), value.to_string()));
    }
}

/// How many `/token` calls of grant type `grant` the fake OAuth server
/// has handled so far, across the whole binary.
fn grant_count(fx: &Fixtures, grant: &str) -> usize {
    fx.oauth
        .token_grants()
        .iter()
        .filter(|g| g.as_str() == grant)
        .count()
}

// --- 1. Pasted token: conformance suite ---------------------------------

#[test]
fn pasted_token_meets_the_conformance_suite() {
    let root = unique_root("conformance");

    let conn_id = "conn-pasted-token";
    let secrets = Arc::new(RecordingSecrets::seeded(conn_id, PASTED_TOKEN));
    let cfg = connection_config(conn_id, AuthMethod::OAuthToken);
    let backend = DropboxFactory
        .connect(&cfg, secrets)
        .expect("a pasted token must connect");

    conformance::exercise_backend(&*backend, &root);
}

// --- 2. Pagination -------------------------------------------------------

/// Test 2: a listing bigger than one page comes back complete, and the
/// fake really was asked for more than one page.
///
/// No other test in this binary seeds more than `page_size` (3)
/// entries into one folder before listing it, so every
/// `list_folder/continue` call in this binary's whole run belongs to
/// this test; a plain total is safe with no per-test tagging needed.
#[test]
fn listing_paginates_across_multiple_continuation_pages() {
    let fx = fixtures();
    let root = unique_root("paginate");
    for i in 0..7 {
        fx.dropbox.seed_file(&format!("{root}/f{i}.txt"), b"x");
    }

    let conn_id = "conn-paginate";
    let secrets = Arc::new(RecordingSecrets::seeded(conn_id, PASTED_TOKEN));
    let cfg = connection_config(conn_id, AuthMethod::OAuthToken);
    let backend = DropboxFactory.connect(&cfg, secrets).expect("must connect");

    let entries = backend
        .list_dir(&root, &ListOptions::default())
        .expect("list_dir must succeed");
    assert_eq!(
        entries.len(),
        7,
        "all seven files must come back: {entries:?}"
    );

    // Only a listing of this exact folder carries its path as the
    // `list_folder` body, so that call is safe to attribute
    // precisely; see the function doc for why the continuation count
    // does not need the same per-test filter.
    let list_folder_calls = fx
        .dropbox
        .requests()
        .into_iter()
        .filter(|r| r.path == "/2/files/list_folder")
        .filter(|r| {
            r.json()
                .ok()
                .and_then(|b| b["path"].as_str().map(str::to_string))
                == Some(root.clone())
        })
        .count();
    assert_eq!(
        list_folder_calls, 1,
        "exactly one initial list_folder call for this root"
    );

    let continue_calls = fx
        .dropbox
        .requests()
        .into_iter()
        .filter(|r| r.path == "/2/files/list_folder/continue")
        .count();
    assert_eq!(
        continue_calls, 2,
        "seven entries at a page size of three must take two continuations"
    );
}

// --- 3. Chunked upload ---------------------------------------------------

/// Test 3: a file uploaded in several writes round-trips exactly, and
/// the fake saw a session start, at least one `append_v2`, and a
/// `finish` whose offsets are consistent with what was actually sent.
#[test]
fn large_file_round_trips_through_a_chunked_upload_session() {
    let fx = fixtures();
    let root = unique_root("chunked");
    let path = format!("{root}/large.bin");

    let conn_id = "conn-chunked";
    let secrets = Arc::new(RecordingSecrets::seeded(conn_id, PASTED_TOKEN));
    let cfg = connection_config(conn_id, AuthMethod::OAuthToken);
    let backend = DropboxFactory.connect(&cfg, secrets).expect("must connect");

    // `ChannelWriter::write` hands its whole buffer to the upload pump
    // as one chunk per call (see `dropbox.rs`), so three explicit
    // `write_all` calls below deterministically produce three
    // `append_v2` calls, with no dependency on an internal buffering
    // constant.
    let chunk_size = 300 * 1024;
    let chunk_a = vec![1u8; chunk_size];
    let chunk_b = vec![2u8; chunk_size];
    let chunk_c = vec![3u8; chunk_size / 2];
    let mut expected = Vec::new();
    expected.extend_from_slice(&chunk_a);
    expected.extend_from_slice(&chunk_b);
    expected.extend_from_slice(&chunk_c);

    {
        let mut writer = backend
            .create_write(&path, Some(expected.len() as u64))
            .expect("create_write must succeed");
        writer.write_all(&chunk_a).expect("write chunk a");
        writer.write_all(&chunk_b).expect("write chunk b");
        writer.write_all(&chunk_c).expect("write chunk c");
        writer.finish().expect("finish must succeed");
    }

    let mut reader = backend.open_read(&path).expect("open_read must succeed");
    let mut actual = Vec::new();
    reader
        .read_to_end(&mut actual)
        .expect("read the uploaded file");
    assert_eq!(
        actual, expected,
        "round-tripped content must match what was written"
    );

    // `path` is unique to this test, and only `upload_session/finish`
    // carries the destination path (in `commit.path`, inside the
    // `Dropbox-API-Arg` header), so filtering on it isolates this
    // test's finish call from any other test's concurrent upload.
    let finish_calls = requests_with_arg_matching("/2/files/upload_session/finish", |arg| {
        arg["commit"]["path"].as_str() == Some(path.as_str())
    });
    assert_eq!(
        finish_calls.len(),
        1,
        "exactly one finish call for this file"
    );
    let session_id = finish_calls[0]["cursor"]["session_id"]
        .as_str()
        .unwrap()
        .to_string();
    let finish_offset = finish_calls[0]["cursor"]["offset"].as_u64().unwrap();
    assert_eq!(
        finish_offset,
        expected.len() as u64,
        "finish must commit the full byte count"
    );

    // Every append_v2 for this exact session id (session ids are
    // random 128-bit tokens, so this is unambiguous even with other
    // uploads running concurrently).
    let append_calls = requests_with_arg_matching("/2/files/upload_session/append_v2", |arg| {
        arg["cursor"]["session_id"].as_str() == Some(session_id.as_str())
    });
    assert!(
        !append_calls.is_empty(),
        "at least one append_v2 call for this session"
    );
    let mut offsets: Vec<u64> = append_calls
        .iter()
        .map(|arg| arg["cursor"]["offset"].as_u64().unwrap())
        .collect();
    offsets.sort_unstable();
    assert_eq!(
        offsets.first().copied(),
        Some(0),
        "the first append must start at offset zero"
    );
    assert_eq!(
        offsets.last().copied(),
        Some(finish_offset),
        "the last append's offset must match what finish committed"
    );

    // The fake's session map only ever holds a session that
    // `upload_session/start` created, so a successful finish for this
    // session id is itself proof a start call happened for it.
    let _ = fx;
}

/// Every `Dropbox-API-Arg` header on `route`, parsed as JSON, for
/// which `matches` returns true.
fn requests_with_arg_matching(
    route: &str,
    matches: impl Fn(&serde_json::Value) -> bool,
) -> Vec<serde_json::Value> {
    fixtures()
        .dropbox
        .requests()
        .into_iter()
        .filter(|r| r.path == route)
        .filter_map(|r| {
            let arg: serde_json::Value = serde_json::from_str(r.header("dropbox-api-arg")?).ok()?;
            matches(&arg).then_some(arg)
        })
        .collect()
}

// --- 4. OAuth app: refresh on expiry, on a 401 retry, and rotation ------

/// Test 4: an OAuth-app connection refreshes an expired token on its
/// first call, refreshes again after a server-side revocation forces
/// a 401 retry, and (with refresh-token rotation on) stores the new
/// refresh token both times.
///
/// This is the only test in the binary that drives a `refresh_token`
/// grant, so a plain total across the fake OAuth server's whole run is
/// safe to use for the grant-count assertions below.
#[test]
fn oauth_app_refreshes_on_expiry_then_on_a_401_with_rotation() {
    let fx = fixtures();
    let root = unique_root("oauth-refresh");

    // The fake only trusts a refresh token it minted itself, so the
    // expired `TokenSet` below is seeded around one obtained through a
    // real (fake) authorization grant, not a made-up string.
    let refresh_token = mint_refresh_token(&fx.oauth);
    let conn_id = "conn-oauth-refresh";
    let expired = TokenSet {
        access_token: "stale-access-token".to_string(),
        refresh_token: Some(refresh_token.clone()),
        expires_at_ms: 0,
        client_secret: None,
    };
    let secrets = Arc::new(RecordingSecrets::seeded(
        conn_id,
        &expired.to_json().unwrap(),
    ));
    let cfg = connection_config(
        conn_id,
        AuthMethod::OAuthApp {
            client_id: OAUTH_CLIENT_ID.to_string(),
            tenant_id: String::new(),
        },
    );
    let backend = DropboxFactory
        .connect(&cfg, secrets.clone())
        .expect("must connect with a stored, expired token set");

    let before_first = grant_count(fx, REFRESH_GRANT);
    backend
        .list_dir(&root, &ListOptions::default())
        .expect("the first listing must succeed after refreshing the expired token");
    assert_eq!(
        grant_count(fx, REFRESH_GRANT) - before_first,
        1,
        "an expired stored token must refresh exactly once"
    );
    assert!(
        secrets.set_call_count() >= 1,
        "the refreshed token must be stored back through set_secret"
    );

    let after_first_refresh = TokenSet::from_json(&secrets.get_secret(conn_id).unwrap()).unwrap();
    assert_ne!(after_first_refresh.access_token, "stale-access-token");
    assert_ne!(
        after_first_refresh.refresh_token.as_deref(),
        Some(refresh_token.as_str()),
        "rotation must replace the refresh token on the very first refresh too"
    );

    // Force the next call down the 401-and-retry path.
    fx.oauth
        .expire_access_token(&after_first_refresh.access_token);

    let before_second = grant_count(fx, REFRESH_GRANT);
    backend
        .list_dir(&root, &ListOptions::default())
        .expect("the retry after a 401 must succeed");
    assert_eq!(
        grant_count(fx, REFRESH_GRANT) - before_second,
        1,
        "a revoked access token must trigger exactly one more refresh"
    );

    let after_second_refresh = TokenSet::from_json(&secrets.get_secret(conn_id).unwrap()).unwrap();
    assert_ne!(
        after_second_refresh.refresh_token.as_deref(),
        after_first_refresh.refresh_token.as_deref(),
        "the second, 401-triggered refresh must rotate the refresh token again"
    );
}

/// Runs a real authorization-code grant against the shared fake OAuth
/// server and returns the refresh token it issues.
fn mint_refresh_token(oauth: &FakeOAuth) -> String {
    let redirect_uri = "http://127.0.0.1:9/callback";
    let verifier = "a-code-verifier-that-is-at-least-43-characters-long";
    let challenge = pkce_challenge(verifier);
    let agent = ureq::AgentBuilder::new().redirects(0).build();
    let authorize_url = format!(
        "{}?client_id={}&redirect_uri={}&response_type=code&state=s&code_challenge={}&code_challenge_method=S256",
        oauth.authorize_url(),
        OAUTH_CLIENT_ID,
        percent_encode(redirect_uri),
        challenge,
    );
    let response = agent
        .get(&authorize_url)
        .call()
        .expect("authorize must redirect");
    assert_eq!(response.status(), 302);
    let location = response.header("Location").unwrap().to_string();
    let query = location.split_once('?').unwrap().1;
    let code = query
        .split('&')
        .find_map(|pair| pair.strip_prefix("code="))
        .expect("redirect must carry a code")
        .to_string();

    let token_response: serde_json::Value = ureq::post(&oauth.token_url())
        .send_form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", redirect_uri),
            ("client_id", OAUTH_CLIENT_ID),
            ("code_verifier", verifier),
        ])
        .expect("code exchange must succeed")
        .into_json()
        .unwrap();
    token_response["refresh_token"]
        .as_str()
        .unwrap()
        .to_string()
}

fn pkce_challenge(verifier: &str) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use sha2::{Digest, Sha256};
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// A minimal percent-encoder for the one query value this file needs
/// to build by hand: the loopback redirect URI in an authorize URL.
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

// --- 5. Expired pasted token ---------------------------------------------

/// Test 5: a bearer token the fake never validated is rejected with a
/// 401 whose message carries the expired-token hint `dropbox.rs`
/// adds.
#[test]
fn expired_pasted_token_reports_the_expired_hint() {
    let root = unique_root("expired-pasted");
    let conn_id = "conn-expired-pasted";
    // Neither the shared static token nor any token the shared OAuth
    // fake has minted: the shared fake's auth check rejects it.
    let secrets = Arc::new(RecordingSecrets::seeded(
        conn_id,
        "a-token-the-fake-never-issued",
    ));
    let cfg = connection_config(conn_id, AuthMethod::OAuthToken);
    let backend = DropboxFactory
        .connect(&cfg, secrets)
        .expect("connect never dials the network");

    let err = backend
        .stat(&root)
        .expect_err("a token the fake never validated must be rejected");
    assert!(err.contains("401"), "got: {err}");
    assert!(err.contains("expired"), "got: {err}");
}
