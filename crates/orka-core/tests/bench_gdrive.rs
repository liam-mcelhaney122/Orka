//! Google Drive connector bench: the pasted-token, OAuth-app, and
//! service-account sign-in paths against a fake Drive v3 API and a
//! fake OAuth server.
//!
//! One fake Drive and one fake OAuth server serve the whole binary,
//! started once behind a [`OnceLock`]: `ORKA_ENDPOINT_GOOGLE_API` and
//! `ORKA_ENDPOINT_GOOGLE_TOKEN` are process-global, so two fakes
//! racing to set them would be a bug. Every test below carves out its
//! own uniquely named root folder (or, for a grant count, relies on
//! its grant type being the only test that ever uses it) so the tests
//! stay correct under the default parallel test runner, with no
//! `--test-threads=1` needed.

mod support;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use orka_bench::fake_drive::{DriveConfig, FakeDrive};
use orka_bench::fake_oauth::{FakeOAuth, OAuthConfig};
use orka_core::vfs::connections::{AuthMethod, BackendFactory, ConnectionConfig, SecretProvider};
use orka_core::vfs::gdrive::GdriveFactory;
use orka_core::vfs::http::url_encode;
use orka_core::vfs::oauth::TokenSet;
use orka_core::vfs::{FsBackend, Scheme};
use orka_core::ListOptions;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
use rsa::RsaPrivateKey;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use support::conformance;

/// The bearer token every test on the pasted-token sign-in path uses.
const PASTED_TOKEN: &str = "bench-pasted-token-abc123";

/// The client id the fake OAuth server and the OAuth-app connections
/// in this file both use.
const OAUTH_CLIENT_ID: &str = "bench-oauth-client";

/// The service-account JWT-bearer grant type string, as the token
/// endpoint reports it in [`FakeOAuth::token_grants`].
const JWT_BEARER_GRANT: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/// The refresh grant type string.
const REFRESH_GRANT: &str = "refresh_token";

/// The fakes and generated key material every test shares. Built once
/// per test binary run, since the endpoint overrides it configures
/// are process-wide environment variables.
struct Fixtures {
    drive: FakeDrive,
    oauth: FakeOAuth,
    /// PKCS8 PEM of the key whose public half the fake OAuth server
    /// verifies a service-account JWT against.
    service_account_private_key_pem: String,
}

fn fixtures() -> &'static Fixtures {
    static FIXTURES: OnceLock<Fixtures> = OnceLock::new();
    FIXTURES.get_or_init(|| {
        let private_key =
            RsaPrivateKey::new(&mut rand_core::OsRng, 2048).expect("generate an RSA test key");
        let public_key_pem = private_key
            .to_public_key()
            .to_public_key_pem(Default::default())
            .expect("encode the public key as PEM");
        let private_key_pem = private_key
            .to_pkcs8_pem(Default::default())
            .expect("encode the private key as PKCS8 PEM")
            .to_string();

        let oauth = FakeOAuth::start(
            OAuthConfig::new(OAUTH_CLIENT_ID).with_service_account_public_key_pem(public_key_pem),
        );

        // A low page size forces every listing bigger than a handful
        // of items across several pages, which is what the pagination
        // test below checks for. Every other test's listings stay
        // correct either way: the backend's own pagination loop keeps
        // following `nextPageToken` until it runs out.
        let drive = FakeDrive::start(DriveConfig {
            token_store: Some(oauth.token_store()),
            static_bearer: Some(PASTED_TOKEN.to_string()),
            page_size: 3,
        });

        // SAFETY: this closure runs exactly once, before any test
        // reads these variables, since it lives behind the `OnceLock`
        // every test goes through via `fixtures()`.
        unsafe {
            std::env::set_var("ORKA_ENDPOINT_GOOGLE_API", drive.base_url());
            std::env::set_var("ORKA_ENDPOINT_GOOGLE_TOKEN", oauth.token_url());
            std::env::set_var("ORKA_ENDPOINT_GOOGLE_AUTH", oauth.authorize_url());
        }

        Fixtures {
            drive,
            oauth,
            service_account_private_key_pem: private_key_pem,
        }
    })
}

/// A process-wide unique root folder name, so concurrently running
/// tests never share a Drive path.
fn unique_root(tag: &str) -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    format!("/bench-{tag}-{}", NEXT.fetch_add(1, Ordering::SeqCst))
}

/// An in-memory [`SecretProvider`] that also records every
/// [`SecretProvider::set_secret`] call, so a test can prove a token
/// refresh persisted its result.
struct RecordingSecrets {
    values: Mutex<HashMap<String, String>>,
    set_calls: Mutex<Vec<(String, String)>>,
}

impl RecordingSecrets {
    fn seeded(connection_id: &str, value: &str) -> RecordingSecrets {
        let mut values = HashMap::new();
        values.insert(connection_id.to_string(), value.to_string());
        RecordingSecrets {
            values: Mutex::new(values),
            set_calls: Mutex::new(Vec::new()),
        }
    }

    fn set_call_count(&self) -> usize {
        self.set_calls.lock().unwrap().len()
    }
}

impl SecretProvider for RecordingSecrets {
    fn get_secret(&self, connection_id: &str) -> Option<String> {
        self.values.lock().unwrap().get(connection_id).cloned()
    }

    fn set_secret(&self, connection_id: &str, value: &str) {
        self.values
            .lock()
            .unwrap()
            .insert(connection_id.to_string(), value.to_string());
        self.set_calls
            .lock()
            .unwrap()
            .push((connection_id.to_string(), value.to_string()));
    }
}

fn connection_config(id: &str, auth: AuthMethod) -> ConnectionConfig {
    ConnectionConfig {
        id: id.to_string(),
        display_name: "Bench Drive".to_string(),
        scheme: Scheme::Gdrive,
        host: "drive.google.com".to_string(),
        port: 443,
        username: "bench@example.com".to_string(),
        initial_path: "/".to_string(),
        auth,
    }
}

fn write_bytes(backend: &dyn FsBackend, path: &str, content: &[u8]) {
    let mut writer = backend
        .create_write(path, Some(content.len() as u64))
        .unwrap_or_else(|e| panic!("create_write failed for {path}: {e}"));
    writer
        .write_all(content)
        .unwrap_or_else(|e| panic!("write failed for {path}: {e}"));
    writer
        .finish()
        .unwrap_or_else(|e| panic!("finish failed for {path}: {e}"));
}

/// The count of `/token` grants of one grant type this fake has seen
/// so far. Every test below uses a grant type no other test in this
/// file triggers (`refresh_token` only from the OAuth-app test,
/// `urn:...jwt-bearer` only from the service-account test), so this
/// count stays correct even though every test shares one fake OAuth
/// server and the test runner runs tests in parallel.
fn grant_count(fx: &Fixtures, grant_type: &str) -> usize {
    fx.oauth
        .token_grants()
        .iter()
        .filter(|g| g.as_str() == grant_type)
        .count()
}

/// Runs the authorization-code PKCE flow against the shared fake OAuth
/// server and returns `(access_token, refresh_token)`. Used only to
/// mint a genuine, fake-recognized refresh token for the OAuth-app
/// test to seed as an already-expired stored token; the flow itself
/// (an `authorization_code` grant) is not what that test measures.
fn mint_oauth_app_token_pair(oauth: &FakeOAuth) -> (String, String) {
    let mut verifier_bytes = [0u8; 32];
    getrandom::getrandom(&mut verifier_bytes).expect("read random bytes for the PKCE verifier");
    let verifier = URL_SAFE_NO_PAD.encode(verifier_bytes);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let redirect_uri = "http://127.0.0.1:9/callback";

    let authorize_url = format!(
        "{}?client_id={OAUTH_CLIENT_ID}&redirect_uri={}&response_type=code&state=bench&code_challenge={challenge}&code_challenge_method=S256",
        oauth.authorize_url(),
        url_encode(redirect_uri),
    );
    // `redirects(0)` hands back the raw 302 instead of chasing a
    // redirect URI nothing is listening on.
    let agent = ureq::AgentBuilder::new().redirects(0).build();
    let response = agent
        .get(&authorize_url)
        .call()
        .expect("the authorize step must redirect");
    assert_eq!(
        response.status(),
        302,
        "expected a redirect from /authorize"
    );
    let location = response
        .header("Location")
        .expect("the redirect must carry a Location header")
        .to_string();
    let query = location
        .split_once('?')
        .expect("the redirect location must carry a query string")
        .1;
    let code = query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(key, _)| *key == "code")
        .map(|(_, value)| value.to_string())
        .expect("the redirect must carry an authorization code");

    let token_response: serde_json::Value = ureq::post(&oauth.token_url())
        .send_form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", redirect_uri),
            ("client_id", OAUTH_CLIENT_ID),
            ("code_verifier", &verifier),
        ])
        .expect("the code exchange must succeed")
        .into_json()
        .expect("the code exchange response must be JSON");
    let access_token = token_response["access_token"]
        .as_str()
        .expect("the code exchange must return an access token")
        .to_string();
    let refresh_token = token_response["refresh_token"]
        .as_str()
        .expect("the code exchange must return a refresh token")
        .to_string();
    (access_token, refresh_token)
}

/// True when `haystack` contains `needle` as a contiguous byte run.
/// Used to find the one upload request that carries a test's own
/// uniquely named file, among every upload request every concurrently
/// running test has sent to the shared fake.
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Test 1: the pasted-token sign-in path meets the shared conformance
/// suite.
#[test]
fn pasted_token_meets_the_conformance_suite() {
    let fx = fixtures();
    let root = unique_root("conformance");
    fx.drive.seed_folder(&root);

    let conn_id = "conn-pasted-token";
    let secrets = Arc::new(RecordingSecrets::seeded(conn_id, PASTED_TOKEN));
    let cfg = connection_config(conn_id, AuthMethod::OAuthToken);
    let backend = GdriveFactory
        .connect(&cfg, secrets)
        .expect("a pasted token must connect");

    conformance::exercise_backend(&*backend, &root);
}

/// Test 2: a listing bigger than one page comes back complete, and
/// the fake really was asked for more than one page.
#[test]
fn listing_paginates_across_multiple_pages() {
    let fx = fixtures();
    let root = unique_root("paginate");
    let folder_id = fx.drive.seed_folder(&root);
    for i in 0..7 {
        fx.drive.seed_file(
            &format!("{root}/file{i}.txt"),
            format!("body {i}").as_bytes(),
        );
    }

    let conn_id = "conn-paginate";
    let secrets = Arc::new(RecordingSecrets::seeded(conn_id, PASTED_TOKEN));
    let cfg = connection_config(conn_id, AuthMethod::OAuthToken);
    let backend = GdriveFactory.connect(&cfg, secrets).expect("must connect");

    let entries = backend
        .list_dir(&root, &ListOptions::default())
        .expect("list_dir must succeed");
    assert_eq!(
        entries.len(),
        7,
        "all seven files must come back: {entries:?}"
    );

    // Only a listing of this exact folder carries its id as the `q`
    // parent; the folder-resolution walk that finds the folder itself
    // queries under the shared root, not under `folder_id`, so it is
    // never counted here.
    let list_requests = fx
        .drive
        .requests()
        .into_iter()
        .filter(|r| r.method == "GET" && r.path == "/drive/v3/files")
        .filter(|r| r.query_param("q").is_some_and(|q| q.contains(&folder_id)))
        .count();
    assert_eq!(
        list_requests, 3,
        "seven items at a page size of three must take three requests"
    );
}

/// Test 3: an OAuth-app connection refreshes an expired token on its
/// first call, and the 401 retry path refreshes again after the
/// access token is revoked server-side.
#[test]
fn oauth_app_refreshes_on_first_call_and_after_a_401() {
    let fx = fixtures();
    let root = unique_root("oauthapp");
    fx.drive.seed_folder(&root);

    let (placeholder_access_token, refresh_token) = mint_oauth_app_token_pair(&fx.oauth);
    let expired = TokenSet {
        access_token: placeholder_access_token,
        refresh_token: Some(refresh_token),
        expires_at_ms: 0,
        client_secret: None,
    };
    let conn_id = "conn-oauth-app";
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
    let backend = GdriveFactory
        .connect(&cfg, secrets.clone())
        .expect("must connect");

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

    // Force the next call down the 401-and-retry path.
    let stored = TokenSet::from_json(&secrets.get_secret(conn_id).unwrap()).unwrap();
    fx.oauth.expire_access_token(&stored.access_token);

    let before_second = grant_count(fx, REFRESH_GRANT);
    backend
        .list_dir(&root, &ListOptions::default())
        .expect("the retry after a 401 must succeed");
    assert_eq!(
        grant_count(fx, REFRESH_GRANT) - before_second,
        1,
        "a revoked access token must trigger exactly one more refresh"
    );
}

/// Test 4: a service account signs and exchanges its own JWT, and
/// reuses the resulting access token instead of minting a new one on
/// every call.
#[test]
fn service_account_signs_once_and_reuses_the_token() {
    let fx = fixtures();
    let root = unique_root("serviceaccount");
    fx.drive.seed_folder(&root);

    let key_json = serde_json::json!({
        "type": "service_account",
        "client_email": "bench-svc@bench.iam.gserviceaccount.com",
        "private_key": fx.service_account_private_key_pem,
        "token_uri": fx.oauth.token_url(),
    })
    .to_string();
    let conn_id = "conn-service-account";
    let secrets = Arc::new(RecordingSecrets::seeded(conn_id, &key_json));
    let cfg = connection_config(conn_id, AuthMethod::ServiceAccount);
    let backend = GdriveFactory
        .connect(&cfg, secrets)
        .expect("a well-formed key must connect");

    let before = grant_count(fx, JWT_BEARER_GRANT);
    backend
        .list_dir(&root, &ListOptions::default())
        .expect("the first listing must succeed after signing a JWT");
    assert_eq!(
        grant_count(fx, JWT_BEARER_GRANT) - before,
        1,
        "the first call must sign and exchange exactly one JWT"
    );

    backend
        .list_dir(&root, &ListOptions::default())
        .expect("the second listing must succeed");
    assert_eq!(
        grant_count(fx, JWT_BEARER_GRANT) - before,
        1,
        "a cached token must not mint a second JWT"
    );
}

/// Test 5: renaming a folder drops its cached path so a later lookup
/// under the old path fails instead of silently reusing the stale id.
#[test]
fn rename_invalidates_the_folder_path_cache() {
    let fx = fixtures();
    let root = unique_root("cache");
    fx.drive.seed_folder(&root);

    let conn_id = "conn-cache";
    let secrets = Arc::new(RecordingSecrets::seeded(conn_id, PASTED_TOKEN));
    let cfg = connection_config(conn_id, AuthMethod::OAuthToken);
    let backend = GdriveFactory.connect(&cfg, secrets).expect("must connect");

    let old_dir = format!("{root}/old_dir");
    backend.mkdir(&old_dir).expect("mkdir must succeed");
    let old_file = format!("{old_dir}/inner.txt");
    write_bytes(&*backend, &old_file, b"content");

    // Resolving this file once populates the folder path cache for
    // `old_dir`, which is exactly the cache entry a rename must drop.
    backend
        .stat(&old_file)
        .expect("stat must populate the folder cache");

    let new_dir = format!("{root}/new_dir");
    backend
        .rename(&old_dir, &new_dir)
        .expect("rename must succeed");

    let new_file = format!("{new_dir}/inner.txt");
    let renamed_stat = backend
        .stat(&new_file)
        .expect("the file must resolve under the new path");
    assert_eq!(renamed_stat.name, "inner.txt");

    let stale_lookup = backend.stat(&old_file);
    assert!(
        stale_lookup.is_err(),
        "a stale cache entry must not resolve the old path after a rename, got: {stale_lookup:?}"
    );
}

/// Test 6: a file larger than one write buffer round-trips exactly,
/// and the create request the fake received used the multipart
/// upload content type the backend's `post_multipart` sends.
#[test]
fn large_file_round_trips_with_a_multipart_create() {
    let fx = fixtures();
    let root = unique_root("large");
    fx.drive.seed_folder(&root);

    let conn_id = "conn-large-file";
    let secrets = Arc::new(RecordingSecrets::seeded(conn_id, PASTED_TOKEN));
    let cfg = connection_config(conn_id, AuthMethod::OAuthToken);
    let backend = GdriveFactory.connect(&cfg, secrets).expect("must connect");

    // The root's own generated name is unique to this test binary
    // run, so using it as the file name lets the assertion below find
    // this exact upload among every concurrently running test's own
    // upload requests.
    let file_name = format!("{}.bin", root.trim_start_matches('/'));
    let path = format!("{root}/{file_name}");
    let size = 3 * 1024 * 1024;
    let mut data = vec![0u8; size];
    for (i, byte) in data.iter_mut().enumerate() {
        *byte = (i % 251) as u8;
    }
    write_bytes(&*backend, &path, &data);

    let mut reader = backend.open_read(&path).expect("open_read must succeed");
    let mut actual = Vec::new();
    reader
        .read_to_end(&mut actual)
        .expect("read_to_end must succeed");
    assert_eq!(actual, data, "the large file must round-trip exactly");

    let upload_request = fx
        .drive
        .requests()
        .into_iter()
        .find(|r| {
            r.method == "POST"
                && r.path == "/upload/drive/v3/files"
                && contains_bytes(&r.body, file_name.as_bytes())
        })
        .expect("the fake must have seen this test's multipart create request");
    let content_type = upload_request.header("content-type").unwrap_or("");
    assert!(
        content_type.starts_with("multipart/related"),
        "the create request must use a multipart/related content type, got: {content_type}"
    );
}
