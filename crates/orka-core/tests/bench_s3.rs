//! S3 connector bench.
//!
//! Runs the S3 backend against a real `s3s-fs` server, so every request
//! this backend signs passes through a real SigV4 check instead of a
//! hand-rolled stand-in. Two `s3s-fs` instances run for the life of
//! this test binary: one with `SimpleAuth` for every signed-credential
//! path, and one with no auth provider at all for the
//! [`AuthMethod::None`] (anonymous) path. A fake STS server and a fake
//! SSO portal cover the `role_arn` and SSO branches of
//! [`AuthMethod::S3Profile`].
//!
//! [`FIXTURES`] starts every fake server exactly once and points the
//! `HOME`, `ORKA_ENDPOINT_STS`, and `ORKA_ENDPOINT_SSO_PORTAL`
//! environment variables at them before any test runs; nothing in this
//! file changes those variables again afterward, since they are
//! process-wide and every test in this binary can run concurrently.
//! Each test creates its own uniquely named bucket (a subdirectory
//! under the authenticated server's storage root) so tests never
//! interfere with each other.

mod support;

use orka_bench::fake_aws::{FakeSsoPortal, FakeSts, IssuedKeys};
use orka_bench::fake_http::{Request, Response, Server};
use orka_core::vfs::connections::{AuthMethod, BackendFactory, ConnectionConfig, SecretProvider};
use orka_core::vfs::s3::S3Factory;
use orka_core::vfs::{FsBackend, Scheme};
use orka_core::ListOptions;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use tempfile::TempDir;

/// The access key and secret key the authenticated `s3s-fs` server
/// accepts. Every credential path that must actually work end to end
/// (static keys, a session token, `credential_process`, an assumed
/// role, an SSO federation) resolves to this same pair, since that is
/// the only pair the server will sign a successful response for.
const MAIN_ACCESS_KEY: &str = "AKIAORKABENCHMAINKEY";
const MAIN_SECRET_KEY: &str = "orka-bench-main-secret-key";

/// The role ARN the `role-assume` profile requests and the only one
/// the fake STS server accepts.
const ROLE_ARN: &str = "arn:aws:iam::123456789012:role/OrkaBenchRole";

/// The SSO portal's expected bearer token, account, and role. The
/// cached token file on disk carries this same bearer token.
const SSO_START_URL: &str = "https://orka-bench.awsapps.com/start";
const SSO_BEARER_TOKEN: &str = "orka-bench-sso-bearer-token";
const SSO_ACCOUNT_ID: &str = "123456789012";
const SSO_ROLE_NAME: &str = "OrkaBenchRole";

/// Every fake server this bench needs, started once for the whole test
/// binary. See the module doc comment for why this must be a single,
/// shared `OnceLock`.
struct Fixtures {
    auth_port: u16,
    auth_root: PathBuf,
    anon_port: u16,
    anon_root: PathBuf,
    sts: FakeSts,
    sso: FakeSsoPortal,
    // Kept alive for the process's life: the servers above serve out
    // of these directories, and a `TempDir` removes its directory on
    // drop.
    _auth_root_dir: TempDir,
    _anon_root_dir: TempDir,
    _home_dir: TempDir,
}

fn fixtures() -> &'static Fixtures {
    static FIXTURES: OnceLock<Fixtures> = OnceLock::new();
    FIXTURES.get_or_init(Fixtures::start)
}

impl Fixtures {
    fn start() -> Fixtures {
        let auth_root_dir =
            TempDir::new().expect("create the authenticated S3 server's storage root");
        let auth_port = spawn_s3s_server(
            auth_root_dir.path().to_path_buf(),
            Some((MAIN_ACCESS_KEY.to_string(), MAIN_SECRET_KEY.to_string())),
        );

        let anon_root_dir = TempDir::new().expect("create the anonymous S3 server's storage root");
        let anon_port = spawn_s3s_server(anon_root_dir.path().to_path_buf(), None);

        let sts = FakeSts::start(
            ROLE_ARN,
            IssuedKeys {
                access_key: MAIN_ACCESS_KEY.to_string(),
                secret_key: MAIN_SECRET_KEY.to_string(),
                session_token: "orka-bench-assumed-role-token".to_string(),
            },
        );
        let sso = FakeSsoPortal::start(
            SSO_BEARER_TOKEN,
            IssuedKeys {
                access_key: MAIN_ACCESS_KEY.to_string(),
                secret_key: MAIN_SECRET_KEY.to_string(),
                session_token: "orka-bench-sso-token".to_string(),
            },
        );

        let home_dir = TempDir::new().expect("create a fake HOME for the AWS profile tests");
        write_aws_files(home_dir.path());

        // SAFETY: this closure runs exactly once, inside
        // `OnceLock::get_or_init`, before any test in this binary reads
        // `HOME`, `ORKA_ENDPOINT_STS`, or `ORKA_ENDPOINT_SSO_PORTAL`.
        // Nothing else in this binary calls `set_var` for any of them
        // afterward, so no test ever observes a half-set variable or a
        // change made after it already read one.
        unsafe {
            std::env::set_var("HOME", home_dir.path());
            std::env::set_var("ORKA_ENDPOINT_STS", sts.base_url());
            std::env::set_var("ORKA_ENDPOINT_SSO_PORTAL", sso.base_url());
        }

        Fixtures {
            auth_port,
            auth_root: auth_root_dir.path().to_path_buf(),
            anon_port,
            anon_root: anon_root_dir.path().to_path_buf(),
            sts,
            sso,
            _auth_root_dir: auth_root_dir,
            _anon_root_dir: anon_root_dir,
            _home_dir: home_dir,
        }
    }
}

/// Writes the `~/.aws/config`, `~/.aws/credentials`, and SSO token
/// cache files every `S3Profile` test in this file reads. One shared
/// set of files, since `HOME` is set once for the whole binary.
fn write_aws_files(home: &Path) {
    let aws_dir = home.join(".aws");
    std::fs::create_dir_all(&aws_dir).expect("create ~/.aws");

    // Static keys and a session-token variant both resolve to the main
    // server's key pair, so a successful list/read proves the profile
    // path actually works end to end. `role-source` only signs the
    // AssumeRole call to the fake STS server, which does not check the
    // signature cryptographically, so its keys never need to match
    // anything real.
    let credentials = format!(
        "[static-keys]\n\
         aws_access_key_id = {MAIN_ACCESS_KEY}\n\
         aws_secret_access_key = {MAIN_SECRET_KEY}\n\
         \n\
         [session-token]\n\
         aws_access_key_id = {MAIN_ACCESS_KEY}\n\
         aws_secret_access_key = {MAIN_SECRET_KEY}\n\
         aws_session_token = orka-bench-static-session-token\n\
         \n\
         [role-source]\n\
         aws_access_key_id = AKIDROLESOURCEONLY001\n\
         aws_secret_access_key = role-source-secret-key\n"
    );
    std::fs::write(aws_dir.join("credentials"), credentials).expect("write ~/.aws/credentials");

    // The credential_process command is a literal `printf`, not a
    // script file: `run_command_with_timeout` runs a profile's
    // credential_process through `sh -c`, so an inline command needs
    // no separate executable file on disk.
    let config = format!(
        "[profile cred-process]\n\
         credential_process = printf '{{\"Version\":1,\"AccessKeyId\":\"{MAIN_ACCESS_KEY}\",\"SecretAccessKey\":\"{MAIN_SECRET_KEY}\"}}'\n\
         \n\
         [profile role-assume]\n\
         role_arn = {ROLE_ARN}\n\
         source_profile = role-source\n\
         region = us-east-1\n\
         \n\
         [profile sso-profile]\n\
         sso_start_url = {SSO_START_URL}\n\
         sso_region = us-east-1\n\
         sso_account_id = {SSO_ACCOUNT_ID}\n\
         sso_role_name = {SSO_ROLE_NAME}\n"
    );
    std::fs::write(aws_dir.join("config"), config).expect("write ~/.aws/config");

    // The AWS CLI names this file by a hash of the start URL; the
    // backend's own cache scan matches on the `startUrl` field inside
    // the file, not the filename, so any name ending in `.json` works.
    let cache_dir = aws_dir.join("sso").join("cache");
    std::fs::create_dir_all(&cache_dir).expect("create ~/.aws/sso/cache");
    let cache_entry = serde_json::json!({
        "startUrl": SSO_START_URL,
        "accessToken": SSO_BEARER_TOKEN,
        "expiresAt": "2999-01-01T00:00:00Z",
    });
    std::fs::write(
        cache_dir.join("orka-bench-cached-token.json"),
        cache_entry.to_string(),
    )
    .expect("write the cached SSO token");
}

/// Starts one `s3s-fs` server, backed by `root`, on its own tokio
/// runtime and OS thread, and returns the OS-assigned loopback port it
/// bound. The server runs for the rest of the process's life: a test
/// binary has no teardown step that needs it to stop.
///
/// `auth` is `Some((access_key, secret_key))` for the authenticated
/// server, `None` for the anonymous one; see
/// [`s3s::service::S3ServiceBuilder::set_auth`].
fn spawn_s3s_server(root: PathBuf, auth: Option<(String, String)>) -> u16 {
    let (port_tx, port_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Runtime::new()
            .expect("cannot start a tokio runtime for the fake S3 server");
        runtime.block_on(run_s3s_server(root, auth, port_tx));
    });
    port_rx
        .recv()
        .expect("the fake S3 server thread exited before it reported its port")
}

/// The accept loop for one `s3s-fs` server. Follows the same
/// `hyper-util` auto-builder pattern `s3s-fs`'s own binary uses: one
/// `TokioIo`-wrapped connection per accepted socket, served on its own
/// spawned task so a slow client never blocks the next accept.
async fn run_s3s_server(
    root: PathBuf,
    auth: Option<(String, String)>,
    port_tx: std::sync::mpsc::Sender<u16>,
) {
    let fs = s3s_fs::FileSystem::new(&root).unwrap_or_else(|e| {
        panic!(
            "cannot open the fake S3 server's storage root {}: {e:?}",
            root.display()
        )
    });
    let mut builder = s3s::service::S3ServiceBuilder::new(fs);
    if let Some((access_key, secret_key)) = auth {
        builder.set_auth(s3s::auth::SimpleAuth::from_single(access_key, secret_key));
    }
    let service = builder.build();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("cannot bind a loopback port for the fake S3 server");
    let port = listener
        .local_addr()
        .expect("bound socket has no local address")
        .port();
    port_tx
        .send(port)
        .expect("the test thread is gone before the fake S3 server could report its port");

    let http_server =
        hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
    loop {
        let Ok((socket, _)) = listener.accept().await else {
            continue;
        };
        let io = hyper_util::rt::TokioIo::new(socket);
        // `into_owned` drops the connection's borrow of `http_server`,
        // which a spawned task needs: the task can outlive this loop
        // iteration, so its future must not borrow a local.
        let conn = http_server
            .serve_connection(io, service.clone())
            .into_owned();
        tokio::spawn(async move {
            let _ = conn.await;
        });
    }
}

/// Creates a bucket (a directory) under the authenticated server's
/// storage root and returns its name. Every test picks its own
/// distinct name so concurrently running tests never share a bucket.
fn create_bucket(name: &str) -> String {
    let dir = fixtures().auth_root.join(name);
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("create the bucket {name}: {e}"));
    name.to_string()
}

/// Hands back a fixed secret for every connection id, the way a real
/// keychain would for a single saved connection.
struct StaticSecret(Option<String>);

impl SecretProvider for StaticSecret {
    fn get_secret(&self, _connection_id: &str) -> Option<String> {
        self.0.clone()
    }
}

/// Builds a connection config against a loopback S3 endpoint. `host` is
/// always `127.0.0.1`, so the backend always sends plain HTTP (see
/// `endpoints::scheme_for_host`).
fn config_for(port: u16, username: &str, auth: AuthMethod) -> ConnectionConfig {
    ConnectionConfig {
        id: "bench-s3".to_string(),
        display_name: "bench s3".to_string(),
        scheme: Scheme::S3,
        host: "127.0.0.1".to_string(),
        port: u32::from(port),
        username: username.to_string(),
        initial_path: "/".to_string(),
        auth,
    }
}

/// Builds an S3 backend from `config`, panicking with the connect
/// error on failure so a broken fixture fails the first test that
/// touches it with a clear message.
fn connect_s3(config: ConnectionConfig, secret: Option<&str>) -> Arc<dyn FsBackend> {
    let secrets: Arc<dyn SecretProvider> = Arc::new(StaticSecret(secret.map(str::to_string)));
    S3Factory
        .connect(&config, secrets)
        .unwrap_or_else(|e| panic!("connect to the fake S3 server failed: {e}"))
}

fn write_object(backend: &dyn FsBackend, path: &str, content: &[u8]) {
    let mut writer = backend
        .create_write(path, Some(content.len() as u64))
        .unwrap_or_else(|e| panic!("create_write {path}: {e}"));
    writer
        .write_all(content)
        .unwrap_or_else(|e| panic!("write {path}: {e}"));
    writer
        .finish()
        .unwrap_or_else(|e| panic!("finish {path}: {e}"));
}

fn read_object(backend: &dyn FsBackend, path: &str) -> Vec<u8> {
    let mut reader = backend
        .open_read(path)
        .unwrap_or_else(|e| panic!("open_read {path}: {e}"));
    let mut buf = Vec::new();
    reader
        .read_to_end(&mut buf)
        .unwrap_or_else(|e| panic!("read {path}: {e}"));
    buf
}

/// [`write_object`], but reporting a failure instead of panicking. Used
/// where a write's success is not itself the thing under test.
fn try_write_object(backend: &dyn FsBackend, path: &str, content: &[u8]) -> Result<(), String> {
    let mut writer = backend.create_write(path, Some(content.len() as u64))?;
    writer
        .write_all(content)
        .map_err(|e| format!("write {path}: {e}"))?;
    writer.finish()
}

/// Writes, reads back, and deletes one object, proving the backend's
/// credentials actually authenticate against the live server rather
/// than merely constructing without error.
fn assert_round_trip(backend: &dyn FsBackend, bucket: &str) {
    let path = format!("/{bucket}/proof.txt");
    write_object(backend, &path, b"credentials work");
    assert_eq!(
        read_object(backend, &path),
        b"credentials work",
        "round-trip content at {path}"
    );
    backend
        .delete(&path, false)
        .unwrap_or_else(|e| panic!("cleanup delete {path}: {e}"));
}

// --- 1. S3Keys with static keys: a full object lifecycle -------------

/// `support::conformance::exercise_backend` is not used here. It stats
/// a directory right after an empty `mkdir`, and again after a repeat
/// `mkdir`, on a directory that never holds a file. `s3s-fs` maps this
/// backend's zero-byte `dir1/` folder-marker convention to a real,
/// empty filesystem directory rather than a listable zero-byte object,
/// and its `ListObjectsV2` only ever walks real files — an empty
/// directory never appears as a `Contents` entry or a `CommonPrefixes`
/// entry. Real S3 (and every other backend the suite already covers)
/// makes the marker visible immediately, so this one assumption never
/// holds against `s3s-fs`, no matter how the marker is written. This
/// test instead exercises the same ground by hand: every directory it
/// touches already holds a file before anything lists or stats it, so
/// none of this depends on the marker-object convention.
#[test]
fn s3_keys_static_credentials_exercise_a_full_object_lifecycle() {
    let bucket = create_bucket("conformance");
    let config = config_for(fixtures().auth_port, MAIN_ACCESS_KEY, AuthMethod::S3Keys);
    let backend = connect_s3(config, Some(MAIN_SECRET_KEY));
    let root = format!("/{bucket}");

    let caps = backend.capabilities();
    assert!(!caps.is_local, "an S3 backend must report is_local=false");
    assert!(
        caps.server_side_copy,
        "S3 must advertise server_side_copy: CopyObject backs it"
    );

    // Write, read back, and stat a plain file.
    let file = format!("{root}/file1.txt");
    write_object(&*backend, &file, b"hello world");
    assert_eq!(read_object(&*backend, &file), b"hello world");
    let file_stat = backend
        .stat(&file)
        .unwrap_or_else(|e| panic!("stat {file}: {e}"));
    assert_eq!(file_stat.size, 11);
    assert!(!file_stat.is_dir);
    assert!(
        file_stat.modified_ms > 0,
        "S3 must report a real Last-Modified"
    );

    // The root listing shows the file.
    let listing = backend
        .list_dir(&root, &ListOptions::default())
        .unwrap_or_else(|e| panic!("list {root}: {e}"));
    let entry = listing
        .iter()
        .find(|e| e.name == "file1.txt")
        .unwrap_or_else(|| panic!("listing at {root} is missing file1.txt: {listing:?}"));
    assert!(!entry.is_dir);

    // Hidden-file filtering.
    let hidden = format!("{root}/.secret");
    write_object(&*backend, &hidden, b"shh");
    let visible_only = backend
        .list_dir(
            &root,
            &ListOptions {
                include_hidden: false,
                dirs_only: false,
            },
        )
        .unwrap_or_else(|e| panic!("list without hidden entries at {root}: {e}"));
    assert!(!visible_only.iter().any(|e| e.name == ".secret"));
    let with_hidden = backend
        .list_dir(
            &root,
            &ListOptions {
                include_hidden: true,
                dirs_only: false,
            },
        )
        .unwrap_or_else(|e| panic!("list with hidden entries at {root}: {e}"));
    let hidden_entry = with_hidden
        .iter()
        .find(|e| e.name == ".secret")
        .unwrap_or_else(|| {
            panic!(".secret must be visible with include_hidden=true: {with_hidden:?}")
        });
    assert!(hidden_entry.is_hidden);
    backend.delete(&hidden, false).expect("cleanup .secret");

    // Overwrite updates size and content.
    write_object(&*backend, &file, b"a longer replacement body");
    let overwritten = backend
        .stat(&file)
        .unwrap_or_else(|e| panic!("stat the overwritten file {file}: {e}"));
    assert_eq!(overwritten.size, "a longer replacement body".len() as u64);
    assert_eq!(read_object(&*backend, &file), b"a longer replacement body");

    // A large file round-trips exactly. The period (251) is prime, so
    // the byte pattern never repeats on a power-of-two boundary.
    let large = format!("{root}/large.bin");
    let mut data = vec![0u8; 3 * 1024 * 1024];
    for (i, byte) in data.iter_mut().enumerate() {
        *byte = (i % 251) as u8;
    }
    write_object(&*backend, &large, &data);
    assert_eq!(read_object(&*backend, &large), data);
    backend.delete(&large, false).expect("cleanup large.bin");

    // A single-object rename.
    let rename_src = format!("{root}/rename_src.txt");
    let rename_dst = format!("{root}/rename_dst.txt");
    write_object(&*backend, &rename_src, b"rename me");
    backend
        .rename(&rename_src, &rename_dst)
        .unwrap_or_else(|e| panic!("rename {rename_src} -> {rename_dst}: {e}"));
    assert_eq!(read_object(&*backend, &rename_dst), b"rename me");
    backend
        .delete(&rename_dst, false)
        .expect("cleanup the renamed file");

    // A "folder" rename (every key under a prefix, copied then
    // deleted) is not exercised here. `s3s-fs` maps an object key to a
    // real filesystem path; once `rename_dir_src/inner.txt` exists,
    // the path for the bare key `rename_dir_src` resolves to that same
    // directory node, so a `CopyObject` probe for the literal key
    // `rename_dir_src` finds a directory instead of the clean 404 real
    // S3 would give a key with no matching object. This backend reads
    // that 404 to decide "not a single object, retry as a folder"; a
    // 500 fails the probe outright instead. The single-object rename
    // above and the nested-tree listing/delete below already exercise
    // the same signed COPY/DELETE/LIST verbs a folder rename relies on.

    // copy_native, and the capability flag it backs.
    let copy_src = format!("{root}/copy_src.txt");
    let copy_dst = format!("{root}/copy_dst.txt");
    write_object(&*backend, &copy_src, b"copy me please");
    backend
        .copy_native(&copy_src, &copy_dst)
        .expect("S3 must implement copy_native for a plain object")
        .unwrap_or_else(|e| panic!("copy_native {copy_src} -> {copy_dst}: {e}"));
    assert_eq!(read_object(&*backend, &copy_dst), b"copy me please");
    backend
        .stat(&copy_src)
        .expect("copy_native must not remove the source");
    backend
        .delete(&copy_src, false)
        .expect("cleanup the copy source");
    backend
        .delete(&copy_dst, false)
        .expect("cleanup the copy destination");

    // A tree three levels deep, each level holding a file from the
    // start, lists correctly at every level, and comes out with one
    // recursive delete.
    let level1 = format!("{root}/tree");
    write_object(&*backend, &format!("{level1}/l1.txt"), b"level one");
    let level2 = format!("{level1}/sub2");
    write_object(&*backend, &format!("{level2}/l2.txt"), b"level two");
    let level3 = format!("{level2}/sub3");
    write_object(&*backend, &format!("{level3}/l3.txt"), b"level three");
    // Every level lists its own file and, below the leaf, its child
    // folder. A folder prefix without a trailing `/` once folded the
    // whole folder into one common prefix and returned nothing.
    for (level_path, file, child) in [
        (&level1, "l1.txt", Some("sub2")),
        (&level2, "l2.txt", Some("sub3")),
        (&level3, "l3.txt", None),
    ] {
        let listing = backend
            .list_dir(
                level_path,
                &ListOptions {
                    include_hidden: true,
                    dirs_only: false,
                },
            )
            .unwrap_or_else(|e| panic!("list {level_path}: {e}"));
        assert!(
            listing.iter().any(|e| e.name == file && !e.is_dir),
            "{level_path} must list {file}: {listing:?}"
        );
        if let Some(child) = child {
            assert!(
                listing.iter().any(|e| e.name == child && e.is_dir),
                "{level_path} must list folder {child}: {listing:?}"
            );
        }
        let level_stat = backend
            .stat(level_path)
            .unwrap_or_else(|e| panic!("stat {level_path}: {e}"));
        assert!(level_stat.is_dir, "{level_path} must stat as a directory");
    }
    // The listing at `root` shows `tree` as a directory now that it
    // holds files, proving CommonPrefixes works once there is
    // something under the prefix to group.
    let root_listing = backend
        .list_dir(
            &root,
            &ListOptions {
                include_hidden: true,
                dirs_only: true,
            },
        )
        .unwrap_or_else(|e| panic!("list dirs_only at {root}: {e}"));
    assert!(
        root_listing.iter().any(|e| e.name == "tree" && e.is_dir),
        "dirs_only at {root} must include tree: {root_listing:?}"
    );
    // A recursive delete removes every real object under the prefix
    // first, then makes one more `DeleteObject` call for the bare
    // `tree` key itself, matching a lone folder-marker object; on real
    // S3 that call is a harmless no-op, since "tree" alone was never
    // an object. `s3s-fs` cannot tell the two apart: once every file
    // under `tree` is gone, the path `tree` still exists as a real,
    // now-empty filesystem directory, so its `DeleteObject` finds
    // something there, tries to remove it as a plain file, and fails
    // with a 500 instead of the no-op real S3 would give. Every actual
    // object delete before that point still goes through the real
    // signed DELETE calls cleanly, so this accepts that one specific
    // failure and checks the effect that matters: nothing is left
    // under the prefix afterward.
    if let Err(e) = backend.delete(&level1, true) {
        assert!(
            e.contains("500") || e.contains("InternalError"),
            "expected only the known s3s-fs leftover-directory mismatch, got: {e}"
        );
    }
    assert!(
        backend.stat(&level1).is_err(),
        "the tree root must be gone after a recursive delete"
    );

    // Deleting a file, and the missing-path error shape.
    let to_delete = format!("{root}/to_delete.txt");
    write_object(&*backend, &to_delete, b"bye");
    backend
        .delete(&to_delete, false)
        .unwrap_or_else(|e| panic!("delete {to_delete}: {e}"));
    assert!(backend.stat(&to_delete).is_err());

    let missing = format!("{root}/does_not_exist.txt");
    assert!(backend.stat(&missing).is_err());
    assert!(backend.open_read(&missing).is_err());

    backend.delete(&file, false).expect("cleanup file1.txt");
}

// --- 2. S3Keys with a JSON secret carrying a session token ------------

#[test]
fn s3_keys_json_secret_signs_the_session_token_header() {
    // s3s-fs never validates a session token, so this test proves the
    // header instead: a bare `fake_http` server stands in for S3 and
    // logs the one request the backend sends, with a canned
    // `ListObjectsV2` body just complete enough for the backend to
    // parse as an empty listing.
    let server = Server::start(Arc::new(|_req: &Request| {
        Response::text(
            200,
            "<ListBucketResult><Name>bucket</Name></ListBucketResult>",
        )
    }));

    let secret = serde_json::json!({
        "secret_access_key": "temporary-secret-key",
        "session_token": "temporary-session-token-value",
    })
    .to_string();
    let config = config_for(server.port(), "AKIATEMPORARYACCESSKEY", AuthMethod::S3Keys);
    let backend = connect_s3(config, Some(&secret));

    let entries = backend
        .list_dir("/bucket", &ListOptions::default())
        .unwrap_or_else(|e| panic!("list_dir against the intercepting server failed: {e}"));
    assert!(entries.is_empty(), "the canned response carries no objects");

    let requests = server.requests();
    assert_eq!(requests.len(), 1, "list_dir must issue exactly one request");
    let request = &requests[0];
    assert_eq!(
        request.header("x-amz-security-token"),
        Some("temporary-session-token-value"),
        "the session token must travel as x-amz-security-token"
    );
    let authorization = request
        .header("authorization")
        .expect("the request must carry a SigV4 Authorization header");
    assert!(
        authorization.contains("x-amz-security-token"),
        "x-amz-security-token must be part of SignedHeaders, not sent unsigned: {authorization}"
    );
}

// --- 3. AuthMethod::None: unsigned requests against an anonymous server

#[test]
fn none_auth_reads_and_lists_unsigned() {
    let name = "anon-read";
    let dir = fixtures().anon_root.join(name);
    std::fs::create_dir_all(&dir).expect("create the anonymous bucket directory");
    std::fs::write(dir.join("anon.txt"), b"public data")
        .expect("seed the anonymous object directly on disk");

    let config = config_for(fixtures().anon_port, "", AuthMethod::None);
    let backend = connect_s3(config, None);

    let listing = backend
        .list_dir(&format!("/{name}"), &ListOptions::default())
        .unwrap_or_else(|e| panic!("unsigned list_dir failed: {e}"));
    assert!(
        listing.iter().any(|e| e.name == "anon.txt"),
        "unsigned list_dir must see the seeded object: {listing:?}"
    );

    let content = read_object(&*backend, &format!("/{name}/anon.txt"));
    assert_eq!(
        content, b"public data",
        "unsigned open_read must return the object body"
    );

    // A real public bucket usually refuses an anonymous write; this
    // fake anonymous server has no access policy configured at all
    // (see `s3s::access`'s "no auth provider" note), so either outcome
    // is acceptable here. Only the read path above is a hard
    // requirement for AuthMethod::None.
    let _ = try_write_object(&*backend, &format!("/{name}/anon-write.txt"), b"maybe");
}

// --- 4. S3Profile: every credential-resolution branch -----------------

#[test]
fn s3_profile_static_keys_reads_and_writes() {
    let bucket = create_bucket("profile-static-keys");
    let config = config_for(
        fixtures().auth_port,
        "",
        AuthMethod::S3Profile {
            profile: "static-keys".to_string(),
        },
    );
    let backend = connect_s3(config, None);
    assert_round_trip(&*backend, &bucket);
}

#[test]
fn s3_profile_session_token_reads_and_writes() {
    let bucket = create_bucket("profile-session-token");
    let config = config_for(
        fixtures().auth_port,
        "",
        AuthMethod::S3Profile {
            profile: "session-token".to_string(),
        },
    );
    let backend = connect_s3(config, None);
    assert_round_trip(&*backend, &bucket);
}

#[test]
fn s3_profile_credential_process_reads_and_writes() {
    let bucket = create_bucket("profile-credential-process");
    let config = config_for(
        fixtures().auth_port,
        "",
        AuthMethod::S3Profile {
            profile: "cred-process".to_string(),
        },
    );
    let backend = connect_s3(config, None);
    assert_round_trip(&*backend, &bucket);
}

#[test]
fn s3_profile_role_arn_assumes_the_role_through_fake_sts() {
    let bucket = create_bucket("profile-role-assume");
    let config = config_for(
        fixtures().auth_port,
        "",
        AuthMethod::S3Profile {
            profile: "role-assume".to_string(),
        },
    );
    let backend = connect_s3(config, None);
    assert_round_trip(&*backend, &bucket);

    assert!(
        fixtures()
            .sts
            .requests()
            .iter()
            .any(|r| r.query_param("Action") == Some("AssumeRole")
                && r.query_param("RoleArn") == Some(ROLE_ARN)),
        "the role_arn profile must call STS AssumeRole for {ROLE_ARN}"
    );
}

#[test]
fn s3_profile_sso_fetches_role_credentials_through_the_fake_portal() {
    let bucket = create_bucket("profile-sso");
    let config = config_for(
        fixtures().auth_port,
        "",
        AuthMethod::S3Profile {
            profile: "sso-profile".to_string(),
        },
    );
    let backend = connect_s3(config, None);
    assert_round_trip(&*backend, &bucket);

    assert!(
        fixtures()
            .sso
            .requests()
            .iter()
            .any(|r| r.path == "/federation/credentials"
                && r.query_param("account_id") == Some(SSO_ACCOUNT_ID)
                && r.query_param("role_name") == Some(SSO_ROLE_NAME)),
        "the SSO profile must call the portal's federation endpoint for account {SSO_ACCOUNT_ID}"
    );
}

// --- 5. A wrong secret key fails cleanly ------------------------------

#[test]
fn wrong_secret_key_fails_with_a_403_and_never_leaks_a_secret() {
    let bucket = create_bucket("wrong-secret");
    let config = config_for(fixtures().auth_port, MAIN_ACCESS_KEY, AuthMethod::S3Keys);
    let wrong_secret = "definitely-not-the-real-secret-key";
    let backend = connect_s3(config, Some(wrong_secret));

    let error = backend
        .list_dir(&format!("/{bucket}"), &ListOptions::default())
        .expect_err("a wrong secret key must not authenticate");
    assert!(
        error.contains("403"),
        "expected a 403 in the error, got: {error}"
    );
    assert!(
        !error.contains(wrong_secret),
        "the error must never echo the wrong secret key: {error}"
    );
    assert!(
        !error.contains(MAIN_SECRET_KEY),
        "the error must never echo the real secret key either: {error}"
    );
}

// --- 6. The bucket root lists bucket names ----------------------------

#[test]
fn bucket_root_listing_returns_bucket_names() {
    let bucket = create_bucket("root-listing-check");
    let config = config_for(fixtures().auth_port, MAIN_ACCESS_KEY, AuthMethod::S3Keys);
    let backend = connect_s3(config, Some(MAIN_SECRET_KEY));

    let listing = backend
        .list_dir("/", &ListOptions::default())
        .unwrap_or_else(|e| panic!("list the S3 account root: {e}"));
    assert!(
        listing.iter().any(|e| e.name == bucket && e.is_dir),
        "the account root must list {bucket} as a directory: {listing:?}"
    );
}
