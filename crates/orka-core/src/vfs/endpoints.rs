//! Service endpoint overrides for the REST and protocol backends.
//!
//! Every function here returns one backend's base URL. Each reads one
//! environment variable at call time and falls back to the real
//! production endpoint when the variable is not set. Default behavior
//! never changes: production code never sets these variables.
//!
//! A backend factory calls the matching function once, while it
//! builds the backend, and keeps the result for the backend's whole
//! life. This gives an integration test a stable target: it sets the
//! variable before it builds the backend, and the backend never reads
//! the environment again after that.

use std::env;

/// Reads `name` from the environment and trims one trailing `/`.
///
/// Every override in this module reads its variable through this
/// function, so one place shows every environment read a test needs
/// to know about. This function takes no lock: a test that depends on
/// a stable environment (setting a variable, or checking a default
/// with none set) must hold `test_support::ENV_LOCK` for as long as
/// that assumption matters, through `test_support::with_var` or
/// `test_support::with_no_overrides`. See that module's doc comment
/// for why the lock lives there instead of here.
pub fn env_override(name: &str) -> Option<String> {
    let value = env::var(name).ok()?;
    Some(value.trim_end_matches('/').to_string())
}

/// The AWS STS endpoint for `AssumeRole`. `default_host` is the
/// regional or legacy global host the caller already derived (see
/// `s3::sts_host`); the override, when set, replaces the whole
/// origin, so `default_host` is unused in that case.
pub fn sts_endpoint(default_host: &str) -> String {
    env_override("ORKA_ENDPOINT_STS").unwrap_or_else(|| format!("https://{default_host}"))
}

/// The AWS SSO portal's federation endpoint. The override replaces
/// the whole origin; `region` is then ignored.
pub fn sso_portal_endpoint(region: &str) -> String {
    env_override("ORKA_ENDPOINT_SSO_PORTAL")
        .unwrap_or_else(|| format!("https://portal.sso.{region}.amazonaws.com"))
}

/// The Google API base origin. Drive builds `{base}/drive/v3` and
/// `{base}/upload/drive/v3` on top of this.
pub fn google_api_base() -> String {
    env_override("ORKA_ENDPOINT_GOOGLE_API")
        .unwrap_or_else(|| "https://www.googleapis.com".to_string())
}

/// The Google OAuth token endpoint. A service-account key file can
/// carry its own `token_uri`; this override wins over that field when
/// set, since a test fake token server must be reachable.
pub fn google_token_endpoint() -> String {
    env_override("ORKA_ENDPOINT_GOOGLE_TOKEN")
        .unwrap_or_else(|| "https://oauth2.googleapis.com/token".to_string())
}

/// The Google OAuth authorize endpoint.
pub fn google_auth_endpoint() -> String {
    env_override("ORKA_ENDPOINT_GOOGLE_AUTH")
        .unwrap_or_else(|| "https://accounts.google.com/o/oauth2/v2/auth".to_string())
}

/// The Dropbox RPC API base origin (`list_folder`, `get_metadata`, and
/// the other JSON endpoints).
pub fn dropbox_api_base() -> String {
    env_override("ORKA_ENDPOINT_DROPBOX_API")
        .unwrap_or_else(|| "https://api.dropboxapi.com".to_string())
}

/// The Dropbox content API base origin (`download` and the upload
/// session endpoints).
pub fn dropbox_content_base() -> String {
    env_override("ORKA_ENDPOINT_DROPBOX_CONTENT")
        .unwrap_or_else(|| "https://content.dropboxapi.com".to_string())
}

/// The Dropbox OAuth authorize endpoint.
pub fn dropbox_auth_endpoint() -> String {
    env_override("ORKA_ENDPOINT_DROPBOX_AUTH")
        .unwrap_or_else(|| "https://www.dropbox.com/oauth2/authorize".to_string())
}

/// The Dropbox OAuth token endpoint.
pub fn dropbox_token_endpoint() -> String {
    env_override("ORKA_ENDPOINT_DROPBOX_TOKEN")
        .unwrap_or_else(|| "https://api.dropboxapi.com/oauth2/token".to_string())
}

/// The Azure AD login origin. A caller appends `/{tenant}/oauth2/v2.0/token`
/// or `/{tenant}/oauth2/v2.0/authorize`.
pub fn azure_login_base() -> String {
    env_override("ORKA_ENDPOINT_AZURE_LOGIN")
        .unwrap_or_else(|| "https://login.microsoftonline.com".to_string())
}

/// Picks the URL scheme for connecting to `host`.
///
/// Returns `"http"` for a loopback address literal (`127.0.0.1`,
/// `::1`, `[::1]`, or `localhost`) and `"https"` otherwise. Loopback
/// traffic never leaves the machine, so a plain-HTTP connection to it
/// exposes nothing on the network; this lets a test point a backend at
/// a local server with no TLS setup.
pub fn scheme_for_host(host: &str) -> &'static str {
    match host {
        "127.0.0.1" | "::1" | "[::1]" | "localhost" => "http",
        _ => "https",
    }
}

/// Test-only environment helpers shared across this crate's TLS and
/// endpoint-override tests.
///
/// [`env_override`] takes no lock, on purpose: the code under test
/// (a backend factory, an OAuth flow) calls it on the same thread a
/// test drives, often while that same test's `with_var` closure is
/// still running. A `RwLock` here would self-deadlock the moment a
/// `with_var` closure calls code that reads the variable it just
/// set, since a write lock and a same-thread read lock on the same
/// `RwLock` can never both succeed. [`ENV_LOCK`] instead serializes
/// only the test bodies that care about the environment being
/// stable, which is exactly the set of tests that call [`with_var`]
/// or [`with_no_overrides`]. A test that does not touch the
/// environment at all needs no lock and pays no cost.
#[cfg(test)]
pub(crate) mod test_support {
    use std::env;
    use std::sync::Mutex;

    /// Held for as long as one test needs the environment to hold
    /// still: the whole body of [`with_var`] or [`with_no_overrides`].
    /// A poisoned lock (an earlier test panicked while holding it) is
    /// still usable, since the guarded state is only `()`.
    pub(crate) static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Sets `name` to `value`, runs `f`, then removes `name`. Holds
    /// [`ENV_LOCK`] for the whole call, so no other test that also
    /// goes through this lock observes a half-set variable or reads a
    /// stale default while this one is active.
    pub(crate) fn with_var<T>(name: &str, value: &str, f: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // SAFETY: the lock above serializes every test in this crate
        // that touches the environment.
        unsafe {
            env::set_var(name, value);
        }
        let result = f();
        unsafe {
            env::remove_var(name);
        }
        result
    }

    /// Runs `f` while holding [`ENV_LOCK`], with no variable set. Use
    /// this in a test that asserts a function's default (no override
    /// present) behavior, so a concurrent [`with_var`] elsewhere
    /// cannot make that variable appear set mid-check.
    pub(crate) fn with_no_overrides<T>(f: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        f()
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{with_no_overrides, with_var};
    use super::*;

    #[test]
    fn env_override_is_absent_when_the_variable_is_not_set() {
        // "ORKA_ENDPOINT_TEST_UNSET" is unique to this test, so no
        // other test can be setting it concurrently.
        unsafe {
            env::remove_var("ORKA_ENDPOINT_TEST_UNSET");
        }
        assert_eq!(env_override("ORKA_ENDPOINT_TEST_UNSET"), None);
    }

    #[test]
    fn env_override_trims_one_trailing_slash() {
        with_var("ORKA_ENDPOINT_TEST_TRIM", "http://127.0.0.1:9/", || {
            assert_eq!(
                env_override("ORKA_ENDPOINT_TEST_TRIM").as_deref(),
                Some("http://127.0.0.1:9")
            );
        });
    }

    #[test]
    fn sts_endpoint_defaults_to_the_derived_host() {
        with_no_overrides(|| {
            assert_eq!(
                sts_endpoint("sts.amazonaws.com"),
                "https://sts.amazonaws.com"
            );
        });
    }

    #[test]
    fn sts_endpoint_override_replaces_the_whole_origin() {
        with_var("ORKA_ENDPOINT_STS", "http://127.0.0.1:9000", || {
            assert_eq!(
                sts_endpoint("sts.eu-west-1.amazonaws.com"),
                "http://127.0.0.1:9000"
            );
        });
    }

    #[test]
    fn sso_portal_endpoint_defaults_to_the_regional_host() {
        with_no_overrides(|| {
            assert_eq!(
                sso_portal_endpoint("eu-west-1"),
                "https://portal.sso.eu-west-1.amazonaws.com"
            );
        });
    }

    #[test]
    fn sso_portal_endpoint_override_ignores_the_region() {
        with_var("ORKA_ENDPOINT_SSO_PORTAL", "http://127.0.0.1:9001", || {
            assert_eq!(sso_portal_endpoint("eu-west-1"), "http://127.0.0.1:9001");
        });
    }

    #[test]
    fn google_endpoints_default_to_production() {
        with_no_overrides(|| {
            assert_eq!(google_api_base(), "https://www.googleapis.com");
            assert_eq!(
                google_token_endpoint(),
                "https://oauth2.googleapis.com/token"
            );
            assert_eq!(
                google_auth_endpoint(),
                "https://accounts.google.com/o/oauth2/v2/auth"
            );
        });
    }

    #[test]
    fn google_api_base_can_be_overridden() {
        with_var("ORKA_ENDPOINT_GOOGLE_API", "http://127.0.0.1:9002", || {
            assert_eq!(google_api_base(), "http://127.0.0.1:9002");
        });
    }

    #[test]
    fn dropbox_endpoints_default_to_production() {
        with_no_overrides(|| {
            assert_eq!(dropbox_api_base(), "https://api.dropboxapi.com");
            assert_eq!(dropbox_content_base(), "https://content.dropboxapi.com");
            assert_eq!(
                dropbox_auth_endpoint(),
                "https://www.dropbox.com/oauth2/authorize"
            );
            assert_eq!(
                dropbox_token_endpoint(),
                "https://api.dropboxapi.com/oauth2/token"
            );
        });
    }

    #[test]
    fn dropbox_api_base_can_be_overridden() {
        with_var("ORKA_ENDPOINT_DROPBOX_API", "http://127.0.0.1:9003", || {
            assert_eq!(dropbox_api_base(), "http://127.0.0.1:9003");
        });
    }

    #[test]
    fn azure_login_base_defaults_to_production() {
        with_no_overrides(|| {
            assert_eq!(azure_login_base(), "https://login.microsoftonline.com");
        });
    }

    #[test]
    fn azure_login_base_can_be_overridden() {
        with_var("ORKA_ENDPOINT_AZURE_LOGIN", "http://127.0.0.1:9004", || {
            assert_eq!(azure_login_base(), "http://127.0.0.1:9004");
        });
    }

    #[test]
    fn scheme_for_host_is_http_for_every_loopback_literal() {
        assert_eq!(scheme_for_host("127.0.0.1"), "http");
        assert_eq!(scheme_for_host("::1"), "http");
        assert_eq!(scheme_for_host("[::1]"), "http");
        assert_eq!(scheme_for_host("localhost"), "http");
    }

    #[test]
    fn scheme_for_host_is_https_for_a_real_host() {
        assert_eq!(scheme_for_host("s3.amazonaws.com"), "https");
        assert_eq!(scheme_for_host("myaccount.dfs.core.windows.net"), "https");
    }
}
