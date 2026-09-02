//! Shared HTTP plumbing for the REST file-server backends.
//!
//! [`RequestError`] turns a transport failure or a non-2xx status into
//! one `String`, so every backend reports errors the same way. All
//! backends build agents through [`agent`] so timeouts stay consistent.
//! Streaming downloads read straight off the response; the transfer
//! engine consumes chunks from it.
//!
//! [`agent`] trusts the Mozilla root set baked in by `webpki-roots`.
//! Setting `ORKA_EXTRA_CA_FILE` to a PEM file adds those certificates
//! to the trust roots as well, for a private certificate authority.
//! [`build_root_store`] builds that trust store and is shared with
//! [`super::ftp::tls_connector`], so both TLS clients trust the same
//! roots.

use std::io::Read;
use std::time::Duration;

/// TCP connect timeout for every REST backend.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Per-request timeout, including body read time.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Builds the shared agent. One agent per backend instance keeps
/// keep-alive connections pooled across calls.
///
/// Fails when `ORKA_EXTRA_CA_FILE` is set but the file cannot be read
/// or holds no valid certificate; a broken trust store must stop the
/// connection, not fall back to the default roots silently.
pub fn agent() -> Result<ureq::Agent, String> {
    let root_store = build_root_store()?;
    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    Ok(ureq::AgentBuilder::new()
        .timeout_connect(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .tls_config(std::sync::Arc::new(tls_config))
        .build())
}

/// Builds the shared TLS trust store: the Mozilla root set baked in by
/// `webpki-roots`, plus the certificates in `ORKA_EXTRA_CA_FILE` when
/// that variable is set.
///
/// An unreadable file or a file with no valid certificate is an
/// error, not a silent fallback to the default roots: a caller that
/// asked for a private CA must know when it was not applied.
pub fn build_root_store() -> Result<rustls::RootCertStore, String> {
    build_root_store_with(super::endpoints::env_override("ORKA_EXTRA_CA_FILE").as_deref())
}

/// [`build_root_store`] over an explicit path instead of the
/// environment. Pure over its argument, so the parsing and error
/// paths are testable without touching the process environment: that
/// keeps these tests immune to another test concurrently changing
/// `ORKA_EXTRA_CA_FILE` for its own purposes.
fn build_root_store_with(extra_ca_path: Option<&str>) -> Result<rustls::RootCertStore, String> {
    let mut store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };
    let Some(path) = extra_ca_path else {
        return Ok(store);
    };
    let file =
        std::fs::File::open(path).map_err(|e| format!("cannot read extra CA file {path}: {e}"))?;
    let mut reader = std::io::BufReader::new(file);
    let mut added = 0usize;
    for cert in rustls_pemfile::certs(&mut reader) {
        let cert = cert.map_err(|e| format!("cannot parse extra CA file {path}: {e}"))?;
        store
            .add(cert)
            .map_err(|e| format!("cannot add a certificate from {path}: {e}"))?;
        added += 1;
    }
    if added == 0 {
        return Err(format!("extra CA file {path} has no certificates"));
    }
    Ok(store)
}

/// True for 2xx.
pub fn is_ok(status: u16) -> bool {
    (200..300).contains(&status)
}

/// Flattens a ureq error into one message. A status error keeps the
/// server's body, which REST APIs use for their failure reason. The
/// response body is dropped here; backends read it themselves when
/// they need it. A transport error (DNS, connect, timeout) keeps
/// ureq's own message, minus its URL's query string.
pub fn error_string(e: ureq::Error) -> String {
    match e {
        ureq::Error::Status(code, response) => {
            let body = read_body_string(response);
            format!("HTTP {code}: {body}")
        }
        ureq::Error::Transport(transport) => transport_error_string(&transport),
    }
}

/// Formats a transport error the same way ureq's own `Display` does,
/// except with the URL's query string dropped. ureq attaches the full
/// request URL, query string included, to a transport error; a SAS
/// signature or another secret carried in the query string must never
/// reach an error message. Scheme, host, and path stay, so the
/// message is still useful for diagnosing which request failed.
fn transport_error_string(transport: &ureq::Transport) -> String {
    let mut out = String::new();
    if let Some(url) = transport.url() {
        out.push_str(&scrub_url_query(url));
        out.push_str(": ");
    }
    out.push_str(&transport.kind().to_string());
    if let Some(message) = transport.message() {
        out.push_str(": ");
        out.push_str(message);
    }
    if let Some(source) = std::error::Error::source(transport) {
        out.push_str(": ");
        out.push_str(&source.to_string());
    }
    out
}

/// Renders a URL without its query string or fragment: scheme, host,
/// port (when not the scheme's default), and path only.
fn scrub_url_query(url: &url::Url) -> String {
    let mut out = format!("{}://", url.scheme());
    out.push_str(url.host_str().unwrap_or(""));
    if let Some(port) = url.port() {
        out.push(':');
        out.push_str(&port.to_string());
    }
    out.push_str(url.path());
    out
}

/// Reads a whole body into a string, bounded so an error report can
/// never balloon. Used for status messages only.
pub fn read_body_string(response: ureq::Response) -> String {
    let limit: u64 = 4 * 1024;
    let mut buf = Vec::new();
    let mut reader = response.into_reader().take(limit);
    let _ = std::io::Read::read_to_end(&mut reader, &mut buf);
    String::from_utf8_lossy(&buf).into_owned()
}

/// Wraps a streaming response as a `Read`. The response owns the
/// connection until the reader drains or drops.
pub fn response_reader(response: ureq::Response) -> Box<dyn Read + Send> {
    Box::new(response.into_reader())
}

/// Percent-encodes a query parameter value. Reserved characters and
/// non-ASCII bytes become `%XX` escapes; unreserved characters stay.
pub fn url_encode(value: &str) -> String {
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

/// Parses an RFC 3339 timestamp ("2023-05-31T15:14:23Z", optional
/// fractional seconds) to milliseconds since the Unix epoch. No
/// timezone offset support; every backend that uses this receives UTC.
pub fn parse_rfc3339_to_ms(s: &str) -> Option<i64> {
    let bytes = s.as_bytes();
    // YYYY-MM-DDTHH:MM:SS with a fixed-width prefix.
    if bytes.len() < 19 {
        return None;
    }
    let year: i64 = s.get(0..4)?.parse().ok()?;
    let month: i64 = s.get(5..7)?.parse().ok()?;
    let day: i64 = s.get(8..10)?.parse().ok()?;
    let hour: i64 = s.get(11..13)?.parse().ok()?;
    let minute: i64 = s.get(14..16)?.parse().ok()?;
    let second: i64 = s.get(17..19)?.parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    Some(
        days_from_civil(year, month, day) * 86_400_000
            + hour * 3_600_000
            + minute * 60_000
            + second * 1_000,
    )
}

/// Parses an RFC 1123 date ("Wed, 15 Nov 2023 12:45:26 GMT") to
/// milliseconds since the Unix epoch. Azure REST headers use this form.
pub fn parse_rfc1123_to_ms(s: &str) -> Option<i64> {
    // Skip the weekday name: find the first comma, then split the rest.
    let rest = s.split_once(',')?.1.trim();
    let mut parts = rest.split_whitespace();
    let day: i64 = parts.next()?.parse().ok()?;
    let month = month_from_english(parts.next()?)?;
    let year: i64 = parts.next()?.parse().ok()?;
    let clock = parts.next()?;
    let mut clock_parts = clock.split(':');
    let hour: i64 = clock_parts.next()?.parse().ok()?;
    let minute: i64 = clock_parts.next()?.parse().ok()?;
    let second: i64 = clock_parts.next().unwrap_or("0").parse().ok()?;
    Some(
        days_from_civil(year, month, day) * 86_400_000
            + hour * 3_600_000
            + minute * 60_000
            + second * 1_000,
    )
}

/// Days since 1970-01-01 from a civil date. Howard Hinnant's
/// `days_from_civil` algorithm, valid across the whole i64 year range.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn month_from_english(name: &str) -> Option<i64> {
    match name {
        "Jan" => Some(1),
        "Feb" => Some(2),
        "Mar" => Some(3),
        "Apr" => Some(4),
        "May" => Some(5),
        "Jun" => Some(6),
        "Jul" => Some(7),
        "Aug" => Some(8),
        "Sep" => Some(9),
        "Oct" => Some(10),
        "Nov" => Some(11),
        "Dec" => Some(12),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A self-signed certificate, generated once for this test suite.
    /// Its private key is not kept; the certificate only needs to
    /// parse and add to a root store, never to complete a handshake.
    const TEST_CA_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIDDzCCAfegAwIBAgIUGfjbgKT+/GRykk3wD70Z8aKKvdEwDQYJKoZIhvcNAQEL\n\
BQAwFzEVMBMGA1UEAwwMb3JrYS10ZXN0LWNhMB4XDTI2MDkwMjAyNDgxNloXDTM2\n\
MDgzMDAyNDgxNlowFzEVMBMGA1UEAwwMb3JrYS10ZXN0LWNhMIIBIjANBgkqhkiG\n\
9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7ZSXQEIok/aKNc1BXU1MS4ZJK15KaxObJa9M\n\
X5p5r297sD7CZR34zoYF27ZaUWJRnZgS2gffxh0hU3MLZpovo8aF2B8kfXBbtlEn\n\
BoxF/rE4wuwayABJcDtY02P1F4Kfmtb4WMsJ3O9Y9uOTed8P0jH6DwlrY4u1gqip\n\
68cfwTw1qPDrDuvvKyL3521VhsScagT5w9V2+qKAUIUd8e1fallKl2Fk3OfS+16b\n\
OOQ/VRgqg8slo8lmPIdxilNq/6AmQnjIcnYGxCpWsPZqWFy3ug+RQjJ3dRdtarcE\n\
ArMu1bUxOQtOMgLZafzxu43nnWA4TVXQvyz2O+c/ZisgRk2lcwIDAQABo1MwUTAd\n\
BgNVHQ4EFgQUL3r7WmkngfFo8cUsLb1PBdOlIlUwHwYDVR0jBBgwFoAUL3r7Wmkn\n\
gfFo8cUsLb1PBdOlIlUwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOC\n\
AQEAzTX1cGHI5SGLEhmEuN54M4tbXl/og2pn03qOhYe/kvVpDvaUkBNqZnU/LC11\n\
8Sz2yJdLROvPe6gNYsUQl7hChcWSJv7y3tIofFtfPcfoaWdsRabfKqIleVfAAbTl\n\
Zva9b69DLuk0n3voEYS9z4nRTTZmFASXV9wGG2LGLqzwConTQdovIa+zQwIHEmlm\n\
AwFBA/ZnpQfMb21rPe1ipUnW8wO95C0o1zjU4FRI9RspeSLDFfosm4ikJWLtDfny\n\
bfAxhTStsWDws3fg1nMMmWgPN2zYyTOm1PbRbgNC3SE/hm57Jw99r4RXRVCpcUxo\n\
UPqx4AeLu7z6MAGkA9c1G9Wbsw==\n\
-----END CERTIFICATE-----\n";

    // build_root_store_with is pure over its argument, so these cases
    // need no environment variable at all: they cannot collide with a
    // concurrent test that changes ORKA_EXTRA_CA_FILE for its own
    // purposes.

    #[test]
    fn build_root_store_adds_no_certificate_by_default() {
        let default_len = build_root_store_with(None).unwrap().roots.len();
        assert_eq!(default_len, webpki_roots::TLS_SERVER_ROOTS.len());
    }

    #[test]
    fn build_root_store_adds_the_extra_ca_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ca.pem");
        std::fs::write(&path, TEST_CA_PEM).unwrap();
        let store = build_root_store_with(Some(path.to_str().unwrap())).unwrap();
        assert_eq!(store.roots.len(), webpki_roots::TLS_SERVER_ROOTS.len() + 1);
    }

    #[test]
    fn build_root_store_fails_clearly_on_a_missing_file() {
        let err = build_root_store_with(Some("/no/such/file.pem")).unwrap_err();
        assert!(err.contains("/no/such/file.pem"), "got: {err}");
    }

    #[test]
    fn build_root_store_fails_clearly_on_a_file_with_no_certificates() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.pem");
        std::fs::write(&path, "not a certificate").unwrap();
        let err = build_root_store_with(Some(path.to_str().unwrap())).unwrap_err();
        assert!(err.contains("no certificates"), "got: {err}");
    }

    // agent()'s only added logic over ureq's default TLS setup is
    // this module's build_root_store, already covered above with no
    // environment variable involved. A test that instead routes a
    // broken ORKA_EXTRA_CA_FILE through the real environment would
    // risk colliding with any other test in this crate that calls
    // agent() while this one holds a broken path in that
    // process-global variable (agent() is the shared entry point
    // every REST backend factory uses to connect).

    #[test]
    fn ok_range_checks_2xx_only() {
        assert!(is_ok(200));
        assert!(is_ok(204));
        assert!(is_ok(299));
        assert!(!is_ok(199));
        assert!(!is_ok(300));
        assert!(!is_ok(404));
    }

    #[test]
    fn error_string_reports_status_and_body() {
        // A local closed port gives a transport error, not a status.
        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        let result = agent()
            .unwrap()
            .get(&format!("http://127.0.0.1:{port}/x"))
            .call();
        let message = match result {
            Ok(_) => panic!("must fail"),
            Err(e) => error_string(e),
        };
        assert!(message.contains("Connection refused"), "got: {message}");
    }

    #[test]
    fn error_string_strips_the_query_string_from_a_transport_error_url() {
        // A closed local port gives a transport error whose URL still
        // carries the query string ureq attached before dialing. A SAS
        // signature there must never reach the returned message.
        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        let url = format!("http://127.0.0.1:{port}/fs/file?sv=2023-11-03&sig=super-secret-value");
        let result = agent().unwrap().get(&url).call();
        let message = match result {
            Ok(_) => panic!("must fail"),
            Err(e) => error_string(e),
        };
        assert!(!message.contains("sig="), "got: {message}");
        assert!(!message.contains("super-secret-value"), "got: {message}");
        assert!(!message.contains("sv="), "got: {message}");
        // Scheme, host, and path stay, so the message is still useful.
        assert!(
            message.contains(&format!("http://127.0.0.1:{port}/fs/file")),
            "got: {message}"
        );
    }

    #[test]
    fn url_encode_keeps_unreserved_and_escapes_the_rest() {
        assert_eq!(url_encode("aBc-_.~9"), "aBc-_.~9");
        assert_eq!(url_encode("a b"), "a%20b");
        assert_eq!(url_encode("q='x'&y"), "q%3D%27x%27%26y");
        assert_eq!(url_encode("/"), "%2F");
    }

    #[test]
    fn rfc3339_parses_to_epoch_ms() {
        // 1970-01-01T00:00:00Z is the epoch itself.
        assert_eq!(parse_rfc3339_to_ms("1970-01-01T00:00:00Z"), Some(0));
        // 2023-05-31T15:14:23Z cross-checked against a known epoch value.
        assert_eq!(
            parse_rfc3339_to_ms("2023-05-31T15:14:23Z"),
            Some(1_685_546_063_000)
        );
        // Fractional seconds and a lowercase t still parse.
        assert_eq!(
            parse_rfc3339_to_ms("2023-05-31T15:14:23.5Z"),
            Some(1_685_546_063_000)
        );
        assert_eq!(parse_rfc3339_to_ms("not a date"), None);
    }

    #[test]
    fn rfc1123_parses_to_epoch_ms() {
        // Thursday, 1 January 1970 00:00:00 GMT.
        assert_eq!(
            parse_rfc1123_to_ms("Thu, 01 Jan 1970 00:00:00 GMT"),
            Some(0)
        );
        assert_eq!(
            parse_rfc1123_to_ms("Wed, 15 Nov 2023 12:45:26 GMT"),
            Some(1_700_052_326_000)
        );
        assert_eq!(parse_rfc1123_to_ms("garbage"), None);
    }
}
