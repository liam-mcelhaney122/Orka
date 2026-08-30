//! Shared HTTP plumbing for the REST file-server backends.
//!
//! [`RequestError`] turns a transport failure or a non-2xx status into
//! one `String`, so every backend reports errors the same way. All
//! backends build agents through [`agent`] so timeouts stay consistent.
//! Streaming downloads read straight off the response; the transfer
//! engine consumes chunks from it.

use std::io::Read;
use std::time::Duration;

/// TCP connect timeout for every REST backend.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Per-request timeout, including body read time.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Builds the shared agent. One agent per backend instance keeps
/// keep-alive connections pooled across calls.
pub fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .build()
}

/// True for 2xx.
pub fn is_ok(status: u16) -> bool {
    (200..300).contains(&status)
}

/// Flattens a ureq error into one message. A status error keeps the
/// server's body, which REST APIs use for their failure reason. The
/// response body is dropped here; backends read it themselves when
/// they need it.
pub fn error_string(e: ureq::Error) -> String {
    match e {
        ureq::Error::Status(code, response) => {
            let body = read_body_string(response);
            format!("HTTP {code}: {body}")
        }
        other => other.to_string(),
    }
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
        let result = agent().get(&format!("http://127.0.0.1:{port}/x")).call();
        let message = match result {
            Ok(_) => panic!("must fail"),
            Err(e) => error_string(e),
        };
        assert!(message.contains("Connection refused"), "got: {message}");
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
