//! A minimal HTTP/1.1 server for tests.
//!
//! This server understands only what a test needs: one request per
//! connection, a handler callback, and a log of what arrived. It does
//! not support keep-alive. Every response closes the socket after it
//! sends a `Content-Length` body, which matches how `ureq` behaves and
//! keeps the request parser simple.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

/// One parsed HTTP request.
///
/// Header names are stored lowercase so lookups do not depend on the
/// casing a particular client happens to send.
#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub query: Vec<(String, String)>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    /// The value of `name`, matched case-insensitively against the
    /// stored lowercase header names.
    pub fn header(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value.as_str())
    }

    /// The value of a query-string parameter named `name`.
    pub fn query_param(&self, name: &str) -> Option<&str> {
        self.query
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    /// Parses the body as `application/x-www-form-urlencoded`, decoding
    /// `+` as space and `%XX` escapes.
    pub fn form(&self) -> Vec<(String, String)> {
        let body = String::from_utf8_lossy(&self.body);
        parse_form_encoded(&body)
    }

    /// Parses the body as JSON.
    pub fn json(&self) -> Result<serde_json::Value, String> {
        serde_json::from_slice(&self.body)
            .map_err(|e| format!("request body is not valid JSON: {e}"))
    }

    /// The token from an `Authorization: Bearer <token>` header.
    pub fn bearer_token(&self) -> Option<&str> {
        self.header("authorization")?.strip_prefix("Bearer ")
    }
}

/// Decodes one `application/x-www-form-urlencoded` or query-string
/// body into ordered key/value pairs. A pair with no `=` is skipped:
/// a fake server only ever needs to read parameters a real client
/// sends deliberately, so a malformed pair is not worth failing over.
fn parse_form_encoded(body: &str) -> Vec<(String, String)> {
    body.split('&')
        .filter(|pair| !pair.is_empty())
        .filter_map(|pair| pair.split_once('='))
        .map(|(key, value)| (percent_decode(key), percent_decode(value)))
        .collect()
}

/// Decodes `%XX` escapes and `+` as space. An escape with fewer than
/// two hex digits following it passes through as literal characters
/// instead of failing the whole decode, since a fake server must never
/// panic on a client's malformed input.
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
                match hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    Some(byte) => {
                        out.push(byte);
                        i += 3;
                    }
                    None => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A response the handler builds for one request.
pub struct Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Response {
    /// A JSON body at the given status.
    pub fn json(status: u16, value: &serde_json::Value) -> Response {
        Response::bytes(status, "application/json", value.to_string().into_bytes())
    }

    /// A response with an arbitrary content type and raw body bytes.
    pub fn bytes(status: u16, content_type: &str, body: Vec<u8>) -> Response {
        Response {
            status,
            headers: vec![("Content-Type".to_string(), content_type.to_string())],
            body,
        }
    }

    /// A plain-text response.
    pub fn text(status: u16, body: &str) -> Response {
        Response::bytes(status, "text/plain; charset=utf-8", body.as_bytes().to_vec())
    }

    /// A response with the given status and no body.
    pub fn empty(status: u16) -> Response {
        Response {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// A `302` redirect to `location`.
    pub fn redirect(location: &str) -> Response {
        Response::empty(302).header("Location", location)
    }

    /// Adds one header to the response.
    pub fn header(mut self, name: &str, value: &str) -> Response {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    /// Writes the status line, headers, and body over `transport`.
    /// `Content-Length` and `Connection: close` are always sent, so a
    /// caller never sets them: every response here closes the
    /// connection once it is written, which keeps the parser on the
    /// other end simple and matches how `ureq` treats a fake server.
    fn write_to<W: Write>(&self, transport: &mut W) -> std::io::Result<()> {
        let reason = reason_phrase(self.status);
        let mut head = format!("HTTP/1.1 {} {reason}\r\n", self.status);
        for (name, value) in &self.headers {
            head.push_str(name);
            head.push_str(": ");
            head.push_str(value);
            head.push_str("\r\n");
        }
        head.push_str(&format!("Content-Length: {}\r\n", self.body.len()));
        head.push_str("Connection: close\r\n\r\n");
        transport.write_all(head.as_bytes())?;
        transport.write_all(&self.body)?;
        transport.flush()
    }
}

/// A short reason phrase for the status line. Real clients ignore
/// this text, so an unrecognized status gets a generic placeholder
/// rather than failing the response.
fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        302 => "Found",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "Response",
    }
}

/// A handler that turns one request into one response. Shared across
/// connection threads, so it must be `Send + Sync`.
pub type Handler = Arc<dyn Fn(&Request) -> Response + Send + Sync>;

/// A running fake server. Dropping it stops the accept loop and joins
/// its thread, so a test does not leak a thread pinned to a socket
/// that is about to disappear.
pub struct Server {
    port: u16,
    scheme: &'static str,
    requests: Arc<Mutex<Vec<Request>>>,
    stop: Arc<AtomicBool>,
    accept_thread: Option<JoinHandle<()>>,
}

impl Server {
    /// Starts a plain-text HTTP server on an OS-assigned loopback port.
    pub fn start(handler: Handler) -> Server {
        Server::start_with(handler, None)
    }

    /// Starts an HTTPS server on an OS-assigned loopback port, using
    /// the certificate and key from `tls`.
    pub fn start_tls(tls: &crate::tls::ServerTls, handler: Handler) -> Server {
        Server::start_with(handler, Some(tls.server_config()))
    }

    fn start_with(handler: Handler, tls_config: Option<Arc<rustls::ServerConfig>>) -> Server {
        // Binding port 0 on the loopback address cannot reasonably fail
        // on a working machine; a fake server that cannot do this
        // leaves every test relying on it unable to run, so panicking
        // here instead of threading a `Result` through every call site
        // is the right tradeoff.
        let listener = TcpListener::bind("127.0.0.1:0").expect("cannot bind a loopback port");
        let port = listener
            .local_addr()
            .expect("bound socket has no local address")
            .port();
        let scheme = if tls_config.is_some() { "https" } else { "http" };
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));

        let thread_requests = Arc::clone(&requests);
        let thread_stop = Arc::clone(&stop);
        let accept_thread = std::thread::spawn(move || {
            accept_loop(listener, thread_stop, thread_requests, handler, tls_config);
        });

        Server {
            port,
            scheme,
            requests,
            stop,
            accept_thread: Some(accept_thread),
        }
    }

    /// The server's base URL: `http://127.0.0.1:{port}` for a plain
    /// server, or `https://localhost:{port}` for a TLS one. TLS uses
    /// `localhost` because the generated certificate's Subject
    /// Alternative Names include it, and `ureq`'s TLS verifier checks
    /// the hostname it connected to against those names.
    pub fn base_url(&self) -> String {
        let host = if self.scheme == "https" { "localhost" } else { "127.0.0.1" };
        format!("{}://{host}:{}", self.scheme, self.port)
    }

    /// The OS-assigned loopback port this server is bound to.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Every request received so far, in arrival order.
    pub fn requests(&self) -> Vec<Request> {
        self.requests.lock().unwrap().clone()
    }

    /// Clears the request log.
    pub fn clear_requests(&self) {
        self.requests.lock().unwrap().clear();
    }

    /// The number of requests received so far.
    pub fn request_count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
}

impl Drop for Server {
    /// Stops the accept loop and joins its thread. Setting the flag
    /// alone is not enough: `TcpListener::accept` blocks, so a
    /// throwaway connection to the server's own port wakes it up to
    /// notice the flag.
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Ignore a failed connect: if this fails, the accept loop is
        // already gone, and there is nothing left to unblock.
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(handle) = self.accept_thread.take() {
            let _ = handle.join();
        }
    }
}

/// Accepts connections until `stop` is set, spawning one thread per
/// connection. A connection thread's own panic is caught so one bad
/// request never takes the whole listener down.
fn accept_loop(
    listener: TcpListener,
    stop: Arc<AtomicBool>,
    requests: Arc<Mutex<Vec<Request>>>,
    handler: Handler,
    tls_config: Option<Arc<rustls::ServerConfig>>,
) {
    for stream in listener.incoming() {
        if stop.load(Ordering::SeqCst) {
            return;
        }
        let Ok(stream) = stream else {
            continue;
        };
        let requests = Arc::clone(&requests);
        let handler = Arc::clone(&handler);
        let tls_config = tls_config.clone();
        std::thread::spawn(move || {
            // A panic inside one connection (a bad handler, an I/O
            // surprise) must stay isolated to that connection; it must
            // never propagate and kill the accept loop.
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                serve_connection(stream, &requests, &handler, tls_config.as_ref());
            }));
        });
    }
}

/// One transport a connection can arrive over: plain TCP, or TCP
/// wrapped in a TLS server session.
enum Transport {
    Plain(TcpStream),
    Tls(Box<rustls::StreamOwned<rustls::ServerConnection, TcpStream>>),
}

impl Read for Transport {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Transport::Plain(s) => s.read(buf),
            Transport::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Transport {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Transport::Plain(s) => s.write(buf),
            Transport::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Transport::Plain(s) => s.flush(),
            Transport::Tls(s) => s.flush(),
        }
    }
}

/// Reads one request, runs the handler, and writes the response. A
/// parse failure replies `400` and logs a diagnostic to stderr instead
/// of propagating: one malformed request must not be treated as a
/// crash, only as a bad request.
fn serve_connection(
    stream: TcpStream,
    requests: &Arc<Mutex<Vec<Request>>>,
    handler: &Handler,
    tls_config: Option<&Arc<rustls::ServerConfig>>,
) {
    let mut transport = match tls_config {
        Some(config) => {
            let session = match rustls::ServerConnection::new(Arc::clone(config)) {
                Ok(session) => session,
                Err(e) => {
                    eprintln!("orka-bench: cannot start a TLS session: {e}");
                    return;
                }
            };
            Transport::Tls(Box::new(rustls::StreamOwned::new(session, stream)))
        }
        None => Transport::Plain(stream),
    };

    let request = {
        let mut reader = BufReader::new(&mut transport);
        read_request(&mut reader)
    };
    let request = match request {
        Ok(request) => request,
        Err(e) => {
            eprintln!("orka-bench: malformed request: {e}");
            let _ = Response::text(400, "bad request").write_to(&mut transport);
            return;
        }
    };

    requests.lock().unwrap().push(request.clone());
    let response = handler(&request);
    let _ = response.write_to(&mut transport);
}

/// Reads and parses one full HTTP request: the request line, headers,
/// and a body sized by `Content-Length` or reassembled from chunked
/// transfer-encoding. Answers a `100-continue` expectation before
/// reading the body, since `ureq` sends that header before a body of
/// unknown size and then waits for the interim response.
fn read_request<T: Read + Write>(reader: &mut BufReader<&mut T>) -> Result<Request, String> {
    let request_line = read_line(reader)?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or("empty request line")?.to_string();
    let target = parts.next().ok_or("request line has no target")?.to_string();
    let (path, query) = split_path_and_query(&target);

    let mut headers = Vec::new();
    loop {
        let line = read_line(reader)?;
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':').ok_or("malformed header line")?;
        headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
    }

    let expects_continue = headers
        .iter()
        .any(|(k, v)| k == "expect" && v.eq_ignore_ascii_case("100-continue"));
    if expects_continue {
        reader
            .get_mut()
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .map_err(|e| format!("cannot send 100-continue: {e}"))?;
        reader
            .get_mut()
            .flush()
            .map_err(|e| format!("cannot flush 100-continue: {e}"))?;
    }

    let is_chunked = headers
        .iter()
        .any(|(k, v)| k == "transfer-encoding" && v.eq_ignore_ascii_case("chunked"));
    let body = if is_chunked {
        read_chunked_body(reader)?
    } else {
        let content_length: usize = headers
            .iter()
            .find(|(k, _)| k == "content-length")
            .map(|(_, v)| v.parse().map_err(|_| "invalid Content-Length".to_string()))
            .transpose()?
            .unwrap_or(0);
        let mut body = vec![0u8; content_length];
        reader
            .read_exact(&mut body)
            .map_err(|e| format!("cannot read request body: {e}"))?;
        body
    };

    Ok(Request {
        method,
        path,
        query,
        headers,
        body,
    })
}

/// Reads one CRLF- or LF-terminated line, without the terminator.
fn read_line<R: BufRead>(reader: &mut R) -> Result<String, String> {
    let mut line = Vec::new();
    let n = reader
        .read_until(b'\n', &mut line)
        .map_err(|e| format!("cannot read a line: {e}"))?;
    if n == 0 {
        return Err("connection closed before a full request arrived".to_string());
    }
    while line.last() == Some(&b'\n') || line.last() == Some(&b'\r') {
        line.pop();
    }
    String::from_utf8(line).map_err(|_| "request line is not valid UTF-8".to_string())
}

/// Reads a `Transfer-Encoding: chunked` body and reassembles it into
/// one buffer. `ureq` sends a request body this way when its length is
/// not known up front, so this must work for at least the OAuth
/// token-exchange POSTs.
fn read_chunked_body<R: BufRead>(reader: &mut R) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();
    loop {
        let size_line = read_line(reader)?;
        // A chunk-extension (";name=value") can follow the size; only
        // the size itself matters here.
        let size_str = size_line.split(';').next().unwrap_or("").trim();
        let size =
            usize::from_str_radix(size_str, 16).map_err(|_| "invalid chunk size".to_string())?;
        if size == 0 {
            // A trailer section (zero or more header lines) can follow
            // the last chunk before the final blank line; read and
            // discard it.
            loop {
                let line = read_line(reader)?;
                if line.is_empty() {
                    break;
                }
            }
            break;
        }
        let mut chunk = vec![0u8; size];
        reader
            .read_exact(&mut chunk)
            .map_err(|e| format!("cannot read chunk body: {e}"))?;
        body.extend_from_slice(&chunk);
        // Each chunk ends with a trailing CRLF that is not part of the
        // data.
        let trailer = read_line(reader)?;
        if !trailer.is_empty() {
            return Err("malformed chunk trailer".to_string());
        }
    }
    Ok(body)
}

/// Splits a request target into its path and decoded query
/// parameters, e.g. `"/token?grant_type=x"` into
/// `("/token", [("grant_type", "x")])`.
fn split_path_and_query(target: &str) -> (String, Vec<(String, String)>) {
    match target.split_once('?') {
        Some((path, query)) => (path.to_string(), parse_form_encoded(query)),
        None => (target.to_string(), Vec::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_get_round_trips() {
        let server = Server::start(Arc::new(|req: &Request| {
            assert_eq!(req.method, "GET");
            assert_eq!(req.path, "/hello");
            Response::json(200, &serde_json::json!({"ok": true, "path": req.path}))
        }));

        let response: serde_json::Value = ureq::get(&format!("{}/hello", server.base_url()))
            .call()
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(response["ok"], true);
        assert_eq!(response["path"], "/hello");
        assert_eq!(server.request_count(), 1);
    }

    #[test]
    fn chunked_post_is_read_completely() {
        let server = Server::start(Arc::new(|req: &Request| {
            Response::bytes(200, "application/octet-stream", req.body.clone())
        }));

        // ureq switches a `Read`-sourced body to chunked transfer
        // encoding, since it does not know the length up front.
        let payload = vec![b'x'; 20_000];
        let cursor = std::io::Cursor::new(payload.clone());
        let response = ureq::post(&format!("{}/echo", server.base_url()))
            .send(cursor)
            .unwrap();
        let mut body = Vec::new();
        response.into_reader().read_to_end(&mut body).unwrap();
        assert_eq!(body, payload);

        let logged = server.requests();
        assert_eq!(logged.len(), 1);
        assert_eq!(logged[0].header("transfer-encoding"), Some("chunked"));
    }

    #[test]
    fn request_log_tracks_and_clears() {
        let server = Server::start(Arc::new(|_req: &Request| Response::empty(204)));
        let url = server.base_url();

        ureq::get(&format!("{url}/a")).call().unwrap();
        ureq::get(&format!("{url}/b")).call().unwrap();
        assert_eq!(server.request_count(), 2);
        assert_eq!(server.requests()[0].path, "/a");
        assert_eq!(server.requests()[1].path, "/b");

        server.clear_requests();
        assert_eq!(server.request_count(), 0);
    }

    #[test]
    fn query_form_and_bearer_are_parsed() {
        let server = Server::start(Arc::new(|req: &Request| {
            if req.path == "/query" {
                assert_eq!(req.query_param("a"), Some("1 2"));
                assert_eq!(req.bearer_token(), Some("secret-token"));
            } else {
                let form = req.form();
                assert!(form.iter().any(|(k, v)| k == "grant_type" && v == "refresh_token"));
            }
            Response::empty(200)
        }));
        let url = server.base_url();

        ureq::get(&format!("{url}/query?a=1+2"))
            .set("Authorization", "Bearer secret-token")
            .call()
            .unwrap();
        ureq::post(&format!("{url}/token"))
            .send_form(&[("grant_type", "refresh_token")])
            .unwrap();
    }
}
