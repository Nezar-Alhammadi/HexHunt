use super::MAX_HTTP_RESPONSE_BODY_BYTES;
use serde::{Deserialize, Serialize};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

pub struct LocalLab {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchLabFixture {
    pub namespace: String,
    pub json_path: String,
    pub missing_path: String,
    pub large_path: String,
    pub source_path: String,
    pub echo_path: String,
    pub expected_label: String,
    pub expected_code: String,
}

impl LocalLab {
    pub fn start() -> std::io::Result<Self> {
        Self::start_with_fixture(None)
    }

    pub fn start_research(
        namespace: impl Into<String>,
    ) -> std::io::Result<(Self, ResearchLabFixture)> {
        let namespace = namespace.into();
        let fixture = ResearchLabFixture {
            json_path: format!("/lab/{namespace}/artifact"),
            missing_path: format!("/lab/{namespace}/missing"),
            large_path: format!("/lab/{namespace}/large"),
            source_path: format!("/lab/{namespace}/source"),
            echo_path: format!("/lab/{namespace}/echo"),
            expected_label: format!("asset-{namespace}"),
            expected_code: format!("HX-{}", namespace.to_ascii_uppercase()),
            namespace,
        };
        let lab = Self::start_with_fixture(Some(fixture.clone()))?;
        Ok((lab, fixture))
    }

    fn start_with_fixture(fixture: Option<ResearchLabFixture>) -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = stop.clone();
        let thread = thread::spawn(move || {
            while !thread_stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => handle_connection(stream, fixture.as_ref()),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(Self {
            address,
            stop,
            thread: Some(thread),
        })
    }

    pub fn base_url(&self) -> String {
        format!("http://{}", self.address)
    }

    pub fn port(&self) -> u16 {
        self.address.port()
    }

    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for LocalLab {
    fn drop(&mut self) {
        self.stop();
    }
}

fn handle_connection(mut stream: TcpStream, fixture: Option<&ResearchLabFixture>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let Some((method, path, body)) = read_request(&mut stream) else {
        return;
    };

    let research_response = fixture.and_then(|fixture| {
        let response = if method == "GET" && path == fixture.json_path {
            (
                "200 OK",
                "application/json",
                format!(
                    r#"{{"label":"{}","code":"{}","active":true}}"#,
                    fixture.expected_label, fixture.expected_code
                ),
                vec![],
            )
        } else if method == "GET" && path == fixture.missing_path {
            (
                "404 Not Found",
                "application/json",
                format!(
                    r#"{{"error":"not_found","namespace":"{}"}}"#,
                    fixture.namespace
                ),
                vec![],
            )
        } else if method == "GET" && path == fixture.large_path {
            (
                "200 OK",
                "text/plain",
                format!(
                    "{}:{}",
                    fixture.expected_code,
                    "x".repeat(MAX_HTTP_RESPONSE_BODY_BYTES + 64)
                ),
                vec![],
            )
        } else if method == "GET" && path == fixture.source_path {
            (
                "200 OK",
                "application/json",
                format!(
                    r#"{{"relay":"{}","value":"{}"}}"#,
                    fixture.namespace, fixture.expected_code
                ),
                vec![],
            )
        } else if method == "POST" && path == fixture.echo_path {
            (
                "200 OK",
                "application/json",
                if body.is_empty() {
                    "{}".into()
                } else {
                    body.clone()
                },
                vec![],
            )
        } else {
            return None;
        };
        Some(response)
    });

    let (status, content_type, response_body, extra_headers) =
        research_response.unwrap_or_else(|| match (method.as_str(), path.as_str()) {
            ("GET", "/") => (
                "200 OK",
                "text/html",
                r#"<!doctype html><html><head><title>HexHunt Lab Login</title><style>body{font-family:sans-serif;background:#0b1220;color:#fff;display:grid;place-items:center;height:100vh}form{background:#172033;padding:28px;border-radius:12px;width:320px}label,input,button{display:block;width:100%;margin-top:10px}button{margin-top:18px}</style></head><body><form data-reactroot><h1>Research portal</h1><p>Authorized local lab</p><label>Username<input name="username"></label><label>Password<input name="password" type="password"></label><button type="submit">Sign in</button></form><img src="http://127.0.0.1:1/outside.png" alt=""><script src="/assets/app.js"></script></body></html>"#
                    .to_string(),
                vec![("Server", "HexHunt-Lab/1.0"), ("X-Powered-By", "Rust")],
            ),
            ("GET", "/health") => (
                "200 OK",
                "application/json",
                r#"{"status":"ok"}"#.to_string(),
                vec![],
            ),
            ("GET", "/robots.txt") => (
                "200 OK",
                "text/plain",
                "User-agent: *\nDisallow: /private\nSitemap: /sitemap.xml\n".into(),
                vec![],
            ),
            ("GET", "/sitemap.xml") => (
                "200 OK",
                "application/xml",
                "<urlset><url><loc>/profile</loc></url></urlset>".into(),
                vec![],
            ),
            ("GET", "/assets/app.js") => (
                "200 OK",
                "application/javascript",
                r#"const users = "/api/v1/users?role=admin";
const login = "/login";
const specification = "/openapi.json";
const api_key = "lab-placeholder-value";
fetch(specification);
fetch("/api/v1/users?role=admin", { method: "POST" });
axios.get("/api/v1/accounts?page=1");
const overview = `query AccountOverview { viewer { id } }`;
localStorage.setItem("session", "lab-session-placeholder");
ReactDOM.render(app, root);
import("/assets/admin.js?v=1");
//# sourceMappingURL=app.js.map"#
                    .into(),
                vec![],
            ),
            ("GET", "/assets/app.js.map") => (
                "200 OK",
                "application/json",
                r#"{"version":3,"sources":["src/app.ts"],"names":[],"mappings":""}"#.into(),
                vec![],
            ),
            ("GET", "/openapi.json") => (
                "200 OK",
                "application/json",
                r#"{"openapi":"3.1.0","servers":[{"url":"/api"}],"security":[{"bearerAuth":[]}],"paths":{"/api/v1/users":{"get":{"security":[],"parameters":[{"name":"role","in":"query"}],"responses":{"200":{}}},"post":{"requestBody":{"content":{"application/json":{}}},"responses":{"201":{}}}},"/login":{"post":{"security":[],"responses":{"200":{}}}}},"components":{"schemas":{"User":{"type":"object"}},"securitySchemes":{"bearerAuth":{"type":"http","scheme":"bearer"}}}}"#.into(),
                vec![],
            ),
            ("GET", "/profile") => (
                "200 OK",
                "application/json",
                r#"{"username":"alice","role":"user"}"#.to_string(),
                vec![],
            ),
            ("POST", "/echo") => (
                "200 OK",
                "application/json",
                if body.is_empty() { "{}".into() } else { body },
                vec![],
            ),
            ("GET", "/redirect") => (
                "302 Found",
                "text/plain",
                "redirect disabled".into(),
                vec![("Location", "/profile")],
            ),
            ("GET", "/large") => (
                "200 OK",
                "text/plain",
                "x".repeat(MAX_HTTP_RESPONSE_BODY_BYTES + 32),
                vec![],
            ),
            _ => (
                "404 Not Found",
                "application/json",
                r#"{"error":"not_found"}"#.to_string(),
                vec![],
            ),
        });

    let mut headers = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n",
        response_body.len()
    );
    for (name, value) in extra_headers {
        headers.push_str(&format!("{name}: {value}\r\n"));
    }
    headers.push_str("\r\n");
    let _ = stream.write_all(headers.as_bytes());
    let _ = stream.write_all(response_body.as_bytes());
    let _ = stream.flush();
}

fn read_request(stream: &mut TcpStream) -> Option<(String, String, String)> {
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line).ok()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();

    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).ok()?;
        if line == "\r\n" || line.is_empty() {
            break;
        }
        if let Some(value) = line
            .split_once(':')
            .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .map(|(_, value)| value.trim())
        {
            content_length = value.parse().ok()?;
        }
    }

    if content_length > super::MAX_HTTP_REQUEST_BODY_BYTES {
        return None;
    }
    let mut body = vec![0; content_length];
    reader.read_exact(&mut body).ok()?;
    Some((method, path, String::from_utf8_lossy(&body).into_owned()))
}
