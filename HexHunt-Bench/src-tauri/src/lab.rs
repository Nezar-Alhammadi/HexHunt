use std::{
    io::{BufRead, BufReader, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

#[derive(Clone)]
pub struct LabRoute {
    pub method: String,
    pub path: String,
    pub status: String,
    pub content_type: String,
    pub body: String,
    pub headers: Vec<(String, String)>,
}

pub struct BenchmarkLab {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl BenchmarkLab {
    pub fn start(
        build_routes: impl FnOnce(&str, u16) -> Vec<LabRoute>,
    ) -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let base_url = format!("http://{address}");
        let routes = Arc::new(build_routes(&base_url, address.port()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = stop.clone();
        let thread_routes = routes.clone();
        let thread = thread::spawn(move || {
            while !thread_stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => handle_connection(stream, &thread_routes),
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
}

impl Drop for BenchmarkLab {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn handle_connection(mut stream: TcpStream, routes: &[LabRoute]) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
    let mut reader = BufReader::new(&mut stream);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() {
        return;
    }
    let mut parts = request_line.split_whitespace();
    let Some(method) = parts.next() else {
        return;
    };
    let Some(raw_path) = parts.next() else {
        return;
    };
    let path = raw_path.split('?').next().unwrap_or(raw_path);
    let route = routes.iter().find(|route| {
        (route.method.eq_ignore_ascii_case(method)
            || (method.eq_ignore_ascii_case("HEAD")
                && route.method.eq_ignore_ascii_case("GET")))
            && route.path == path
    });
    let fallback = LabRoute {
        method: "GET".into(),
        path: path.into(),
        status: "404 Not Found".into(),
        content_type: "application/json".into(),
        body: r#"{"error":"not_found"}"#.into(),
        headers: vec![],
    };
    let route = route.unwrap_or(&fallback);
    let mut response = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
        route.status,
        route.content_type,
        route.body.len()
    );
    for (name, value) in &route.headers {
        response.push_str(&format!("{name}: {value}\r\n"));
    }
    response.push_str("\r\n");
    let _ = stream.write_all(response.as_bytes());
    if !method.eq_ignore_ascii_case("HEAD") {
        let _ = stream.write_all(route.body.as_bytes());
    }
    let _ = stream.flush();
}
