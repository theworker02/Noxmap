use crate::policy::ScanPolicy;
use crate::scanner::{ScanOptions, ScanSnapshot, Scanner, parse_ports};
use crate::storage::SnapshotStore;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};

#[derive(Debug, Clone)]
pub struct ApiScanRequest {
    pub target: String,
    pub ports: Vec<u16>,
}
#[derive(Debug, Clone)]
pub enum ApiResponse {
    Health { status: &'static str },
    Scan(ScanSnapshot),
    Error { code: &'static str, message: String },
}

/// Transport-independent contract. A future HTTP adapter must bind to loopback by default.
pub trait NoxmapApi {
    fn health(&self) -> ApiResponse;
    fn scan(&self, request: ApiScanRequest) -> ApiResponse;
}

/// Runs a minimal local HTTP API on a loopback address.
///
/// # Errors
///
/// Returns an error when the listener, storage, or request processing cannot start.
pub fn serve_loopback(port: u16, policy: ScanPolicy, store: &SnapshotStore) -> Result<(), String> {
    let listener = TcpListener::bind(("127.0.0.1", port))
        .map_err(|error| format!("could not bind Noxmap API: {error}"))?;
    eprintln!("Noxmap API listening on http://127.0.0.1:{port}");
    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                if let Err(error) = handle_connection(stream, policy, store) {
                    eprintln!("api request failed: {error}");
                }
            }
            Err(error) => eprintln!("api accept failed: {error}"),
        }
    }
    Ok(())
}

fn handle_connection(
    mut stream: TcpStream,
    policy: ScanPolicy,
    store: &SnapshotStore,
) -> Result<(), String> {
    let mut request = String::new();
    BufReader::new(stream.try_clone().map_err(|error| error.to_string())?)
        .read_line(&mut request)
        .map_err(|error| error.to_string())?;
    let mut request_parts = request.split_whitespace();
    let method = request_parts.next().ok_or("malformed HTTP request")?;
    let target = request_parts.next().ok_or("malformed HTTP request")?;
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let query = query_values(query);
    let (status, body) = match (method, path) {
        ("GET", "/health") => (
            "200 OK",
            "{\"status\":\"ok\",\"service\":\"noxmap\"}".into(),
        ),
        ("GET", "/v1/latest") => {
            let requested = query
                .get("target")
                .ok_or("target query parameter is required")?;
            match store.latest(requested)? {
                Some(snapshot) => ("200 OK", snapshot_json(&snapshot)),
                None => ("404 Not Found", "{\"error\":\"no stored snapshot\"}".into()),
            }
        }
        ("POST", "/v1/scan") => {
            let requested = query
                .get("target")
                .ok_or("target query parameter is required")?;
            let requested_ports = query.get("ports").map_or_else(
                || Ok(ScanOptions::default().ports),
                |value| parse_ports(value),
            );
            let options = ScanOptions {
                ports: requested_ports?,
                ..ScanOptions::default()
            };
            let snapshot = Scanner::new(policy).scan(requested, &options)?;
            store.append(&snapshot)?;
            ("200 OK", snapshot_json(&snapshot))
        }
        _ => ("404 Not Found", "{\"error\":\"route not found\"}".into()),
    };
    write!(stream, "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).map_err(|error| error.to_string())?;
    Ok(())
}

fn query_values(query: &str) -> std::collections::HashMap<String, String> {
    query
        .split('&')
        .filter_map(|item| item.split_once('='))
        .map(|(key, value)| (key.to_string(), percent_decode(value)))
        .collect()
}
fn percent_decode(value: &str) -> String {
    value
        .replace("%2C", ",")
        .replace("%3A", ":")
        .replace("%2E", ".")
}
fn snapshot_json(snapshot: &ScanSnapshot) -> String {
    let ports = snapshot
        .ports
        .iter()
        .map(|port| {
            let state = match port.state {
                crate::scanner::PortState::Open => "open",
                crate::scanner::PortState::Closed => "closed",
                crate::scanner::PortState::Filtered => "filtered",
                crate::scanner::PortState::Unreachable => "unreachable",
                crate::scanner::PortState::Unresolved => "unresolved",
            };
            format!("{{\"port\":{},\"state\":\"{}\"}}", port.port, state)
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"target\":\"{}\",\"scanned_at_unix_ms\":{},\"ports\":[{}]}}",
        snapshot.target.replace('"', ""),
        snapshot.scanned_at_unix_ms,
        ports
    )
}

