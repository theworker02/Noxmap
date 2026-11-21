use crate::policy::ScanPolicy;
use crate::service::{ServiceIdentity, identify, port_hint};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub ports: Vec<u16>,
    pub timeout: Duration,
    pub concurrency: usize,
    pub identify_services: bool,
}
impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            ports: vec![22, 80, 443, 445, 3389, 5432, 8080],
            timeout: Duration::from_millis(800),
            concurrency: 32,
            identify_services: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    Unreachable,
    Unresolved,
}
#[derive(Debug, Clone)]
pub struct PortResult {
    pub port: u16,
    pub state: PortState,
    pub latency_ms: Option<u128>,
    pub service: Option<ServiceIdentity>,
}
#[derive(Debug, Clone)]
pub struct ScanSnapshot {
    pub target: String,
    pub resolved_address: Option<SocketAddr>,
    pub scanned_at_unix_ms: u128,
    pub ports: Vec<PortResult>,
}

pub struct Scanner {
    policy: ScanPolicy,
}
impl Scanner {
    #[must_use]
    pub fn new(policy: ScanPolicy) -> Self {
        Self { policy }
    }
    /// Performs a bounded TCP connect scan.
    ///
    /// # Errors
    ///
    /// Returns an error if policy validation or target resolution fails.
    ///
    /// # Panics
    ///
    /// Panics if an internal worker queue mutex is poisoned.
    pub fn scan(&self, target: &str, options: &ScanOptions) -> Result<ScanSnapshot, String> {
        self.policy
            .validate(target, options.ports.len(), options.concurrency)?;
        let addresses = format!("{target}:0")
            .to_socket_addrs()
            .map_err(|error| format!("could not resolve target: {error}"))?
            .collect::<Vec<_>>();
        let base = addresses
            .into_iter()
            .next()
            .ok_or_else(|| "target resolved to no addresses".to_string())?;
        self.policy.validate_resolved(base.ip())?;
        let (sender, receiver) = mpsc::channel();
        let queue = Arc::new(Mutex::new(options.ports.clone().into_iter()));
        let workers = options.concurrency.min(options.ports.len());
        thread::scope(|scope| {
            for _ in 0..workers {
                let sender = sender.clone();
                let queue = Arc::clone(&queue);
                let timeout = options.timeout;
                let services = options.identify_services;
                scope.spawn(move || {
                    loop {
                        let Some(port) = queue.lock().expect("work queue poisoned").next() else {
                            break;
                        };
                        let address = SocketAddr::new(base.ip(), port);
                        let started = Instant::now();
                        let result = match TcpStream::connect_timeout(&address, timeout) {
                            Ok(mut stream) => PortResult {
                                port,
                                state: PortState::Open,
                                latency_ms: Some(started.elapsed().as_millis()),
                                service: if services {
                                    identify(
                                        &mut stream,
                                        port,
                                        timeout.min(Duration::from_millis(500)),
                                    )
                                    .or_else(|| port_hint(port))
                                } else {
                                    None
                                },
                            },
                            Err(error) => PortResult {
                                port,
                                state: classify_connect_error(&error),
                                latency_ms: None,
                                service: None,
                            },
                        };
                        let _ = sender.send(result);
                    }
                });
            }
        });
        drop(sender);
        let mut ports: Vec<_> = receiver.into_iter().collect();
        ports.sort_by_key(|result| result.port);
        Ok(ScanSnapshot {
            target: target.into(),
            resolved_address: Some(base),
            scanned_at_unix_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|error| error.to_string())?
                .as_millis(),
            ports,
        })
    }
}

fn classify_connect_error(error: &std::io::Error) -> PortState {
    // Windows can surface WSAECONNREFUSED as `Other`; POSIX uses ECONNREFUSED.
    if matches!(error.raw_os_error(), Some(10061 | 111)) {
        return PortState::Closed;
    }
    match error.kind() {
        std::io::ErrorKind::ConnectionRefused
        | std::io::ErrorKind::ConnectionAborted
        | std::io::ErrorKind::ConnectionReset => PortState::Closed,
        std::io::ErrorKind::TimedOut => PortState::Filtered,
        std::io::ErrorKind::AddrNotAvailable
        | std::io::ErrorKind::NetworkUnreachable
        | std::io::ErrorKind::HostUnreachable => PortState::Unreachable,
        _ => PortState::Unresolved,
    }
}

/// Parses a comma-separated list of TCP ports and inclusive port ranges.
///
/// # Errors
///
/// Returns an error for malformed ports, invalid ranges, port zero, or an empty list.
pub fn parse_ports(input: &str) -> Result<Vec<u16>, String> {
    let mut ports = Vec::new();
    for part in input.split(',').filter(|value| !value.trim().is_empty()) {
        let value = part.trim();
        if let Some((start, end)) = value.split_once('-') {
            let start = start
                .parse::<u16>()
                .map_err(|_| format!("invalid port: {start}"))?;
            let end = end
                .parse::<u16>()
                .map_err(|_| format!("invalid port: {end}"))?;
            if start == 0 || end == 0 || start > end {
                return Err(format!("invalid range: {value}"));
            }
            ports.extend(start..=end);
        } else {
            let port = value
                .parse::<u16>()
                .map_err(|_| format!("invalid port: {value}"))?;
            if port == 0 {
                return Err("port 0 is not scannable".into());
            }
            ports.push(port);
        }
    }
    ports.sort_unstable();
    ports.dedup();
    if ports.is_empty() {
        return Err("no ports specified".into());
    }
    Ok(ports)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_and_deduplicates_ports() {
        assert_eq!(parse_ports("443,80-81,80").unwrap(), vec![80, 81, 443]);
    }
    #[test]
    fn rejects_invalid_ranges() {
        assert!(parse_ports("10-2").is_err());
    }
    #[test]
    fn classifies_connection_refusal_as_closed() {
        assert_eq!(
            classify_connect_error(&std::io::Error::from(std::io::ErrorKind::ConnectionRefused)),
            PortState::Closed
        );
    }
}

