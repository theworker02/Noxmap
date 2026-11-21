use crate::scanner::{PortState, ScanOptions, Scanner};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostStatus {
    Responsive,
    NoResponse,
    Unknown,
}
#[derive(Debug, Clone)]
pub struct DiscoveryResult {
    pub target: String,
    pub status: HostStatus,
    pub evidence: String,
}

/// Performs bounded TCP reachability checks. A connection refusal still proves a
/// host responded, while timeouts and unresolved errors are not treated as alive.
///
/// # Errors
///
/// Returns an error if target resolution or the underlying bounded scan fails.
pub fn discover(
    scanner: &Scanner,
    target: &str,
    ports: Vec<u16>,
) -> Result<DiscoveryResult, String> {
    let options = ScanOptions {
        ports,
        identify_services: false,
        ..ScanOptions::default()
    };
    let snapshot = scanner.scan(target, &options)?;
    let responsive = snapshot
        .ports
        .iter()
        .find(|port| matches!(port.state, PortState::Open | PortState::Closed));
    Ok(match responsive {
        Some(port) => DiscoveryResult {
            target: target.into(),
            status: HostStatus::Responsive,
            evidence: format!("tcp/{} returned {:?}", port.port, port.state),
        },
        None if snapshot
            .ports
            .iter()
            .any(|port| port.state == PortState::Filtered) =>
        {
            DiscoveryResult {
                target: target.into(),
                status: HostStatus::NoResponse,
                evidence: "TCP probe timed out or was filtered".into(),
            }
        }
        None => DiscoveryResult {
            target: target.into(),
            status: HostStatus::Unknown,
            evidence: "TCP reachability could not be determined".into(),
        },
    })
}

