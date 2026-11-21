use crate::scanner::{PortState, ScanSnapshot};
use std::fmt::Write;

#[must_use]
pub fn normal(snapshot: &ScanSnapshot) -> String {
    let address = snapshot
        .resolved_address
        .map_or_else(|| "unresolved".into(), |item| item.ip().to_string());
    let mut output = format!(
        "Noxmap scan report for {} ({address})\nPORT      STATE       SERVICE\n",
        snapshot.target
    );
    for port in &snapshot.ports {
        let _ = writeln!(
            output,
            "{}/tcp {:<11} {}",
            port.port,
            state_name(&port.state),
            port.service
                .as_ref()
                .map_or("unknown", |service| service.name.as_str())
        );
    }
    output
}

#[must_use]
pub fn xml(snapshot: &ScanSnapshot) -> String {
    let address = snapshot
        .resolved_address
        .map_or_else(String::new, |item| item.ip().to_string());
    let ports = snapshot.ports.iter().map(|port| format!("    <port protocol=\"tcp\" number=\"{}\"><state value=\"{}\"/><service name=\"{}\"/></port>", port.port, state_name(&port.state), port.service.as_ref().map_or("unknown", |service| service.name.as_str()))).collect::<Vec<_>>().join("\n");
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<noxmaprun schema=\"1\">\n  <host target=\"{}\" address=\"{}\">\n  <ports>\n{}\n  </ports>\n  </host>\n</noxmaprun>\n",
        escape(&snapshot.target),
        escape(&address),
        ports
    )
}

/// Produces a compact, line-oriented inventory record suitable for grep/awk
/// style tooling. This is Noxmap's own stable text format, not a byte-for-byte
/// reproduction of another scanner's report dialect.
#[must_use]
pub fn grepable(snapshot: &ScanSnapshot) -> String {
    let address = snapshot
        .resolved_address
        .map_or_else(|| "unresolved".into(), |item| item.ip().to_string());
    let ports = snapshot
        .ports
        .iter()
        .map(|port| {
            let service = port
                .service
                .as_ref()
                .map_or("unknown", |service| service.name.as_str());
            format!(
                "{}/{}/tcp//{}",
                port.port,
                state_name(&port.state),
                service.replace(['/', ','], "_")
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!("Host: {} ({address})\tPorts: {ports}\n", snapshot.target)
}

#[must_use]
pub fn state_name(state: &PortState) -> &'static str {
    match state {
        PortState::Open => "open",
        PortState::Closed => "closed",
        PortState::Filtered => "filtered",
        PortState::Unreachable => "unreachable",
        PortState::Unresolved => "unresolved",
    }
}
fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn escapes_xml_attributes() {
        assert_eq!(escape("a<&>\""), "a&lt;&amp;&gt;&quot;");
    }
    #[test]
    fn grepable_report_has_one_port_record_per_result() {
        let snapshot = ScanSnapshot {
            target: "loopback".into(),
            resolved_address: None,
            scanned_at_unix_ms: 0,
            ports: vec![crate::scanner::PortResult {
                port: 80,
                state: PortState::Open,
                latency_ms: None,
                service: None,
            }],
        };
        assert_eq!(
            grepable(&snapshot),
            "Host: loopback (unresolved)\tPorts: 80/open/tcp//unknown\n"
        );
    }
}

