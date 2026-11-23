use crate::scanner::{PortState, ScanSnapshot};
use std::fmt::Write;

#[must_use]
pub fn normal(snapshot: &ScanSnapshot) -> String {
    let address = snapshot
        .resolved_address
        .map_or_else(|| "unresolved".into(), |item| item.ip().to_string());
    let mut output = format!(
        "Noxmap scan report for {} ({address})\nPORT      STATE       SERVICE      EVIDENCE\n",
        snapshot.target
    );
    for port in &snapshot.ports {
        let _ = writeln!(
            output,
            "{}/tcp {:<11} {:<12} {}",
            port.port,
            state_name(&port.state),
            port.service
                .as_ref()
                .map_or("unknown", |service| service.name.as_str()),
            port.service
                .as_ref()
                .map_or("", |service| service.evidence.as_str())
        );
    }
    output
}

#[must_use]
pub fn xml(snapshot: &ScanSnapshot) -> String {
    let address = snapshot
        .resolved_address
        .map_or_else(String::new, |item| item.ip().to_string());
    let ports = snapshot.ports.iter().map(|port| format!("    <port protocol=\"tcp\" number=\"{}\"><state value=\"{}\"/><service name=\"{}\" product=\"{}\" version=\"{}\" evidence=\"{}\"/></port>", port.port, state_name(&port.state), port.service.as_ref().map_or("unknown", |service| service.name.as_str()), port.service.as_ref().and_then(|service| service.product.as_deref()).map_or_else(String::new, escape), port.service.as_ref().and_then(|service| service.version.as_deref()).map_or_else(String::new, escape), port.service.as_ref().map_or_else(String::new, |service| escape(&service.evidence)))).collect::<Vec<_>>().join("\n");
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<noxmaprun schema=\"1\">\n  <host target=\"{}\" address=\"{}\">\n  <ports>\n{}\n  </ports>\n  </host>\n</noxmaprun>\n",
        escape(&snapshot.target),
        escape(&address),
        ports
    )
}

/// Produces a stable JSON representation of one Noxmap scan snapshot.
///
/// The serializer is implemented locally to keep the core dependency-light;
/// strings are escaped according to the JSON string grammar.
#[must_use]
pub fn json(snapshot: &ScanSnapshot) -> String {
    let address = snapshot.resolved_address.map_or_else(
        || "null".to_string(),
        |item| json_string(&item.ip().to_string()),
    );
    let ports = snapshot
        .ports
        .iter()
        .map(|port| {
            let latency = port
                .latency_ms
                .map_or_else(|| "null".to_string(), |value| value.to_string());
            let service = port.service.as_ref().map_or_else(
                || "null".to_string(),
                |service| {
                    format!(
                        "{{\"name\":{},\"evidence\":{},\"product\":{},\"version\":{}}}",
                        json_string(&service.name),
                        json_string(&service.evidence),
                        optional_json_string(service.product.as_deref()),
                        optional_json_string(service.version.as_deref())
                    )
                },
            );
            format!(
                "{{\"port\":{},\"protocol\":\"tcp\",\"state\":{},\"latency_ms\":{latency},\"service\":{service}}}",
                port.port,
                json_string(state_name(&port.state)),
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"schema\":1,\"target\":{},\"address\":{address},\"scanned_at_unix_ms\":{},\"ports\":[{ports}]}}",
        json_string(&snapshot.target),
        snapshot.scanned_at_unix_ms,
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

fn json_string(value: &str) -> String {
    let mut output = String::with_capacity(value.len() + 2);
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character.is_control() => {
                let _ = write!(output, "\\u{:04x}", u32::from(character));
            }
            character => output.push(character),
        }
    }
    output.push('"');
    output
}

fn optional_json_string(value: Option<&str>) -> String {
    value.map_or_else(|| "null".into(), json_string)
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
    #[test]
    fn json_escapes_string_fields_and_includes_service_evidence() {
        let snapshot = ScanSnapshot {
            target: "host\"name".into(),
            resolved_address: None,
            scanned_at_unix_ms: 12,
            ports: vec![crate::scanner::PortResult {
                port: 80,
                state: PortState::Open,
                latency_ms: Some(3),
                service: Some(crate::service::ServiceIdentity {
                    name: "http".into(),
                    evidence: "HTTP/1.1\r\n".into(),
                    product: None,
                    version: None,
                }),
            }],
        };
        assert_eq!(
            json(&snapshot),
            "{\"schema\":1,\"target\":\"host\\\"name\",\"address\":null,\"scanned_at_unix_ms\":12,\"ports\":[{\"port\":80,\"protocol\":\"tcp\",\"state\":\"open\",\"latency_ms\":3,\"service\":{\"name\":\"http\",\"evidence\":\"HTTP/1.1\\r\\n\",\"product\":null,\"version\":null}}]}"
        );
    }
}
