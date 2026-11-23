use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// A protocol family identified from a bounded, non-authenticating exchange.
///
/// `evidence` is intentionally short and printable so it can be persisted in
/// local snapshots and reports without retaining arbitrary server output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceIdentity {
    pub name: String,
    pub evidence: String,
    pub product: Option<String>,
    pub version: Option<String>,
}

/// Identifies a small set of common TCP services after a successful connect.
///
/// This is an original, deliberately conservative probe set. It never sends
/// credentials, changes server state, follows redirects, or uses a copied
/// fingerprint database. Banner-first protocols are read before a capability
/// query; request-first protocols receive one bounded read-only query.
pub fn identify(stream: &mut TcpStream, port: u16, timeout: Duration) -> Option<ServiceIdentity> {
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    let mut evidence = if is_banner_first(port) {
        read_evidence(stream)
    } else {
        String::new()
    };

    if evidence.is_empty() {
        if let Some(probe) = safe_probe(port) {
            let _ = stream.write_all(probe);
            evidence = read_evidence(stream);
        }
    }

    classify_evidence(port, &evidence).or_else(|| port_hint(port))
}

fn is_banner_first(port: u16) -> bool {
    matches!(port, 21 | 22 | 25 | 110 | 143 | 5900)
}

fn safe_probe(port: u16) -> Option<&'static [u8]> {
    match port {
        21 => Some(b"SYST\r\n"),
        25 => Some(b"EHLO noxmap.local\r\n"),
        80 | 8000 | 8008 | 8080 | 8888 => Some(b"HEAD / HTTP/1.0\r\nHost: noxmap.local\r\n\r\n"),
        110 => Some(b"CAPA\r\n"),
        143 => Some(b"a001 CAPABILITY\r\n"),
        6379 => Some(b"PING\r\n"),
        11211 => Some(b"version\r\n"),
        _ => None,
    }
}

fn read_evidence(stream: &mut TcpStream) -> String {
    let mut buffer = [0_u8; 512];
    let Ok(read) = stream.read(&mut buffer) else {
        return String::new();
    };
    compact_evidence(&buffer[..read])
}

fn compact_evidence(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(160)
        .collect()
}

fn classify_evidence(port: u16, evidence: &str) -> Option<ServiceIdentity> {
    if evidence.is_empty() {
        return None;
    }
    let lower = evidence.to_ascii_lowercase();
    let name = if evidence.starts_with("SSH-") {
        "ssh"
    } else if evidence.starts_with("HTTP/") {
        "http"
    } else if evidence.starts_with("+PONG") {
        "redis"
    } else if evidence.starts_with("VERSION ") {
        "memcached"
    } else if evidence.starts_with("RFB ") {
        "vnc"
    } else if evidence.starts_with("AMQP") {
        "amqp"
    } else if (evidence.starts_with("+OK") || evidence.starts_with("-ERR")) && port == 110 {
        "pop3"
    } else if (evidence.starts_with("* OK") || evidence.starts_with("* CAPABILITY")) && port == 143
    {
        "imap"
    } else if evidence.starts_with("220 ") {
        if port == 21 || lower.contains("ftp") {
            "ftp"
        } else if port == 25 || lower.contains("smtp") || lower.contains("esmtp") {
            "smtp"
        } else {
            "smtp-or-ftp"
        }
    } else if (evidence.starts_with("250-") || evidence.starts_with("250 ")) && port == 25 {
        "smtp"
    } else if port == 21 && (evidence.starts_with("215 ") || evidence.starts_with("211 ")) {
        "ftp"
    } else {
        return None;
    };
    let (product, version) = product_version(name, evidence);
    Some(ServiceIdentity {
        name: name.into(),
        evidence: evidence.into(),
        product,
        version,
    })
}

fn product_version(service: &str, evidence: &str) -> (Option<String>, Option<String>) {
    let token = if service == "ssh" {
        evidence
            .split_whitespace()
            .next()
            .and_then(|value| value.splitn(3, '-').nth(2))
    } else if service == "http" {
        evidence
            .split("Server: ")
            .nth(1)
            .and_then(|value| value.split_whitespace().next())
    } else if matches!(service, "ftp" | "smtp") {
        evidence.split_whitespace().nth(1)
    } else {
        None
    };
    let Some(token) = token else {
        return (None, None);
    };
    let (product, version) = if service == "ssh" {
        token.split_once('_').unwrap_or((token, ""))
    } else {
        token.split_once('/').unwrap_or((token, ""))
    };
    let product = product.trim_matches(|character: char| {
        !character.is_ascii_alphanumeric() && character != '-' && character != '_'
    });
    if product.is_empty() || product.chars().all(|character| character.is_ascii_digit()) {
        return (None, None);
    }
    let version = version.trim_matches(|character: char| {
        !character.is_ascii_alphanumeric()
            && character != '.'
            && character != '-'
            && character != '_'
    });
    (
        Some(product.into()),
        (!version.is_empty()).then(|| version.into()),
    )
}

#[must_use]
pub fn port_hint(port: u16) -> Option<ServiceIdentity> {
    let name = match port {
        21 => "ftp",
        22 => "ssh",
        80 | 8000 | 8008 | 8080 | 8888 => "http",
        443 => "https",
        53 => "dns",
        25 => "smtp",
        110 => "pop3",
        143 => "imap",
        3306 => "mysql",
        5432 => "postgresql",
        5900 => "vnc",
        6379 => "redis",
        11211 => "memcached",
        _ => return None,
    };
    Some(ServiceIdentity {
        name: name.into(),
        evidence: format!("well-known TCP port {port}"),
        product: None,
        version: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_common_banner_protocols() {
        assert_eq!(
            classify_evidence(22, "SSH-2.0-OpenSSH_9.6"),
            Some(ServiceIdentity {
                name: "ssh".into(),
                evidence: "SSH-2.0-OpenSSH_9.6".into(),
                product: Some("OpenSSH".into()),
                version: Some("9.6".into()),
            })
        );
        assert_eq!(
            classify_evidence(21, "220 ProFTPD ready"),
            Some(ServiceIdentity {
                name: "ftp".into(),
                evidence: "220 ProFTPD ready".into(),
                product: Some("ProFTPD".into()),
                version: None
            })
        );
        assert_eq!(
            classify_evidence(25, "220 mail.example ESMTP"),
            Some(ServiceIdentity {
                name: "smtp".into(),
                evidence: "220 mail.example ESMTP".into(),
                product: Some("mail.example".into()),
                version: None
            })
        );
        assert_eq!(
            classify_evidence(5900, "RFB 003.008"),
            Some(ServiceIdentity {
                name: "vnc".into(),
                evidence: "RFB 003.008".into(),
                product: None,
                version: None
            })
        );
    }

    #[test]
    fn compacts_untrusted_banner_bytes() {
        assert_eq!(
            compact_evidence(b"HTTP/1.1 200 OK\r\nServer: example\0\n"),
            "HTTP/1.1 200 OK Server: example"
        );
    }

    #[test]
    fn retains_port_hint_when_a_service_does_not_reply() {
        assert_eq!(port_hint(443).unwrap().name, "https");
        assert!(classify_evidence(443, "").is_none());
    }

    #[test]
    fn extracts_product_and_version_without_guessing() {
        assert_eq!(
            product_version("http", "HTTP/1.1 200 OK Server: nginx/1.27.4"),
            (Some("nginx".into()), Some("1.27.4".into()))
        );
        assert_eq!(product_version("redis", "+PONG"), (None, None));
    }
}
