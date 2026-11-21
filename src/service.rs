use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceIdentity {
    pub name: String,
    pub evidence: String,
}

pub fn identify(stream: &mut TcpStream, port: u16, timeout: Duration) -> Option<ServiceIdentity> {
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let probe = match port {
        80 | 8000 | 8008 | 8080 | 8888 => {
            Some(b"HEAD / HTTP/1.0\r\nHost: noxmap.local\r\n\r\n".as_slice())
        }
        6379 => Some(b"PING\r\n".as_slice()),
        11211 => Some(b"version\r\n".as_slice()),
        _ => None,
    };
    if let Some(probe) = probe {
        let _ = stream.write_all(probe);
    }
    let mut buffer = [0_u8; 512];
    let read = stream.read(&mut buffer).ok()?;
    let banner = String::from_utf8_lossy(&buffer[..read]).replace(['\r', '\n'], " ");
    let trimmed = banner.trim().chars().take(160).collect::<String>();
    if trimmed.is_empty() {
        return port_hint(port);
    }
    let name = if trimmed.starts_with("SSH-") {
        "ssh"
    } else if trimmed.starts_with("HTTP/") {
        "http"
    } else if trimmed.starts_with("220 ") {
        "smtp-or-ftp"
    } else if trimmed.starts_with("+PONG") {
        "redis"
    } else if trimmed.starts_with("VERSION ") {
        "memcached"
    } else if trimmed.starts_with("+OK") && port == 110 {
        "pop3"
    } else if trimmed.starts_with("* OK") && port == 143 {
        "imap"
    } else {
        return port_hint(port).map(|mut hint| {
            hint.evidence = trimmed;
            hint
        });
    };
    Some(ServiceIdentity {
        name: name.into(),
        evidence: trimmed,
    })
}

#[must_use]
pub fn port_hint(port: u16) -> Option<ServiceIdentity> {
    let name = match port {
        22 => "ssh",
        80 | 8000 | 8008 | 8080 | 8888 => "http",
        443 => "https",
        53 => "dns",
        25 => "smtp",
        110 => "pop3",
        143 => "imap",
        3306 => "mysql",
        5432 => "postgresql",
        6379 => "redis",
        11211 => "memcached",
        _ => return None,
    };
    Some(ServiceIdentity {
        name: name.into(),
        evidence: format!("well-known TCP port {port}"),
    })
}

