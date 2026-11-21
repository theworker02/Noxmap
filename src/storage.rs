use crate::scanner::{PortResult, PortState, ScanSnapshot};
use crate::service::ServiceIdentity;
use std::fs::{OpenOptions, create_dir_all};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct SnapshotStore {
    path: PathBuf,
}
impl SnapshotStore {
    /// Opens or creates a local Noxmap state directory.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be created.
    pub fn open(directory: impl AsRef<Path>) -> Result<Self, String> {
        create_dir_all(directory.as_ref())
            .map_err(|error| format!("could not create state directory: {error}"))?;
        Ok(Self {
            path: directory.as_ref().join("snapshots.noxlog"),
        })
    }
    /// Appends a scan snapshot to the durable local journal.
    ///
    /// # Errors
    ///
    /// Returns an error if the journal cannot be opened or written.
    pub fn append(&self, snapshot: &ScanSnapshot) -> Result<(), String> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|error| format!("could not open snapshot store: {error}"))?;
        writeln!(file, "{}", encode(snapshot))
            .map_err(|error| format!("could not save snapshot: {error}"))
    }
    /// Reads the latest stored snapshot for one exact target.
    ///
    /// # Errors
    ///
    /// Returns an error if an existing journal cannot be read or decoded.
    pub fn latest(&self, target: &str) -> Result<Option<ScanSnapshot>, String> {
        let file = match std::fs::File::open(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(format!("could not read snapshot store: {error}")),
        };
        let mut found = None;
        for line in BufReader::new(file).lines() {
            let snapshot = decode(&line.map_err(|error| error.to_string())?)?;
            if snapshot.target == target {
                found = Some(snapshot);
            }
        }
        Ok(found)
    }
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}
fn encode(snapshot: &ScanSnapshot) -> String {
    let ports = snapshot
        .ports
        .iter()
        .map(|port| {
            format!(
                "{}:{}:{}:{}",
                port.port,
                state_code(&port.state),
                port.latency_ms.unwrap_or(0),
                port.service
                    .as_ref()
                    .map_or_else(String::new, |service| service.name.replace(':', ""))
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{}|{}|{}",
        snapshot.target.replace('|', ""),
        snapshot.scanned_at_unix_ms,
        ports
    )
}
fn decode(line: &str) -> Result<ScanSnapshot, String> {
    let mut chunks = line.splitn(3, '|');
    let target = chunks.next().ok_or("invalid state record")?.into();
    let scanned_at_unix_ms = chunks
        .next()
        .ok_or("invalid state record")?
        .parse()
        .map_err(|_| "invalid timestamp")?;
    let ports = chunks
        .next()
        .unwrap_or_default()
        .split(',')
        .filter(|item| !item.is_empty())
        .map(decode_port)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ScanSnapshot {
        target,
        resolved_address: None,
        scanned_at_unix_ms,
        ports,
    })
}
fn decode_port(value: &str) -> Result<PortResult, String> {
    let mut items = value.splitn(4, ':');
    let port = items
        .next()
        .ok_or("invalid port record")?
        .parse()
        .map_err(|_| "invalid port")?;
    let state = match items.next().ok_or("missing state")? {
        "o" => PortState::Open,
        "c" => PortState::Closed,
        "f" => PortState::Filtered,
        "r" => PortState::Unreachable,
        _ => PortState::Unresolved,
    };
    let latency = items.next().unwrap_or("0").parse::<u128>().unwrap_or(0);
    let service = items
        .next()
        .filter(|name| !name.is_empty())
        .map(|name| ServiceIdentity {
            name: name.into(),
            evidence: "stored result".into(),
        });
    Ok(PortResult {
        port,
        state,
        latency_ms: (latency != 0).then_some(latency),
        service,
    })
}
fn state_code(state: &PortState) -> &'static str {
    match state {
        PortState::Open => "o",
        PortState::Closed => "c",
        PortState::Filtered => "f",
        PortState::Unreachable => "r",
        PortState::Unresolved => "u",
    }
}

