use crate::scanner::{PortState, ScanSnapshot};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangeKind {
    PortOpened,
    PortClosed,
    PortAdded,
    PortRemoved,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanChange {
    pub port: u16,
    pub kind: ChangeKind,
}

#[must_use]
pub fn diff(previous: &ScanSnapshot, current: &ScanSnapshot) -> Vec<ScanChange> {
    let mut changes = Vec::new();
    for now in &current.ports {
        match previous.ports.iter().find(|item| item.port == now.port) {
            None => changes.push(ScanChange {
                port: now.port,
                kind: ChangeKind::PortAdded,
            }),
            Some(before) => match (&before.state, &now.state) {
                (PortState::Open, PortState::Open)
                | (PortState::Closed, PortState::Closed)
                | (PortState::Filtered, PortState::Filtered)
                | (PortState::Unreachable, PortState::Unreachable)
                | (PortState::Unresolved, PortState::Unresolved) => {}
                (PortState::Open, _) => changes.push(ScanChange {
                    port: now.port,
                    kind: ChangeKind::PortClosed,
                }),
                (_, PortState::Open) => changes.push(ScanChange {
                    port: now.port,
                    kind: ChangeKind::PortOpened,
                }),
                _ => {}
            },
        }
    }
    for before in &previous.ports {
        if !current.ports.iter().any(|item| item.port == before.port) {
            changes.push(ScanChange {
                port: before.port,
                kind: ChangeKind::PortRemoved,
            });
        }
    }
    changes.sort_by_key(|change| change.port);
    changes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::PortResult;

    fn snapshot(ports: Vec<(u16, PortState)>) -> ScanSnapshot {
        ScanSnapshot {
            target: "loopback".into(),
            resolved_address: None,
            scanned_at_unix_ms: 0,
            ports: ports
                .into_iter()
                .map(|(port, state)| PortResult {
                    port,
                    state,
                    latency_ms: None,
                    service: None,
                })
                .collect(),
        }
    }

    #[test]
    fn tracks_state_and_inventory_changes() {
        let changes = diff(
            &snapshot(vec![(22, PortState::Open), (80, PortState::Closed)]),
            &snapshot(vec![(22, PortState::Closed), (443, PortState::Open)]),
        );
        assert_eq!(
            changes,
            vec![
                ScanChange {
                    port: 22,
                    kind: ChangeKind::PortClosed,
                },
                ScanChange {
                    port: 80,
                    kind: ChangeKind::PortRemoved,
                },
                ScanChange {
                    port: 443,
                    kind: ChangeKind::PortAdded,
                },
            ]
        );
    }
}

