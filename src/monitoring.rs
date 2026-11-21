use crate::scanner::{PortState, ScanSnapshot};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangeKind {
    PortOpened,
    PortClosed,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanChange {
    pub port: u16,
    pub kind: ChangeKind,
}

#[must_use]
pub fn diff(previous: &ScanSnapshot, current: &ScanSnapshot) -> Vec<ScanChange> {
    current
        .ports
        .iter()
        .filter_map(|now| {
            let before = previous.ports.iter().find(|item| item.port == now.port)?;
            match (&before.state, &now.state) {
                (PortState::Open, PortState::Open)
                | (PortState::Closed, PortState::Closed)
                | (PortState::Filtered, PortState::Filtered)
                | (PortState::Unreachable, PortState::Unreachable)
                | (PortState::Unresolved, PortState::Unresolved) => None,
                (PortState::Open, _) => Some(ScanChange {
                    port: now.port,
                    kind: ChangeKind::PortClosed,
                }),
                (_, PortState::Open) => Some(ScanChange {
                    port: now.port,
                    kind: ChangeKind::PortOpened,
                }),
                _ => None,
            }
        })
        .collect()
}

