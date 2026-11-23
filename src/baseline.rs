//! Declarative desired-state baselines for local network assurance.

use crate::scanner::{PortState, ScanOptions, ScanSnapshot};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Baseline {
    pub target: String,
    expectations: BTreeMap<u16, ExpectedState>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpectedState {
    Open,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditViolation {
    pub port: u16,
    pub expected: ExpectedState,
    pub observed: PortState,
}

/// Loads one text baseline from disk.
///
/// # Errors
///
/// Returns an error if the file cannot be read or violates the baseline format.
pub fn load(path: &Path) -> Result<Baseline, String> {
    let source = std::fs::read_to_string(path)
        .map_err(|error| format!("could not read baseline: {error}"))?;
    parse(&source)
}

/// Parses a versioned Noxmap baseline document.
///
/// The supported keys are `schema=1`, `target=...`, `expect_open=...`, and
/// `expect_closed=...`. Port values use Noxmap's comma/range syntax.
///
/// # Errors
///
/// Returns an error for unknown keys, missing required fields, invalid ports,
/// conflicting expectations, or unsupported schemas.
pub fn parse(source: &str) -> Result<Baseline, String> {
    let mut schema = None;
    let mut target = None;
    let mut expectations = BTreeMap::new();
    for line in source.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("invalid baseline line: {line}"))?;
        match key.trim() {
            "schema" => schema = Some(value.trim().to_string()),
            "target" => target = Some(value.trim().to_string()),
            "expect_open" => add_expectations(&mut expectations, value, ExpectedState::Open)?,
            "expect_closed" => {
                add_expectations(&mut expectations, value, ExpectedState::Closed)?;
            }
            unknown => return Err(format!("unknown baseline key: {unknown}")),
        }
    }
    if schema.as_deref() != Some("1") {
        return Err("baseline requires schema=1".into());
    }
    let target = target.ok_or("baseline requires target=<hostname-or-ip>")?;
    if target.is_empty() {
        return Err("baseline target must not be empty".into());
    }
    if expectations.is_empty() {
        return Err("baseline requires at least one expected port".into());
    }
    Ok(Baseline {
        target,
        expectations,
    })
}

impl Baseline {
    #[must_use]
    pub fn scan_options(&self) -> ScanOptions {
        ScanOptions {
            ports: self.expectations.keys().copied().collect(),
            ..ScanOptions::default()
        }
    }
}

/// Compares a snapshot against the baseline expectations.
#[must_use]
pub fn evaluate(baseline: &Baseline, snapshot: &ScanSnapshot) -> Vec<AuditViolation> {
    baseline
        .expectations
        .iter()
        .filter_map(|(port, expected)| {
            let observed = snapshot
                .ports
                .iter()
                .find(|result| result.port == *port)
                .map_or(PortState::Unresolved, |result| result.state.clone());
            let matches = matches!(
                (expected, &observed),
                (ExpectedState::Open, PortState::Open) | (ExpectedState::Closed, PortState::Closed)
            );
            (!matches).then_some(AuditViolation {
                port: *port,
                expected: *expected,
                observed,
            })
        })
        .collect()
}

fn add_expectations(
    expectations: &mut BTreeMap<u16, ExpectedState>,
    input: &str,
    state: ExpectedState,
) -> Result<(), String> {
    for port in crate::scanner::parse_ports(input)? {
        if expectations.insert(port, state).is_some() {
            return Err(format!("port {port} appears in more than one expectation"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::PortResult;

    #[test]
    fn parses_and_evaluates_a_baseline() {
        let baseline = parse("schema=1\ntarget=loopback\nexpect_open=80\nexpect_closed=22,23\n")
            .expect("baseline should parse");
        let snapshot = ScanSnapshot {
            target: "loopback".into(),
            resolved_address: None,
            scanned_at_unix_ms: 0,
            ports: vec![
                result(22, PortState::Open),
                result(23, PortState::Closed),
                result(80, PortState::Open),
            ],
        };
        assert_eq!(
            evaluate(&baseline, &snapshot),
            vec![AuditViolation {
                port: 22,
                expected: ExpectedState::Closed,
                observed: PortState::Open,
            }]
        );
    }

    #[test]
    fn rejects_conflicting_expectations() {
        assert!(parse("schema=1\ntarget=loopback\nexpect_open=80\nexpect_closed=80\n").is_err());
    }

    fn result(port: u16, state: PortState) -> PortResult {
        PortResult {
            port,
            state,
            latency_ms: None,
            service: None,
        }
    }
}

