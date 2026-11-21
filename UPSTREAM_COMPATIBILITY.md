# Upstream structure and compatibility inventory

Noxmap is an independently authored Rust implementation in a GitHub fork of
`nmap/nmap`. This document records the architectural study used for feature
planning. It is not a source-code port and does not import upstream code,
scripts, databases, binaries, or assets.

## Upstream repository structure studied

| Upstream area | Responsibility | Noxmap direction |
| --- | --- | --- |
| Root scanner core and scan engines | Target handling, timing, port-state collection, raw and connect scans | `src/scanner.rs`, `src/policy.rs`, `src/targets.rs`; TCP connect engine implemented, other engines planned |
| `libnetutil`, `nbase`, `nsock` | Low-level networking, packet support, asynchronous I/O | Rust standard networking today; platform capability adapters remain planned |
| Service probes and service database | Active protocol identification | `src/service.rs`; original probe databases are not copied |
| OS fingerprinting core/database | Fingerprint collection and matching | `src/fingerprint.rs`; service-evidence inference only today |
| `scripts` and `nselib` | Script execution and shared libraries | `src/scripting.rs`; data-only, capability-scoped `.nox` scripts |
| `ncat`, `nping`, `ndiff` | Companion networking tools and output comparison | Monitoring diffs in `src/monitoring.rs`; companion tools are separate future surfaces |
| `zenmap` | Graphical UI | A Noxmap desktop UI is future work |
| `docs`, `tests`, platform build folders | Documentation, tests, packaging | README, architecture, unit tests; release packaging is not implemented |

## Behavioral-compatibility status

Implemented: TCP connect scanning, bounded port lists/ranges, hostname scope
validation, limited protocol identification, normal/XML/JSON reports, bounded
IPv4 CIDR expansion, target-list parsing, monitoring snapshots, and local API.

Not implemented: raw packet scan families, UDP scanning, exhaustive service
probe databases, active OS detection, platform-native privilege handling,
full script compatibility, distributed companion tools, desktop UI, and
installer packaging.

## Release inventory

As of 2026-11-20, the GitHub Releases endpoint for `nmap/nmap` returns an
empty collection. Therefore Noxmap does not include, mirror, relabel, or claim
any upstream GitHub release artifact. Upstream tags and releases made through
other official distribution channels remain upstream material.

Noxmap will publish only independently built, versioned Rust artifacts after
platform packaging, license review, reproducible builds, checksums, and
release notes are in place.
