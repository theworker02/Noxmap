# Changelog

## Unreleased

- Wire bounded IPv4 CIDR and Nmap-style `-iL` inventory input into `scan` and compatibility TCP-connect scans.
- Document the 256-target ceiling and keep continuous monitoring scoped to one target per process.
- Add exact-host and IPv4-CIDR exclusions through `--exclude` and `--excludefile`.
- Add Noxmap's line-oriented `-oG` report and document the supported compatibility command subset.

## 0.1.0 — 2026-11-20

- Established the clean-room Rust scanning core.
- Added bounded TCP connect scanning, port parsing, service evidence, and
  structured normal, JSON, and XML reports.
- Added persistent local monitoring, capability-scoped scripts, local API,
  conservative OS evidence, and platform topology adapter boundaries.
- Added target-list parsing, bounded IPv4 CIDR expansion, and TCP discovery.
- Added original Noxmap branding and upstream relationship documentation.

## Release policy

Noxmap releases represent independently built Rust artifacts only. Upstream
Nmap releases, binaries, scripts, service data, and licensing remain upstream
material and are not republished as Noxmap artifacts.

