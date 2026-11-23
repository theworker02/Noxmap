# Changelog

## Unreleased

- Expand Noxmap's original safe service-identification layer with banner-first
  FTP, SMTP, POP3, IMAP, VNC, and AMQP recognition plus bounded capability
  queries where a protocol requires an initial request.
- Preserve printable, length-bounded service evidence in normal, XML, and JSON
  reports, with XML attribute escaping for evidence.

## Unreleased

- Wire bounded IPv4 CIDR and Nmap-style `-iL` inventory input into `scan` and compatibility TCP-connect scans.
- Document the 256-target ceiling and keep continuous monitoring scoped to one target per process.
- Add exact-host and IPv4-CIDR exclusions through `--exclude` and `--excludefile`.
- Add Noxmap's line-oriented `-oG` report and document the supported compatibility command subset.
- Add Noxmap-maintained fast (`-F`) and bounded `--top-ports` TCP profiles, with explicit `-sV` service identification in compatibility mode.
- Add an optional native Rust desktop binary with a real scan form and live port-result table.
- Add bounded TCP host discovery through the `-sn` compatibility option and document its transport limitations.
- Add an original desktop design-direction visual and refine the native desktop Scan workspace.
- Add `diff` for comparison of the two latest Noxmap snapshots, including added and removed port inventory entries.
- Add `noxcat`, an original bounded TCP diagnostic companion client for authorized checks.
- Add `noxping`, a bounded TCP reachability and timing companion utility.
- Add a stable JSON report schema with native `--json` and compatibility `-oJ` output.
- Add versioned `.noxbaseline` desired-state audits for open and closed TCP-port expectations.

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
