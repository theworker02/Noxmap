# Noxmap

![Noxmap mark](assets/noxmap-mark.svg)

Noxmap is an original, Rust-native network inventory and observability tool for authorized administrators and security researchers. It is a new implementation; it does not include Nmap source, branding, scripts, or compatibility claims.

The first release establishes a portable, consent-first scanning core: bounded TCP connect scans, lightweight service identification, machine-readable results, and an extensible domain model for monitoring, topology, scripting, OS identification, and a local API.

## Status

This is an early foundation, not a drop-in replacement for Nmap. It intentionally does **not** implement raw-packet scanning, evasion, spoofing, stealth modes, exploit execution, or unauthenticated remote administration.

## Quick start

```powershell
cargo run -- scan 127.0.0.1 --ports 22,80,443,8080 --json
```

Only scan systems you own or are explicitly authorized to assess. Public addresses require an explicit `--allow-public` acknowledgement.

```powershell
cargo run -- scan example.com --ports 80,443 --allow-public
```

## Commands

```text
noxmap scan <target> [--ports <spec>] [--timeout-ms <n>] [--concurrency <n>] [--json] [--allow-public]
noxmap watch <target> [scan options] [--interval-secs <n>]
```

Port specifications accept comma-separated ports and inclusive ranges, for example `22,80,443,8000-8100`. The default is a small inventory-oriented set of common TCP services.

## Architecture

```text
src/
  policy.rs       Scope validation and public-target acknowledgement
  scanner.rs      Bounded TCP connect engine and scan result model
  service.rs      Non-invasive banner and port-hint identification
  monitoring.rs   Change detection for recurring scans
  topology.rs     Portable topology model and platform-provider boundary
  fingerprint.rs  OS-fingerprint confidence model and provider boundary
  scripting.rs    Declarative, validated script manifest model
  api.rs          Local API request/response contract (transport-ready)
```

Raw packet collection, traceroute, and active OS fingerprinting are deliberately provider boundaries because they need platform-specific privileges and careful rate control. They must not be represented as working until implemented and tested on each target operating system.

## Security model

- Explicit target input; no default discovery sweep.
- Maximum 1,024 ports and 256 concurrent connections per scan.
- Public targets require `--allow-public`.
- TCP connect scanning only; no packet forging or stealth behavior.
- Script manifests are data-only and do not execute arbitrary commands.
- Future API transport must bind to loopback by default and authenticate any non-loopback listener.

## Development

```powershell
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
```

## Implemented local systems

```text
noxmap fingerprint <target> [scan options]
noxmap topology <target>
noxmap script <file.nox> <target> [scan options]
noxmap api [loopback-port]
```

`watch` and `scan` persist results in `.noxmap/snapshots.noxlog` by default; a later run uses the prior stored snapshot for change detection. `fingerprint` reports only service-derived, low-confidence evidence. `topology` invokes the platform traceroute command only when the user explicitly calls it.

The local API binds only to `127.0.0.1:8421` by default. It provides `GET /health`, `GET /v1/latest?target=<target>`, and `POST /v1/scan?target=<target>&ports=80,443`.

Scripts are data-only `.nox` manifests, not shell code. Supported actions are `open-port:<port>`, `service:<name>`, and `banner:<port>`:

```ini
id=web-service
version=1
capabilities=MakeTcpConnection,ReadServiceBanner
action=service:http
```

## Roadmap

1. Persist scan snapshots in local SQLite and expose a loopback-only authenticated API.
2. Add platform-specific, permission-aware topology providers.
3. Add passive OS evidence collection with provenance and confidence scoring.
4. Add signed, capability-scoped WASM scripts after a sandbox is in place.
5. Add a desktop client and continuous monitoring schedules with notification adapters.

