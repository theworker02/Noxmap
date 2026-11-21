# Noxmap

![Noxmap mark](assets/noxmap-mark.svg)

Noxmap is an original, Rust-native network inventory and observability tool for authorized administrators and security researchers. It is a clean-room implementation maintained in a fork relationship for historical context; it does not include Nmap source, branding, scripts, databases, binaries, or compatibility claims.

The first release establishes a portable, consent-first scanning core: bounded TCP connect scans, lightweight service identification, machine-readable results, and an extensible domain model for monitoring, topology, scripting, OS identification, and a local API.

## Status

This is an early foundation, not a drop-in replacement for Nmap. It intentionally does **not** implement raw-packet scanning, evasion, spoofing, stealth modes, exploit execution, or unauthenticated remote administration. Features are only described as available after they are implemented and tested.

## Project documentation

- [Architecture](ARCHITECTURE.md)
- [Upstream structure and compatibility inventory](UPSTREAM_COMPATIBILITY.md)
- [Changelog](CHANGELOG.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Upstream Nmap relationship](UPSTREAM-NMAP-NOTICE.md)

## Quick start

```powershell
cargo run -- scan 127.0.0.1 --ports 22,80,443,8080 --json
```

Only scan systems you own or are explicitly authorized to assess. Public addresses require an explicit `--allow-public` acknowledgement.

```powershell
cargo run -- scan example.com --ports 80,443 --allow-public
```

Build a release binary when you are ready to use the tool outside the working tree:

```powershell
cargo build --release
.\target\release\noxmap.exe --help
```

Noxmap currently builds with stable Rust 1.85 or later and has no third-party runtime dependencies. The TCP-connect engine is designed to run on Windows, macOS, and Linux. Topology collection delegates to each platform's native tracing utility and may require that utility to be present in `PATH`.

## Commands

```text
noxmap scan <target> [--ports <spec>] [--timeout-ms <n>] [--concurrency <n>] [--json] [--allow-public]
noxmap scan <target> --top-ports <1-100> [scan options]
noxmap scan <ipv4-cidr> [scan options]
noxmap scan -iL <authorized-inventory.txt> [scan options]
noxmap watch <target> [scan options] [--interval-secs <n>]
```

Port specifications accept comma-separated ports and inclusive ranges, for example `22,80,443,8000-8100`. The default is a small inventory-oriented set of common TCP services.

Target inputs accept one hostname/IP address, a bounded IPv4 CIDR, or a newline-delimited `-iL` inventory. Empty lines and lines beginning with `#` are ignored. CIDR and inventory expansion are capped at 256 targets so an accidental broad range cannot trigger an uncontrolled scan. `watch` deliberately remains one-target-per-process so each saved change history is unambiguous.

Use exclusions to keep known or out-of-scope devices out of an otherwise authorized inventory. Exact hostnames/IP addresses and IPv4 CIDRs are supported. An exclusion list uses the same newline-and-comment convention as an input inventory.

```powershell
cargo run -- scan -iL .\inventory.txt --exclude 192.168.50.0/24
cargo run -- scan -iL .\inventory.txt --excludefile .\out-of-scope.txt
```

### TCP-connect compatibility invocation

For familiar operator workflows, Noxmap accepts a deliberately small compatibility subset. These forms select Noxmap's own TCP-connect engine; they do not invoke or bundle Nmap.

```powershell
noxmap -sT 127.0.0.1 -p 22,80,443
noxmap -sT -F 127.0.0.1
noxmap -sT --top-ports 20 -sV 127.0.0.1
noxmap -sT -iL .\inventory.txt --exclude 192.168.50.0/24 -oN .\scan.txt
noxmap -sT 127.0.0.1 -p 80,443 -oX .\scan.xml
noxmap -sT 127.0.0.1 -p 80,443 -oG .\scan.grep
```

Supported compatibility options are `-sT`, `-sV`, `-p`, `-F`, `--top-ports`, `-iL`, `--exclude`, `--excludefile`, `-oN`, `-oX`, and `-oG`. `-F` selects Noxmap's maintained 100-port TCP profile, and `--top-ports N` selects its first `N` entries. In compatibility mode, service identification runs only when `-sV` is supplied. Unsupported scan families fail explicitly rather than being silently replaced with a different operation.

## What Noxmap does today

| Capability | Behavior |
| --- | --- |
| TCP port inventory | Performs bounded, concurrent TCP connection attempts and reports open, closed, filtered, unreachable, or unresolved outcomes where the operating system exposes enough information. |
| Service identification | Uses restrained HTTP, Redis, memcached, and port-hint checks on confirmed open ports. Native scans identify by default; the compatibility command requires `-sV`. It does not run arbitrary payloads or reuse another project's probe database. |
| Target handling | Accepts a hostname/IP, a capped IPv4 CIDR, or an `-iL` inventory. Target lists can remove exact hosts and IPv4 CIDRs with exclusions. |
| Reports | Prints human-readable output and supports JSON from the native command plus normal (`-oN`), XML (`-oX`), and line-oriented grepable (`-oG`) reports from the compatibility command. |
| Monitoring | Saves local snapshots and emits port-state changes on later scans or recurring `watch` runs. |
| Local integration | Exposes a loopback-only HTTP API for local automation and a data-only `.nox` script format for constrained checks. |

## Output and automation

The native `--json` flag is intended for a small local integration surface. Use `-oN` for a readable report, `-oX` when a single-target XML document is needed, and `-oG` for compact line-oriented tooling. Noxmap's XML and grepable layouts are its own documented formats; consumers should not rely on byte-level compatibility with another scanner.

```powershell
cargo run -- scan 127.0.0.1 --top-ports 20 --json
cargo run -- -sT 127.0.0.1 -p 80,443 -oG .\loopback.grep
```

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

Noxmap cannot determine whether you are authorized to scan a system. It requires an explicit acknowledgement before connecting to public addresses, but that acknowledgement is not permission. Confirm scope, maintenance windows, and local policy before running any scan.

## Development

```powershell
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
```

The repository includes [a safe loopback inventory example](examples/loopback-inventory.txt). Run it without touching external systems:

```powershell
cargo run -- scan -iL examples/loopback-inventory.txt --ports 1 --timeout-ms 100
```

## Project relationship

Noxmap studies the public structure and user-facing categories of the upstream Nmap repository to plan interoperable operator workflows. The work is clean-room: no upstream source, scripts, service fingerprints, assets, logos, release artifacts, or proprietary/trademarked presentation material is carried into this repository. See the [upstream relationship notice](UPSTREAM-NMAP-NOTICE.md) and the [compatibility inventory](UPSTREAM_COMPATIBILITY.md) for the current, explicit feature boundary.

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

