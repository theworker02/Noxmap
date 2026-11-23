# Noxmap

![Noxmap mark](assets/noxmap-mark.svg)

Noxmap is an original, Rust-native network inventory and observability tool for authorized administrators and security researchers. It is a clean-room implementation maintained in a fork relationship for historical context; it does not include Nmap source, branding, scripts, databases, binaries, or compatibility claims.

The first release establishes a portable, consent-first scanning core: bounded TCP connect scans, lightweight service identification, machine-readable results, and an extensible domain model for monitoring, topology, scripting, OS identification, and a local API.

## Desktop application

![Noxmap desktop design direction](docs/screenshots/noxmap-desktop-concept.png)

The image above is an original **design-direction concept**, not a claim that every panel is already shipped. The repository now includes a real native Rust desktop binary with an operational Scan workspace: target input, port selection, fast-profile selection, service-identification selection, explicit public-target acknowledgement, a real scan action, scan-state feedback, live result metrics, and a port-results table. Inventory, saved profiles, settings, and the richer multi-target panels shown in the concept remain future work.

Build and run the desktop application with:

```powershell
cargo run --features desktop --bin noxmap-desktop
```

The GUI calls the same scanner and consent policy as the CLI; it is not a fake dashboard or a separate scanning implementation.

## Noxcat companion client

Nmap distributes Ncat as a separate networking companion. Noxmap now includes an original, deliberately bounded Rust counterpart named `noxcat`. It is a TCP diagnostic client for authorized checks—not a listener, proxy, relay, or remote-administration tool. It limits a single reply to 8 KiB, uses timeouts, and requires `--allow-public` for public destinations.

```powershell
cargo run --bin noxcat -- 127.0.0.1 80 --send "HEAD / HTTP/1.0`r`n`r`n"
cargo run --bin noxcat -- example.com 443 --allow-public --timeout-ms 1500 --no-read
```

## Noxping companion utility

Nmap also contains Nping. Noxmap's original `noxping` is a bounded TCP reachability and timing utility: it measures connection attempts to one authorized TCP service and treats connection refusal as evidence that the host responded. It deliberately does **not** emit ICMP, craft packets, spoof sources, or provide raw-packet modes.

```powershell
cargo run --bin noxping -- 127.0.0.1 443 --count 4
cargo run --bin noxping -- example.com 443 --count 3 --allow-public
```

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
noxmap diff <target> [--state-dir .noxmap]
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
noxmap -sn -iL .\inventory.txt -oG .\discovery.grep
noxmap -sT -iL .\inventory.txt --exclude 192.168.50.0/24 -oN .\scan.txt
noxmap -sT 127.0.0.1 -p 80,443 -oX .\scan.xml
noxmap -sT 127.0.0.1 -p 80,443 -oG .\scan.grep
noxmap -sT -iL .\inventory.txt -p 80,443 -oJ .\scan.json
```

Supported compatibility options are `-sT`, `-sV`, `-sn`, `-p`, `-F`, `--top-ports`, `-iL`, `--exclude`, `--excludefile`, `-oN`, `-oX`, `-oG`, and `-oJ`. `-F` selects Noxmap's maintained 100-port TCP profile, and `--top-ports N` selects its first `N` entries. `-sn` performs bounded TCP reachability checks and does not claim ARP, ICMP, or raw-packet discovery parity. In compatibility mode, service identification runs only when `-sV` is supplied. Unsupported scan families fail explicitly rather than being silently replaced with a different operation.

## What Noxmap does today

| Capability | Behavior |
| --- | --- |
| TCP port inventory | Performs bounded, concurrent TCP connection attempts and reports open, closed, filtered, unreachable, or unresolved outcomes where the operating system exposes enough information. |
| Service identification | Uses a restrained original probe set for HTTP, FTP, SMTP, POP3, IMAP, Redis, memcached, and banner-first SSH/VNC/AMQP services, then records short protocol evidence or a well-known-port hint. Native scans identify by default; the compatibility command requires `-sV`. It does not run arbitrary payloads, credentials, or another project's probe database. |
| Target handling | Accepts a hostname/IP, a capped IPv4 CIDR, or an `-iL` inventory. Target lists can remove exact hosts and IPv4 CIDRs with exclusions. |
| Host discovery | Provides a bounded TCP reachability mode through `discover` and `-sn`; a connection refusal can prove a host responded. |
| Reports | Prints human-readable output and supports a shared JSON schema from native `--json` and compatibility `-oJ`, plus normal (`-oN`), XML (`-oX`), and line-oriented grepable (`-oG`) reports. |
| Monitoring and comparison | Saves local snapshots, emits changes during `watch`, and provides `diff` to compare the two most recent snapshots for a target. |
| Desired-state assurance | Audits versioned `.noxbaseline` expectations and reports open/closed port drift. |
| Local integration | Exposes a loopback-only HTTP API for local automation and a data-only `.nox` script format for constrained checks. |
| Companion client | Provides `noxcat`, a bounded TCP diagnostic client for authorized one-to-one protocol checks. |
| Reachability timing | Provides `noxping`, a bounded TCP connection-timing utility with summary statistics. |

## Output and automation

The native `--json` flag and compatibility `-oJ` use Noxmap's stable JSON schema, including address, port state, latency, and service evidence. `-oJ` emits an array so a target inventory remains one valid document. Use `-oN` for a readable report, `-oX` when a single-target XML document is needed, and `-oG` for compact line-oriented tooling. Noxmap's XML and grepable layouts are its own documented formats; consumers should not rely on byte-level compatibility with another scanner.

```powershell
cargo run -- scan 127.0.0.1 --top-ports 20 --json
cargo run -- -sT 127.0.0.1 -p 80,443 -oG .\loopback.grep
cargo run -- -sT -iL .\inventory.txt -p 80,443 -oJ .\inventory.json
```

## Snapshot comparison

Noxmap saves each native `scan` and `watch` result locally. The `diff` command compares the two latest snapshots for one target and reports opened, closed, newly added, or removed port entries. This is an original Noxmap snapshot workflow inspired by the practical use case served by Nmap's separate `ndiff` companion; it does not parse or claim compatibility with Nmap XML.

```powershell
cargo run -- scan 127.0.0.1 --ports 22,80 --state-dir .\state
# Make another scan after the target state or selected ports have changed.
cargo run -- diff 127.0.0.1 --state-dir .\state
```

## Desired-state audits

Noxmap baselines turn a one-off scan into a repeatable network assurance check. A `.noxbaseline` file declares a target and expected open/closed TCP ports. `audit` performs only the ports listed in that baseline, then returns a non-zero result if reality has drifted. This makes the scanner usable in local operations, scheduled checks, and future policy automation without inventing a cloud control plane.

```ini
# web-edge.noxbaseline
schema=1
target=127.0.0.1
expect_open=80,443
expect_closed=23,25
```

```powershell
cargo run -- audit .\web-edge.noxbaseline
cargo run -- audit .\production-edge.noxbaseline --allow-public
```

See the [safe loopback example](examples/loopback.noxbaseline). The first baseline format deliberately supports only `schema`, `target`, `expect_open`, and `expect_closed`; unknown keys fail rather than being ignored.

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
