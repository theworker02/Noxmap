# Contributing to Noxmap

Noxmap accepts focused pull requests and issue reports in this GitHub
repository. Before opening a change, describe the supported platform, scan
behavior, authorization assumptions, and test evidence.

## Development checks

```powershell
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
```

## Contribution rules

- Do not copy Nmap source, scripts, service databases, documentation, assets,
  or branding into Noxmap.
- Keep new scan behavior explicit about privileges, target scope, and failure
  states.
- Add behavior tests for parsers, output, policy, and protocol recognition.
- Do not add evasion or destructive automation modes.
- Document platform limitations and compatibility gaps accurately.

