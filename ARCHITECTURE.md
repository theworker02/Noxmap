# Noxmap architecture

## Design goals

Noxmap separates policy, collection, enrichment, storage, and transport. This keeps a local-first scanner usable without an account and lets privileged capabilities be added per platform without exposing them to the user interface or API by default.

## Data flow

`CLI/API request -> ScanPolicy -> Scanner -> Service identifier -> ScanSnapshot -> Monitoring diff -> Storage/API adapters`

The current executable implements the first four stages in memory. `ScanSnapshot` is intentionally serializable through the internal JSON renderer so a later SQLite store or HTTP transport can reuse the result model.

## Extension contracts

- **OS fingerprinting:** providers must return evidence, provenance, and a confidence value. A missing provider is reported as unavailable, never guessed.
- **Topology:** providers supply hops and their source. The portable default has no collection provider.
- **Monitoring:** consumes consecutive snapshots and emits deterministic state changes.
- **Scripting:** manifests declare capabilities. Command execution is excluded; a future runner must enforce capability grants and a sandbox.
- **API:** request/response contracts are transport-independent. Future transports bind to `127.0.0.1` by default.

## Non-goals for this foundation

No raw socket operations, stealth scanning, packet crafting, spoofing, or automated exploitation are in scope. These are not needed for inventory-oriented TCP connect scanning and carry materially different safety, privilege, and portability requirements.

