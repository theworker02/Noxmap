# Security policy

## Scope

Noxmap is intended for systems you own or are authorized to assess. Public
targets require an explicit acknowledgement in the CLI.

## Reporting a vulnerability

Do not post exploitable vulnerability details in a public issue. Use GitHub's
private security-advisory flow for this repository, or contact the repository
owner privately with a minimal reproduction and affected revision.

## Supported posture

This early release supports bounded TCP connect scanning. Raw packet engines,
privileged platform backends, and authenticated non-loopback API transport are
not implemented and must not be assumed available.

