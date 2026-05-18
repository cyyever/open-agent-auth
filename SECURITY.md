# Security Policy

## Supported Versions

This repository is the AAP fork baseline (`0.1.0-beta.1-SNAPSHOT`). No
release line is stable yet; the M1 protocol patches are still pending.
Security fixes will land on `main`.

## Reporting a Vulnerability

Report security vulnerabilities privately by emailing the maintainer
(`cyyever`). Include:

- Description of the issue
- Affected commit / version
- Reproduction steps or PoC
- Impact assessment
- Suggested fix (optional)

The maintainer aims to acknowledge within 48 hours. Coordinated
disclosure with credit once a fix is in place.

## Spec-level security constraints

Per the AAP spec (`agent_auth_protocol.tex`):

- Algorithm whitelist: **`alg=EdDSA` only** (Ed25519 + SHA-512). Reject
  `alg=none`, key-confusion attacks, anything else — MALFORMED.
- JOSE header whitelist: `{alg, typ}` only (DPoP also allows `jwk`).
  Any other header → MALFORMED.
- HTTPS only — no plaintext transport.
- No AuthZ, no consent UI, no CA / X.509.

These constraints are enforced by the M1 patches (`alg` lock + header
whitelist enforcer).
