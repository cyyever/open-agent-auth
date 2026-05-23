# Open Agent Auth — AAP fork baseline

[![CI](https://github.com/cyyever/open-agent-auth/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/cyyever/open-agent-auth/actions/workflows/ci.yml)
[![CodeQL](https://github.com/cyyever/open-agent-auth/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/cyyever/open-agent-auth/actions/workflows/codeql.yml)
[![Coverage](https://raw.githubusercontent.com/cyyever/open-agent-auth/badges/jacoco.svg)](https://github.com/cyyever/open-agent-auth/actions/workflows/ci.yml)
[![Branches](https://raw.githubusercontent.com/cyyever/open-agent-auth/badges/branches.svg)](https://github.com/cyyever/open-agent-auth/actions/workflows/ci.yml)

This repository is the upstream baseline being trimmed into an
**Agent Auth Protocol (AAP)** fork.

- Spec: [`cyyever/authentication_plan`](https://github.com/cyyever/authentication_plan) — single source `agent_auth_protocol.tex`
- Scope: authentication-only, single algorithm **Ed25519 + SHA-512** (`alg=EdDSA`), two wire messages — CT (delegation) and DPoP (per-request), JWS compact serialization, HTTPS only.
- Not provided: authorization, consent UI, CA / X.509, OAuth 2.0 / OIDC flows, W3C VC.

## Modules

| Module | Purpose |
|---|---|
| `open-agent-auth-core` | Protocol primitives: JWS sign/verify, key management, JWKS provider, trust roots, WIT/WPT (→ CT/DPoP after M1). Pure Java, no Spring. |
| `open-agent-auth-framework` | Actor interface (`ResourceServer`), default orchestration, request/result models. Pure Java, no Spring. |

Both modules require **Java 21 LTS** (or later). Only direct deps are
[Nimbus JOSE+JWT](https://connect2id.com/products/nimbus-jose-jwt),
Jackson, and SLF4J. Spring Boot is no longer required — consumers
(Spring Boot apps, Quarkus, Helidon, plain `main`) wire `WitValidator`
+ `WptValidator` + `DefaultResourceServer` directly, usually in ~20
lines.

## Status

- Trim phase done (commits `c8f7c95` through current `HEAD`)
- **M1 retrofit pending**: ~250 LoC of patches — lock `alg=EdDSA`,
  strict JOSE header whitelist, DPoP module, PIC cascade revocation,
  CRL anti-rollback, JSONL error events.
- README, package layout (`core.protocol.wimse.*`), and class names
  (`WIT`, `WPT`) will be renamed to spec terms (`CT`, `DPoP`) during M1.

Licensed under the Apache License 2.0 — see [LICENSE](LICENSE).
