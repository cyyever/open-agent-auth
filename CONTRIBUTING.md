# Contributing to Open Agent Auth (AAP fork)

This repository is the upstream baseline trimmed into an
**Agent Auth Protocol (AAP)** fork — see [README.md](README.md) and the
spec at [`cyyever/authentication_plan`](https://github.com/cyyever/authentication_plan)
for context.

## Prerequisites

- Java 21 LTS (or later)
- Maven 3.6+
- Git

## Setup

```bash
git clone https://github.com/cyyever/open-agent-auth.git
cd open-agent-auth
mvn clean install
mvn test
```

## Module layout

```
open-agent-auth/
├── open-agent-auth-core/      # protocol primitives — JWS, keys, JWKS, trust, WIT/WPT
└── open-agent-auth-framework/ # actor interface + DefaultResourceServer
```

Both modules are pure Java (no Spring). Consumers wire `WitValidator`,
`WptValidator`, and `DefaultResourceServer` themselves.

## Commit style

Conventional Commits — `<type>(<scope>): <subject>`. Scopes in active
use: `aap`, `core`, `framework`. Recent history is a series of
`chore(aap): drop X` commits — keep that style for trim work.

## Coding standards

- Default to writing **no** Javadoc except for public APIs whose contract
  isn't obvious from the signature. Don't restate what the code already
  says.
- Don't add `// removed for AAP` or `// see commit X` comments — just
  delete. The git history is the audit trail.
- Validate inputs at module boundaries. Trust internal code.

## Tests

Run `mvn test`. The framework module sits at ~80% instruction coverage;
core is the primary place to add tests when adding M1 patches.

## Security

Report vulnerabilities per [SECURITY.md](SECURITY.md).
