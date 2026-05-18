# Working on this repo with Claude Code

This file is loaded into Claude Code's context on every session. Keep it
short and concrete — capture project-level rules, never per-task state.

## What this repo is

The upstream baseline for an **AAP (Agent Auth Protocol) fork**. AAP spec
lives at [`cyyever/authentication_plan`](https://github.com/cyyever/authentication_plan)
— single source `agent_auth_protocol.tex`. Roadmap is in spec §9, SDK
details in §10.

The trim phase is mostly done. The remaining work is the **M1 retrofit
(~250 LoC of patches)** — see [Pending → M1](#m1-retrofit-pending).

## Hard rules from the spec

Do not relax any of these without a spec change:

- **Java 26** baseline (was 17+; bumped after the trim).
- Algorithm whitelist: **`alg=EdDSA` only** (Ed25519 + SHA-512). Reject
  `alg=none`, key-confusion, anything else → MALFORMED.
- JOSE header whitelist: `{alg, typ}` only (DPoP also allows `jwk`).
- Two wire messages only: **CT** (delegation, signed by `sk_P`) and
  **DPoP** (per-request, signed by `sk_S`). JWS compact serialization.
- PIC/CRL are registry HTTPS responses (themselves JWS).
- HTTPS only. **No AuthZ, no consent UI, no CA / X.509, no OAuth 2.0 /
  OIDC, no W3C VC.**

## Module layout

```
open-agent-auth-core/      protocol primitives — JWS, keys, JWKS, trust
                           WIT/WPT (→ CT/DPoP after M1). Pure Java.
open-agent-auth-framework/ actor interface (ResourceServer) +
                           DefaultResourceServer. Pure Java.
```

No Spring Boot starter, no integration-tests module, no samples — all
dropped per the trim. Consumers wire `WitValidator` + `WptValidator` +
`DefaultResourceServer` themselves in ~20 lines of their own DI.

## Build

```bash
# Linux dev host
JAVA_HOME=/usr/lib/jvm/java-26-openjdk mvn -B test
# macOS (Temurin via `brew install --cask temurin`)
JAVA_HOME=/Library/Java/JavaVirtualMachines/temurin-26.jdk/Contents/Home mvn -B test
```

The default `/usr/bin/javac` still points at Java 21 on the Linux dev
host, and macOS has no system `javac` at all; explicit `JAVA_HOME` is
required until the system default is bumped.

The pom only declares: nimbus-jose-jwt, Jackson (databind/annotations/
jsr310), SLF4J, jakarta.servlet/validation (provided/test), JUnit 5,
Mockito, AssertJ. No Spring, no JaCoCo (dropped — JaCoCo 0.8.12 doesn't
support class-file major 70).

## Coding conventions (project-specific)

- **Don't write `// removed for AAP` / `// see commit X` comments — just
  delete.** Spec authors prefer terse codebases; the git history is the
  audit trail.
- **Don't write javadoc that restates the signature.** Public-API
  protocol contracts deserve a one-liner; everything else doesn't.
- **Don't add new javadoc cross-references** (`@see`/`@link`) for
  in-package types. They become bit-rot during the M1 rename.
- **Records over Builder-classes** for new pure-data types. All four
  model classes (Jwk, AgentIdentity, WorkloadProofToken,
  WorkloadIdentityToken) were converted in this trim and saved ~78% LoC.
  Use compact canonical constructors for REQUIRED-field validation.
  Throw `IllegalStateException` (matches existing test expectations),
  not `NullPointerException` from `Objects.requireNonNull`.
- **Builders allowed only for ergonomic construction** of records with
  many optional fields. Keep them as static inner classes.
- **No new functionality during the trim phase.** If something has zero
  external refs, delete it. Don't preserve it "for future use".

## Conventions when committing

- Conventional Commits with `chore(aap):` or `refactor(aap):` scope. Pattern
  matches recent history (e.g. `chore(aap): drop X`).
- Use HEREDOC for commit messages to preserve formatting.
- Co-author trailer: `Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>`.
- Push only when the user asks ("push"). Don't push automatically.

## M1 retrofit (pending)

Spec §10.2 — **~250 LoC total**. Order of operations:

1. **`alg=EdDSA` lock** — reject `alg=none` / key-confusion. `WitParser`
   + `WptParser` header check before signature verify. ~10 LoC.
2. **JOSE header whitelist** — `{alg, typ}` only (DPoP +`jwk`). Any
   other JOSE header → MALFORMED. ~15 LoC.
3. **DPoP module** (~60 LoC) — `core/protocol/wimse/wpt/` → new
   `core/protocol/dpop/`. Rename `WorkloadProofToken` → DPoP; add
   `htm`/`htu`/`iat`/`jti`/`ath` claims.
4. **PIC cascade revocation** (~50 LoC) — registry HTTPS responses
   (JWS). Revoking a P invalidates all CTs signed by `sk_P`. New
   `core/registry/`.
5. **CRL anti-rollback** (~30 LoC) — every CRL has monotonic `seq`;
   verifier rejects `seq < lastSeen`.
6. **JSONL error events** (~50 LoC) — replaces the deleted
   `AuditLogEntry`. One line per verification failure, stdout/file/
   env-configurable.
7. **HTTP header whitelist enforcer** — network-side complement to (2).

After M1, also rename:
- package `core.protocol.wimse.{wit,wpt}` → `core.protocol.{ct,dpop}`
- `WorkloadIdentityToken` → `CredentialToken`
- `Workload-Identity-Token` HTTP header → spec term
- `KEY_WIT_VERIFICATION` → `KEY_CT_VERIFICATION`
- Residual `WIMSE` / `AOA` / `AOAT` / `DCR` / `5-layer` / `OIDC` strings
  in javadoc

## Perf hot spots already identified

Audited but not yet fixed (most need M1 rename first):

1. `JwtHashUtil.computeSha256Hash` — `MessageDigest.getInstance("SHA-256")`
   per call. Cache via `ThreadLocal<MessageDigest>` + static
   `Base64.Encoder`. ~5-10× faster.
2. `WptValidator.convertToJWK` — rebuilds Nimbus `JWK` from internal
   `Jwk` every validation (Base64-decode X/Y, new `BigInteger`,
   anonymous `ECPublicKey`). Cache by `Jwk` identity.
3. `JwksConsumerKeyResolver` — no TTL, no async refresh; key-not-found
   refetches synchronously per request (thundering herd).
4. `SignedJWT.parse` called twice per WPT validation (once in parser,
   once in validator). Store parsed `SignedJWT` on the token record.
5. `Token.isExpired/isValid` — `Date.from(Instant.now())` per check
   allocates 2 objects. Switch internal type to `Instant`.

## Bookmarks

- This repo's git history is the long-form record of the trim. Recent
  pattern: 20+ `chore(aap): drop X` commits between `c8f7c95` and
  `5a83240` cleared the upstream OAA scaffolding (~25k LoC net).
- The actual fork branch convention is `aap-main` per spec §10.3;
  the current trim is happening on `main` because no upstream rebase
  is happening yet.
