# Changelog

All notable changes are documented here. MRMA follows semantic versioning for the CLI and uses an
independent version in each machine-readable evidence schema.

## Unreleased

### Media-Type Precision

- Content-Type eligibility now parses every parameter outside quoted delimiters, validates token
  and quoted-string grammar, detects conflicting duplicates, and records exact ambiguity reasons.
- Text comparison supports only strict UTF-8 and US-ASCII decoding. Unsupported charsets and bytes
  that violate the declared charset remain digest-only and produce structured limitations.
- Experiment evidence advances to `mrma.experiment/v6`; published v2 through v5 contracts remain
  packaged and immutable.

### Transport Input Integrity

- Custom CA evidence and TLS configuration now use one immutable byte snapshot, removing the gap
  between hashing the bundle and constructing the SSL context.
- Opted-in proxy and TLS environment variables are snapshotted before transport construction.
  Experiments reject environment changes that would make runtime behavior diverge from provenance.

### Verification

- Added adversarial media-type, charset, exact-CA-input, environment-race, v5 immutability, and v6
  schema-invariant tests.

## 0.3.6 - 2026-07-15

### Transport Reproducibility

- Experiment transport now disables HTTPX environment trust by default and supports explicit proxy,
  CA bundle, and environment opt-in policies. V5 evidence records TLS and proxy provenance without
  exposing credentials, environment values, or file paths.
- Research and forensic assurance disable environment trust and reject disabled TLS unless the
  researcher supplies a separate explicit exception.

### Evidence Precision

- Missing, malformed, or conflicting `Content-Type` evidence is no longer assumed to be text.
  Unequal bodies remain indeterminate unless an explicit weaker assumption is requested.
- Exact target-specific response fields can be made decision-bearing. Results disclose the full
  selected header set, omitted-header risk, and a response-header coverage assurance dimension.
- Experiment evidence advances to strict `mrma.experiment/v5`; published v2, v3, and v4 contracts
  remain packaged and immutable.

### Verification

- Added transport secrecy, body eligibility, custom-header, schema-negative, and v4 immutability
  regressions. Runtime dependency auditing now runs independently on Python 3.10 and 3.13.

## 0.3.5 - 2026-07-14

### Dependency Contract

- Published package metadata now requires Tomli 2.4.1 or newer on Python 3.10, matching the
  runtime dependency audit and carrying the parser's bound on pathological key-part growth.
- Added a parsed PEP 508 contract test requiring the runtime audit manifest to exactly match
  published runtime dependencies, including version ranges and environment markers.

### Maintenance And Supply Chain

- Updated the supported Rich range to include Rich 15 and pinned Rich 15.0.0 in the reproducible
  container dependency set. MRMA's Python 3.10 floor is compatible with the release.
- Updated all workflow checkouts to the SHA-pinned Actions Checkout 7 release.
- Raised the audit environment's Tomli floor to 2.4.1 and declared the requirement parser as an
  explicit development dependency.

## 0.3.4 - 2026-07-14

### HTTP Semantic Correctness

- `Allow` and `Access-Control-Allow-Methods` now preserve case-sensitive HTTP method tokens while
  retaining order-insensitive set comparison. Header-name sets in `Vary` and CORS response fields
  remain correctly case-insensitive.
- Conflicting duplicate or malformed `Cache-Control` directives no longer pass through the normal
  order-insensitive canonicalizer. Their normalized order remains decision-bearing and results
  emit the structured `AMBIGUOUS_CACHE_CONTROL` limitation.
- Added deterministic and property-based regression tests for method casing, method ordering,
  duplicate directive order, malformed quoting, and limitation export.

### Safety And Release Governance

- Safety documentation now states that 0.3.x does not enforce authorization manifests or
  centralized request budgets. Authorization-first networking and complete budget accounting are
  explicit v0.4 acceptance criteria.
- Added CODEOWNERS coverage for workflows, release signers, the corrected core, schemas, container
  inputs, and dependency locks.
- Publishing workflows now accept only signed annotated tags, verify the signer before publishing,
  and run through the protected `release` environment. Arbitrary container-version dispatch was
  removed.
- Container publication now creates GitHub-signed provenance in addition to BuildKit provenance
  and SBOM manifests. Added release, asset, container, signer-workflow, source-ref, and OCI-digest
  verification instructions.

## 0.3.3 - 2026-07-14

### Semantic Precision

- Redirect decisions now compare canonical resolved targets. Raw `Location` representations remain
  keyed contextual evidence, so relative/absolute forms, default ports, host casing, dot segments,
  and equivalent percent encoding do not create false influence signals.
- Added a field-aware response-header registry for `Vary`, `Allow`, CORS token sets,
  `Cache-Control`, `Location`, and `Content-Location`. Captured fields without a registry rule and
  `Set-Cookie` retain conservative ordered comparison.
- Stable retry error-subtype sequences are decision-bearing. Attempt elapsed time and configured
  backoff are exported as contextual median, median-absolute-deviation, and direction-consistency
  evidence rather than one-shot binary differences.

### Assurance And Evidence

- Experiment evidence advances to `mrma.experiment/v4`; published v2 and v3 contracts are tested
  as immutable. V4 removes the scalar confidence grade and requires a multidimensional assurance
  profile.
- Results now include structured limitations with stable code, severity, scope, message, and
  remediation fields for CI policy and external review.
- Added authoritative `exploratory`, `research`, and `forensic` assurance presets. Research mode
  selects fresh connections, isolated response state, disabled retries, a 20-round bracketed
  design, standard privacy, and full body retention within the response bound.
- Added optional durable experiment-evidence writes with file synchronization and parent-directory
  synchronization where supported. Normal atomic replacement remains available.

### Verification

- Added semantic equivalence, retry-subtype, timing-distribution, assurance-profile, schema-negative,
  preset-invariant, durable-write interruption, and URI property tests.
- CI now type-checks and measures the HTTP semantics registry and verifies all three published
  schema generations inside the clean installed wheel.

## 0.3.2 - 2026-07-14

### Evidence Correctness

- Redirect traces now participate in verdicts. Hop count, status and origin sequences, redacted
  location equality, cross-origin transitions, method changes, credential forwarding, and final
  origin are compared even when final response bodies match.
- Retry evidence now preserves every attempt, intermediate status or transport outcome, elapsed
  bucket, retry reason, and backoff. Mutation-only retries are decision-bearing; retries remain
  disabled by default.
- Added explicit `reuse`, `per-arm`, `per-round`, and `fresh-observation` connection scopes while
  keeping cookie-state policy independent. Negotiated HTTP versions are recorded.
- `Vary` evidence receives field-aware order-insensitive canonicalization.
- The CLI displays the fixed-sample decision counts before sending requests and exports those
  operating characteristics with the result.

### Contract And Privacy

- Experiment evidence advances to `mrma.experiment/v3`. The complete schema defines strict nested
  observations, attempts, redirects, rounds, intervals, policies, and result dimensions with
  `additionalProperties: false`. The published v2 schema remains available unchanged.
- Standard run timestamps are reduced to minute precision and durations are bucketed. Strict mode
  retains dates and broad duration ranges; only forensic mode preserves exact run timing.
- Evidence reports separate decisiveness, control, transport, isolation, normalization, effect,
  and reproduction dimensions in addition to the compatibility grade.
- JSON evidence files are replaced atomically after serialization.

### Reproducibility And Verification

- Container builds use a digest-pinned multi-architecture Python base plus exact hash-locked build
  and runtime dependencies.
- CI builds and smoke-tests the non-root container on every change.
- Added adversarial tests for identical-final-response redirect changes, mutation-only retries,
  connection scopes, compressed transfer bounds, semantic header reordering, run privacy, strict
  nested schema rejection, and statistical decision boundaries.

## 0.3.1 - 2026-07-14

### Correctness

- Default experiments now isolate response-cookie state while preserving connection reuse and
  explicit request cookies. Per-arm and shared-session state modes are explicit.
- The default schedule locally brackets every mutation with control-before and control-after
  observations. Seeded randomized balanced AB/BA blocks remain available explicitly.
- Verdicts now use predeclared fixed-sample Wilson confidence bounds. Five successful rounds no
  longer produce a positive verdict.
- Timeouts, resets, TLS, DNS, protocol, generic transport failures, and response policy aborts are
  retained as typed evidence with retry-attempt counts.
- Response reads and retained bodies are bounded. Incomplete evidence has an explicit
  `INDETERMINATE` classification. Encoded and non-text bodies require exact transfer-digest
  equality instead of being passed through a text similarity comparator.
- Effective preset and user equivalence rules are resolved once and recorded with each result.
- Duplicate response headers and redirect-chain transitions are preserved as evidence.

### Privacy And Automation

- Evidence supports standard, strict, and forensic redaction policies. Standard and strict modes
  use per-run keyed HMAC fingerprints and mask target paths.
- Experiment output moves to `mrma.experiment/v2` with a packaged JSON Schema.
- `--fail-on` provides opt-in stable exit codes: `10` for influence and `11` for inconclusive.
- Influence is rendered as a neutral signal; no-influence output is not labeled safe.

### Verification

- Added cookie-state, retry, transport-failure, response-bound, redirect, duplicate-header,
  confidence-threshold, privacy, schema, and loopback CLI integration tests.
- CI now validates coverage, selected-core typing, dependency audit, wheel/sdist metadata, clean
  wheel installation, packaged schema presence, CodeQL, and release provenance.
