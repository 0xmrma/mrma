# Changelog

All notable changes are documented here. MRMA follows semantic versioning for the CLI and uses an
independent version in each machine-readable evidence schema.

## 0.4.5 - 2026-08-07

### Attempt Invariant Closure

- Derive reservations directly from the adapter-sealed prepared capability. Attempt kind,
  effective risk, redirect depth, timeout, response allowance, arm, round, target, origin, body,
  and prepared representation are checked before `ATTEMPT_STARTED`.
- Reject evidence contexts whose role or round differs from the prepared attempt, and record depth
  and effective risk in reservation events.
- Require one shared journal for adapter-issued reservations and the central budget ledger.

### Offline Conclusion Verification

- Add strict `mrma.experiment/v9` evidence with public repeated-control pair classifications.
- Recompute pair topology, sampling completeness, changed and indeterminate counts, rates, Wilson
  intervals, similarity summaries, effect counts, outcome counts, control stability, and the final
  fixed-sample verdict during offline verification.
- Retain v7 and v8 schema verification without claiming statistical rederivation that their public
  documents cannot support. New generation through legacy versioned builders remains disabled.

### Target Resolution And Validation

- Define `base_url` as an HTTP(S) origin only. Origin-form targets are root-relative and plans with
  a path, query, fragment, or userinfo in the base fail before networking.
- Expand the committed critical-policy mutation catalog from 39 to 49 cases, including lease
  semantics, evidence context, verdict derivation, and origin-base enforcement.
- Validate 369 tests with 71% whole-repository branch coverage, 94.26% aggregate critical-runtime
  coverage, and 86.43% corrected-core coverage.

## 0.4.4 - 2026-08-07

### Prepared Request Boundary

- Replace the public raw HTTPX request field with an opaque prepared capability that preserves the
  existing import name while exposing only reservation metadata. An adapter-local HMAC seal binds
  request identity, authorization identity, mutation delta, arm, round, and accounting values.
- Recompute the final method, URL, ordered raw fields, buffered content and send stream, extensions,
  effective `Host`, and represented size immediately before network I/O. Mutation, malformed
  buffering, cross-adapter use, and capability metadata changes fail before `ATTEMPT_STARTED`.
- Require the buffered content and actual HTTPX send stream to have identical lengths and digests
  before a request can be reserved.
- Bind each prepared capability to one observation session and consume it before the network call,
  preventing stale-session and repeated-lease replay.

### Mutation And Evidence Precision

- Enforce one-dimensional header experiments: method, target, declared HTTP version, target form,
  and body must remain identical. Unsupported mutation families fail closed instead of receiving a
  generic fingerprint binding, while unchanged exploratory control sends remain valid.
- Add `changed_dimensions` to mutation validation and bind it into the deterministic local delta
  digest under `authorization-policy/2.1`.
- Replace deterministic mutation-delta values in journals with adapter-local HMAC fingerprints and
  declare those identifiers as run-local in v8 evidence without changing the frozen schema.

### Validation And Governance

- Synchronize architecture, budget, API, evidence, and validation documentation with the
  prepare-reserve-revalidate-send capability boundary.
- Require the `semantic-mutation` and `benchmark` jobs in the protected `main` ruleset alongside the
  existing matrix, audit, distribution, container, evidence-quality, and CodeQL checks.
- Expand the suite to 348 tests and the committed critical-policy catalog to 39 mutants, all killed.

## 0.4.3 - 2026-08-07

### Authorization Precision

- Reject ambiguous path and query representations before canonicalization, including encoded path
  octets, double-encoding markers, backslashes, Unicode target text, encoded query keys, and
  parser-dependent delimiters. Authorization hosts now require explicit ASCII A-labels or IP
  literals and no longer use Python's implicit IDNA mapping.
- Evaluate ordered duplicate header values as a complete mutation delta. Mixed add, replace, and
  remove operations must all be authorized; duplicate-value reordering fails closed under v2.
- Bind validated baseline/mutation identities, required operations, policy version, and manifest
  digest into `AuthorizedMutationContext`. Mutation-arm transport rejects ordinary target-only
  authorization contexts.

### Transport And Comparison

- Build the final HTTPX request before budget reservation, revalidate its method, target, and
  effective `Host`, reserve its represented size including generated and cookie fields, and send
  that exact prepared object. Response accounting now includes represented status and header bytes
  alongside the bounded body.
- Make the default comparison preset literal. UUID, long hexadecimal, timestamp, and related
  masking require an explicit dynamic preset. Approximate or normalized equivalence over different
  complete body digests is indeterminate and cannot support `NO_INFLUENCE_OBSERVED`.
- Constrain HTTPX to the verified `>=0.27,<0.29` semantic range.

### Evidence And Compatibility

- Add a deterministic local approval-plan digest covering exact request values, authorization,
  privacy, comparison, and selected transport policy. Shared v8 evidence retains its run-local
  privacy-safe plan digest and does not expose the approval identity.
- Disable new `mrma.experiment/v7` generation while retaining the import-compatible rejection path,
  installed schema, and verification support for existing v7 documents. Published schemas remain
  unchanged.

### Verification

- The local release suite passes 329 tests with 71% whole-repository branch coverage, 94.94%
  aggregate critical-runtime coverage, and 86.64% corrected-core coverage. Every gated v0.4
  runtime module remains above 90%.
- The 22-case loopback corpus passes 942 attempts with zero errors against its controlled ground
  truth. The 32-case semantic mutation catalog kills every committed mutant.

## 0.4.2 - 2026-08-03

### Authorization And Redirect Enforcement

- Bound every exploratory network command to the immutable request loaded at workflow entry.
  Header additions, replacements, removals, and value sizes are validated before any attempt event
  or network activity.
- Enforced cross-origin cookie policy against the final HTTPX-built request. Eligible domain
  cookies from the observation jar and explicit `Cookie` fields are suppressed unless the
  cross-origin field policy explicitly permits them. Source-origin response state is discarded at
  a denied boundary, while state issued by the destination remains usable inside its own chain.

### Evidence And Compatibility

- Centralized canonical effective-plan hashing and recompute the digest during standalone result
  and bundle verification. Bundle verification also binds the result digest to every journal
  `RUN_PLANNED` event.
- Restored the published benchmark v1 schema byte-for-byte. Benchmark v2 retains the current
  terminology and corpus identifier.
- Corrected `build_experiment_v7()` to emit a schema-valid v7 document for authorization v1 instead
  of returning v8 under a versioned name.
- Extended byte and canonical immutability checks to authorization v2, experiment v8, and benchmark
  v1-v2.

### Project Surface

- Rebuilt the README around the enforced pipeline, result semantics, bundle contents, workflow
  roles, explicit limitations, and release verification path.
- Added a repository-native technical banner and synchronized release, architecture,
  authorization, HTTP, evidence, validation, and roadmap documentation.

### Verification

- Expanded the suite to 303 tests. Local branch coverage is 70% repository-wide, 95.11% across the
  critical runtime, and 86.84% across the corrected core; every critical module remains above 90%.
- Expanded the semantic mutation catalog from 18 to 24 invariants. All mutants are killed,
  including workflow-baseline, final-cookie-field, cross-origin state, plan-digest,
  journal-binding, and versioned-v7 regressions.
- Regenerated the 22-case loopback baseline: all expected conclusions pass across 942 authorized
  attempts.

## 0.4.1 - 2026-07-20

### Policy Boundaries

- Added strict `mrma.authorization/v2` authority policy. URL authority, `Host`, TLS SNI, and proxy
  CONNECT routing are bound before each attempt; duplicate `Host` fields are rejected and deliberate
  virtual-host mutations require an exact allowlist.
- Added per-rule query-key policy and exact header mutation name, operation, and value-size limits.
- Replaced cross-origin credential-name filtering with deny-by-default header forwarding. Redirects
  that change to `GET` also remove content, digest, trailer, and message-signature metadata.

### Observation And Evidence Correctness

- Scoped cookie and fresh-connection state to a complete logical observation so redirect and retry
  hops retain required state without leaking it into the next isolated observation.
- Added `mrma.plan/v2`, which binds effective requests, duplicate header order, bodies, experiment,
  comparison, retry, redirect, hook, transport, and authorization policy into one digest.
- Added strict `mrma.experiment/v8` with the effective plan and an accurate partial-correlation
  declaration. Experiment schemas v2-v7 and authorization v1 are byte-locked.
- Added neutral `mrma.benchmark/v2` and `trust-influence-loopback/2.0` identifiers.

### Verification

- Expanded the critical semantic mutation baseline from 12 to 18 invariants, including effective
  authority, query scope, cross-origin fields, observation state, and plan body identity.
- Regenerated the 22-case local benchmark under the v2 contract: all expected conclusions passed
  across 942 authorized attempts.
- Expanded the suite to 292 tests. The local branch-coverage gate reports 94.77% across critical
  runtime modules and 86.11% across the corrected core, with every critical module above 90%.

## 0.4.0 - 2026-07-15

### Authorization-First Runtime

- Added strict `mrma.authorization/v1` manifests with exact target/method/path policy, A/AAAA CIDR
  checks, immediate DNS revalidation, explicit proxy authorization, manual redirect authorization,
  expiry, method repetition, idempotency-key, and disposable hook controls.
- Added a concurrency-safe central ledger. Controls, mutations, retries, redirects, setup/reset,
  and exploratory sends reserve and commit attempts, role counts, origin/target counts, estimated
  request bytes, response bytes, duration, concurrency, depth, and risk.
- Extracted typed engine, policy, semantic transport, evidence, and workflow APIs. Confirmatory
  experiments use `ExperimentOracle`; all legacy network commands route through its policy kernel.
- Ambient proxy/CA environment configuration is rejected. HTTPX redirects remain disabled and are
  processed manually. Semantic replay is explicitly not wire-exact.

### Semantics And Resource Safety

- Added byte-preserving raw request ingestion with strict metadata/framing validation and retained
  method case, header order/duplicates, target form, HTTP version, and original digest.
- Added versioned media-specific charset resolution, semantic Content-Type equivalence, bounded XML
  BOM/declaration handling, conservative unknown-text behavior, and strict decoding.
- Added timeout-bounded pinned regex normalization, bounded trigram similarity, guarded JSON, and
  indeterminate comparator-resource outcomes.
- Added all-stable response-header qualification and explicit exact/pattern/profile field selection.

### Evidence And Research Method

- Added append-only hash-chained normal/durable journals and schema-valid partial results.
- Added strict `mrma.experiment/v7` with authorization, budget, journal, charset, comparator,
  transport/runtime, exploration role, assurance, and limitation contracts. Schemas v2-v6 remain
  byte-locked.
- Added deterministic evidence bundles with offline verification and a packaged, schema-validated
  benchmark baseline.
- Separated exploratory candidate ranking from independent fixed-sample confirmation.

### Verification

- Added a 22-case loopback benchmark: 22/22 passed, 0 false positives, 0 false negatives, 11
  intentional inconclusives, and 942 authorized attempts in the release baseline.
- Expanded to 281 tests before final release verification. Honest whole-repository branch coverage
  is 68%; critical v0.4 runtime coverage is 95.39% with every gated module above 90%; corrected core
  is 86.89%.
- Added strict mypy for every v0.4 module, 12/12 killed critical semantic mutants, six-platform test
  matrix, dual-Python dependency audit, package/schema/baseline checks, CodeQL, and non-root
  container smoke tests.
- Declared the JSON Schema validator as a runtime dependency and hash-locked its multi-architecture
  container dependency closure; clean-wheel CLI startup is a release gate.

## 0.3.7 - 2026-07-15

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
  remediation fields for CI policy and independent validation.
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
