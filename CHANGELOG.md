# Changelog

All notable changes are documented here. MRMA follows semantic versioning for the CLI and uses an
independent version in each machine-readable evidence schema.

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
