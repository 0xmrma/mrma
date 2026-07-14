# Changelog

All notable changes are documented here. MRMA follows semantic versioning for the CLI and uses an
independent version in each machine-readable evidence schema.

## 0.3.1 - Unreleased

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
