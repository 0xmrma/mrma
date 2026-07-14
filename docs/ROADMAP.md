# Research and engineering roadmap

MRMA is a research preview. The sequence below prioritizes correctness and evidence quality before
adding more mutation families.

## 0.3 - Controlled evidence foundation

- [x] Reliable clean installation with declared runtime dependencies
- [x] Python 3.10-3.13 compatibility contract
- [x] Counterbalanced control/mutation experiments
- [x] Reproducibility and 95% Wilson intervals
- [x] Automatic control-instability rejection
- [x] Header-only and body/status evidence
- [x] Reusable semantic HTTP session with explicit transport labeling
- [x] Versioned `mrma.experiment/v1` JSON evidence
- [x] Cross-platform CI and focused experiment tests

## 0.3.1 - Correctness hardening

- [x] Isolated, per-arm, and shared-session cookie-state modes
- [x] Locally bracketed controls and fixed-sample confidence-bound verdicts
- [x] Typed transport and policy-abort outcomes with retry provenance
- [x] Streaming response bounds and explicit incomplete-body evidence
- [x] Effective preset resolution and duplicate response-header preservation
- [x] Redirect-chain provenance and per-run keyed evidence redaction
- [x] Stable automation exit codes and `mrma.experiment/v2` JSON Schema
- [x] Loopback integration tests and built-distribution release gates

## 0.3.2 - Evidence contract completion

- [x] Decision-bearing redirect traces and complete retry-attempt evidence
- [x] Reusable, per-arm, per-round, and fresh-observation connection scopes
- [x] Privacy-aware run timestamps and duration buckets
- [x] Strict nested `mrma.experiment/v3` schema with v2 compatibility preservation
- [x] Fixed-sample operating-characteristic preview and evidence dimensions
- [x] Digest-pinned base image and hash-locked container dependencies

## 0.3.3 - Semantic precision

- [x] Canonical resolved redirect targets with contextual raw fingerprints
- [x] Field-aware response-header comparison registry
- [x] Decision-bearing retry error subtypes and quantitative timing summaries
- [x] Multidimensional assurance profiles and structured limitation codes
- [x] Research, exploratory, and forensic assurance presets
- [x] Durable atomic experiment-evidence writes where directory sync is supported
- [x] Strict `mrma.experiment/v4` with immutable v2 and v3 compatibility contracts

## 0.3.4 - Semantic and release governance

- [x] Case-sensitive HTTP method-set comparison for `Allow` and CORS method declarations
- [x] Ordered comparison and structured limitations for ambiguous `Cache-Control`
- [x] Explicitly aligned safety documentation and authorization boundaries
- [x] CODEOWNERS coverage for the release control plane and corrected core
- [x] Signed annotated tag verification in every publishing workflow
- [x] Protected release environment and verifiable Python/container provenance

## 0.3.5 - Dependency contract consistency

- [x] Align the Python 3.10 Tomli security floor across package and audit metadata
- [x] Parse and compare published and audited PEP 508 dependency contracts in tests
- [x] Validate Rich 15 and Actions Checkout 7 across the complete quality matrix

## 0.3.6 - Transport and evidence precision

- [x] Disable ambient HTTPX environment configuration for experiments by default
- [x] Record privacy-preserving TLS, CA, proxy, and environment provenance
- [x] Require an explicit exception for disabled TLS under research assurance
- [x] Treat missing or ambiguous `Content-Type` as digest-only evidence by default
- [x] Allow exact target-specific response headers into decision evidence
- [x] Expose selective response-header coverage as a structured limitation and assurance dimension
- [x] Publish strict `mrma.experiment/v5` while preserving v2, v3, and v4 contracts
- [x] Audit runtime dependencies on Python 3.10 and 3.13 independently

## 0.3.7 - Media-type and transport-input precision

- [x] Validate complete Content-Type parameter grammar outside quoted delimiters
- [x] Restrict text comparison to strictly decoded UTF-8 and US-ASCII evidence
- [x] Expose machine-readable body-comparator charset and ineligibility reasons
- [x] Build custom TLS contexts from the exact CA bytes recorded in provenance
- [x] Snapshot and guard opted-in environment transport inputs during client construction
- [x] Publish strict `mrma.experiment/v6` while preserving v2 through v5 contracts

## 0.4 - Authorization-first experiment engine

- Enforce an authorization policy before any network operation, including every redirect
- Constrain scheme, host, port, path, method, redirect destination, and policy expiration
- Centralize total, per-target, redirect, byte, duration, concurrency, and mutation-risk budgets
- Charge every control, mutation, retry, and redirect against the same budget ledger
- Extract one stable `ExperimentOracle` and Python API from CLI orchestration
- Produce schema-valid partial evidence for cancellation, rejection, failure, and exhausted budgets
- Begin CLI decomposition and migrate the first legacy workflow to the shared oracle

## 0.5 - Product-wide evidence oracle

- Integrate repeated controls into impact, profiles, discovery, and isolation
- Replace first-sample baselines with robust baseline distributions
- Add median absolute deviation for latency and length signals
- Add explicit exact, conservative, and guarded content-aware body-comparison policies
- Extend schema compatibility tests to every legacy command as it adopts the experiment oracle
- Complete CLI decomposition into policy, workflow, evidence, and presentation modules
- Stabilize the public Python SDK

## Trust Influence Graph

- Model input, boundary-hypothesis, and observable-outcome nodes
- Attach evidence edges with reproducibility and transport provenance
- Minimize combinations under the repeated oracle
- Detect precedence between conflicting headers and duplicate fields
- Compare authenticated roles without storing credentials in evidence artifacts
- Export deterministic bundles containing requests, observations, and replay instructions

## 0.6 - Protocol and boundary differentials

- Separate semantic HTTP, wire-accurate HTTP/1.1, and HTTP/2 transports
- Preserve binary bodies and duplicate-header semantics
- Add protocol-native HTTP/2 stream and connection-affinity controls
- Compare CDN/origin and gateway/backend paths where the operator supplies both authorized routes
- Add protocol-aware mutation grammars with conservative safety classifications

## 0.7 - Enterprise operation

- Signed authorization-policy distribution and organizational trust roots
- Secret redaction and encrypted evidence storage
- CI regression assertions and organization policy integration
- OpenTelemetry-compatible audit events
- Team review states and manual-validation workflow
- Reproducible container images and signed releases with SBOMs

## Acceptance bar

A feature is not complete because it emits a result. It requires:

- a documented hypothesis and threat model;
- deterministic unit tests and network integration tests;
- instability behavior and negative controls;
- versioned machine output;
- transport and normalization provenance;
- a safe default request budget;
- documentation that states what the evidence cannot prove.
