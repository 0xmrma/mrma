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

## 0.4 - One experiment oracle

- Integrate repeated controls into impact, profiles, discovery, and isolation
- Replace first-sample baselines with robust baseline distributions
- Add median absolute deviation for latency and length signals
- Persist normalization rules and effective configuration in every result
- Introduce JSON Schema files and compatibility tests
- Split the CLI into command modules over a stable Python engine API

## 0.5 - Trust Influence Graph

- Model input, boundary-hypothesis, and observable-outcome nodes
- Attach evidence edges with reproducibility and transport provenance
- Minimize combinations under the repeated oracle
- Detect precedence between conflicting headers and duplicate fields
- Compare authenticated roles without storing credentials in evidence artifacts
- Export deterministic bundles containing requests, observations, and replay instructions

## 0.6 - Protocol and boundary differentials

- Separate semantic HTTP, wire-accurate HTTP/1.1, and HTTP/2 transports
- Preserve binary bodies and duplicate-header semantics
- Add connection-affinity and fresh-connection experiment modes
- Compare CDN/origin and gateway/backend paths where the operator supplies both authorized routes
- Add protocol-aware mutation grammars with conservative safety classifications

## 0.7 - Enterprise operation

- Signed scope manifests and explicit target authorization policy
- Request budgets, concurrency ceilings, and mutation safety levels
- Secret redaction and encrypted evidence storage
- Stable SDK and CI regression assertions
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
