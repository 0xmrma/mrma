# Evidence Model

## Journal

The `mrma.journal/v1` JSONL journal is append-only. Each event has a monotonic sequence, previous
digest, current SHA-256 digest, run ID, privacy-aware timestamp, type, and bounded data. Normal mode
flushes appends. Durable mode additionally `fsync`s the file and synchronizes the parent directory
where the operating system supports it.

The journal covers planning, authorization, budget reservations/updates, rounds, attempts,
redirects, observations, cancellation, failure, and completion. Verification rejects duplicate
JSON keys, non-finite numbers, malformed digests, sequence gaps, reorder, truncation, tampering, and
unknown event types.

## Experiment v8

`mrma.experiment/v8` is strict Draft 2020-12 JSON Schema with nested
`additionalProperties: false`. It includes run state, authorization summary, plan, budget, journal,
transport/runtime provenance, comparison resource outcomes, charset resolution, observations,
analysis, exploration/confirmation role, assurance dimensions, a complete privacy-safe effective
plan, and structured limitations.

Cross-field constraints and verifier checks prevent decisive verdicts with incomplete sampling,
research authorization bypass, insecure unacknowledged TLS, exact replay claims from semantic
HTTP, false durable claims, false complete header coverage, and no-influence conclusions after
comparison failure. Verification recomputes the v2 effective-plan digest from its canonical
document. Published experiment schemas v2 through v8 are byte-locked by tests.

The evidence plan digest uses run-local fingerprints and is intended for bundle integrity, not
cross-run approval. Dry-run output separately exposes a deterministic local approval-plan digest
that binds exact request values, privacy mode, authorization digest, comparison policy, and selected
transport policy. The approval digest is excluded from journals and shared v8 evidence.

## Partial results

Keyboard interruption, cancellation, authorization rejection, budget exhaustion, transport/policy
failure, and incomplete transport sampling produce v8-valid partial evidence. Status, planned and
completed rounds, stop reason, consumed budget, collected observations, limitations, and
`INCONCLUSIVE` remain available. Complete sampling requires completed status, exact rounds, and the
exact planned observation count.

## Privacy

Standard and strict evidence use per-run keyed fingerprints and reduced timing/target precision.
Forensic mode retains more exact metadata and requires deliberate use. Public evidence contains a
summary and digest, not the executable authorization manifest. Raw credentials, proxy credentials,
authorization tokens, environment values, mutation secrets, and local paths are forbidden by model
and tests. Version 8 declares cross-run correlation as partial because authorization digests,
original-source digests, and journal target, origin, address-set, and effective-authority
identifiers are deterministic. Mutation-delta identifiers written to the journal are run-local
HMAC fingerprints; the deterministic local delta digest remains inside the authorization and
transport capability boundary.

## Bundle

An `mrma.evidence-bundle/v1` ZIP has deterministic entry order, timestamps, permissions, and
serialization. It contains plan, result, authorization summary, journal, schema, runtime, packaged
release benchmark, replay instructions, and a file-digest manifest. `mrma evidence verify` checks
the ZIP file set, sizes/digests, schema compatibility, result/journal linkage, observation counts,
benchmark schema, effective-plan digest, and equality between the result digest and every journal
`RUN_PLANNED` event.

The hash chain detects modification but does not authenticate who created an entirely new bundle.
MRMA does not implement a home-grown signature scheme; organizational trust roots remain deferred.
