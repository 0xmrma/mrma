<p align="center">
  <img src="https://raw.githubusercontent.com/0xmrma/mrma/main/docs/assets/mrma-readme.svg" width="100%" alt="MRMA - HTTP Trust-Influence Analyzer">
</p>

<p align="center">
  <a href="https://github.com/0xmrma/mrma/actions/workflows/ci.yml"><img alt="Quality" src="https://github.com/0xmrma/mrma/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/0xmrma/mrma/actions/workflows/codeql.yml"><img alt="CodeQL" src="https://github.com/0xmrma/mrma/actions/workflows/codeql.yml/badge.svg"></a>
  <a href="https://github.com/0xmrma/mrma/releases"><img alt="Release" src="https://img.shields.io/github/v/release/0xmrma/mrma?display_name=tag&sort=semver"></a>
  <a href="https://github.com/0xmrma/mrma/pkgs/container/mrma"><img alt="OCI package" src="https://img.shields.io/badge/OCI-ghcr.io-2496ED"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-MIT-35c48d"></a>
</p>

<p align="center">
  <strong>Does one authorized request change reproducibly alter an HTTP outcome?</strong><br>
  MRMA answers that question with repeated controls, bounded mutations, and independently
  verifiable evidence.
</p>

> **Current release: v0.4.3.** MRMA uses semantic HTTP through HTTPX. It does not claim wire-exact
> replay, prove exploitability, assign severity, or identify a proprietary component from
> black-box behavior.

## Why MRMA exists

Security testing often observes that a request changed and a response changed. That alone does not
establish influence. Dynamic content, connection state, retries, redirects, and unstable controls
can produce the same appearance.

MRMA treats the task as a controlled experiment:

1. Predeclare a baseline, one mutation, policies, bounds, and a fixed sample.
2. Bracket mutations with controls or use a seeded balanced schedule.
3. Reject unstable, incomplete, unauthorized, or resource-limited evidence.
4. Return a narrow conclusion with the observations, limitations, and provenance needed to check it.

## Enforcement pipeline

No HTTP attempt can bypass the shared runtime sequence.

```text
Authorization decision
        |
        v
Final HTTPX request preparation
        |
        v
Budget reservation
        |
        v
Immediate authorization revalidation
        |
        v
Journaled attempt identity
        |
        v
Semantic HTTP send
        |
        v
Budget commit + bounded observation
        |
        v
Comparison + fixed-sample conclusion
```

| Boundary | Enforced behavior |
|---|---|
| Authorization | Exact ASCII host labels, target representation, CIDR, method, operation kind, path, query, authority, proxy, redirect, mutation, and expiry policy |
| Effective authority | URL, `Host`, TLS SNI, and proxy CONNECT are checked separately; duplicate `Host` fields are rejected |
| Redirects | Every hop is manually resolved, reauthorized, budgeted, and journaled |
| Cross-origin state | Caller fields are deny-by-default; the final HTTPX-built request also suppresses cookie-jar and explicit `Cookie` fields unless policy explicitly allows them |
| Budgets | The final prepared request and bounded response representation, including fields added by HTTPX, use one reserve/commit ledger with attempts, roles, redirects, retries, targets, origins, duration, depth, concurrency, and method risk |
| Evidence | Effective plan digest, result, journal, schema, benchmark, runtime data, and bundle file digests are cross-checked offline |

## Install

```bash
python -m pip install mrma==0.4.3
mrma --version
```

MRMA is tested on Python 3.10 and 3.13 across Linux, Windows, and macOS.

The published container supports Linux AMD64 and ARM64:

```bash
docker pull ghcr.io/0xmrma/mrma:0.4.3
docker run --rm ghcr.io/0xmrma/mrma:0.4.3 --version
```

## Start without network traffic

Run the packaged 22-case loopback corpus:

```bash
mrma benchmark --out-json benchmark.json
```

Validate the example authorization policy:

```bash
mrma authorization validate examples/authorization.local.json --json
```

Inspect the maximum experiment plan without sending a request:

```bash
mrma experiment \
  --url http://127.0.0.1:8000/ \
  --set-header "X-Probe: 1" \
  --assurance research \
  --authorization examples/authorization.local.json \
  --journal local-plan.journal.jsonl \
  --dry-run
```

Dry-run output includes a local deterministic approval-plan digest. The privacy-safe plan digest in
shared evidence remains run-local and intentionally cannot correlate private request values across
runs.

The example policy authorizes loopback only. Start a service on `127.0.0.1:8000`, then execute the
same plan and produce a deterministic evidence bundle:

```bash
mrma experiment \
  --url http://127.0.0.1:8000/ \
  --set-header "X-Probe: 1" \
  --assurance research \
  --authorization examples/authorization.local.json \
  --journal local-run.journal.jsonl \
  --bundle local-run.zip \
  --json > local-run.json

mrma evidence verify local-run.zip --json
```

Authorization manifests are policy inputs, not proof of permission. Use a short-lived manifest
issued under the target owner's actual approval process.

## Result semantics

| Conclusion | Meaning |
|---|---|
| `INFLUENCE_DETECTED` | Controls were stable and the 95% lower bound for changed mutation pairs met the predeclared reproducibility threshold |
| `NO_INFLUENCE_OBSERVED` | Controls were stable and the 95% upper bound stayed below the predeclared no-influence threshold |
| `INCONCLUSIVE` | Sampling, controls, authorization, transport, policy, body evidence, or comparator resources did not support either conclusion |

These are experiment conclusions, not vulnerability or safety labels. Automation exit codes are
opt-in: `10` for influence and `11` for inconclusive under the selected `--fail-on` policy.

## Evidence bundle

```text
evidence.zip
|-- manifest.json       file set, sizes, and SHA-256 digests
|-- result.json         strict mrma.experiment/v8 document
|-- plan.json           privacy-safe effective plan + bound digest
|-- journal.jsonl       append-only hash-chained runtime events
|-- authorization.json  non-executable policy summary
|-- benchmark.json      packaged release baseline
|-- runtime.json        tool and dependency provenance
|-- schema.json         exact result schema
`-- REPLAY.md           offline verification instructions
```

`mrma evidence verify` checks the bundle manifest, exact schema, result cross-fields, effective-plan
digest, `RUN_PLANNED` linkage, journal chain/head/count, observation count, authorization summary,
and benchmark contract. Integrity verification does not prove who created an entirely new bundle;
artifact authenticity is supplied separately by GitHub release and OCI attestations.

## Workflows

| Interface | Role | Output |
|---|---|---|
| `experiment` | Confirmatory fixed-sample oracle | Strict v8 result and optional evidence bundle |
| `impact` | Exploratory candidate ranking | Candidate manifest for independent confirmation |
| `run`, `diff`, `discover`, `isolate`, profiles, `report` | Policy-guarded exploration | Bounded observations and journal events |
| `benchmark` | Deterministic local validation | Schema-validated 22-case result |
| `authorization validate` | Offline policy validation | Canonical policy summary and digest |
| `evidence verify` | Offline integrity verification | Typed verification result or integrity error |

All exploratory sends retain the immutable workflow baseline and apply the same header-mutation
policy before networking. Exploratory output is not promoted to confirmatory evidence.

## Design boundaries

- Semantic HTTP only. HTTPX may normalize request syntax; no wire-byte equivalence is claimed.
- Response bodies are bounded. Truncation or comparator exhaustion becomes structured uncertainty.
- Default comparison does not mask identifier-shaped values. Explicit normalization can support a
  changed result, but cannot turn different complete body digests into a no-influence result.
- Standard and strict privacy use run-local HMAC fingerprints, while selected policy and journal
  identifiers remain deterministically linkable and are declared as such.
- The hash chain detects modification of an existing journal. It is not an author signature.
- Authorization v1 remains readable; new policies should use strict `mrma.authorization/v2`.
- Published schema versions remain packaged and byte-locked for compatibility.

## Documentation

| Topic | Document |
|---|---|
| Runtime structure | [Architecture](docs/ARCHITECTURE.md) |
| Policy contract | [Authorization](docs/AUTHORIZATION.md) |
| Request accounting | [Budget model](docs/BUDGET_MODEL.md) |
| Result and bundle integrity | [Evidence model](docs/EVIDENCE_MODEL.md) |
| Fixed-sample decisions | [Statistical model](docs/STATISTICAL_MODEL.md) |
| HTTP comparison rules | [HTTP semantics](docs/HTTP_SEMANTICS.md) |
| Security assumptions | [Threat model](docs/THREAT_MODEL.md) |
| Reproducible corpus | [Benchmark](docs/BENCHMARKS.md) |
| Typed interfaces | [Python API](docs/API.md) |
| Verification record | [Validation](docs/VALIDATION.md) |
| Artifact provenance | [Release verification](docs/RELEASE_SECURITY.md) |

## Release integrity

Releases use protected, SSH-signed annotated tags. GitHub Actions builds the wheel, source archive,
and multi-platform OCI index, then publishes provenance attestations and an SBOM. Verification
commands and trust boundaries are documented in [Release verification](docs/RELEASE_SECURITY.md).

## Responsible use

Use MRMA only against targets and request effects explicitly authorized by the target owner. Keep
methods, paths, redirect destinations, CIDRs, mutation names, rates, bytes, and expiry narrower than
the experiment requires. Report defects through GitHub's private Security Advisory flow described
in [SECURITY.md](SECURITY.md).

## Author and license

Created by Mohamed Abdelaal / [0xMRMA](https://0xmrma.com). Released under the [MIT License](LICENSE).
