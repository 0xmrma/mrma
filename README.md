# MRMA

MRMA is an authorization-enforcing, budgeted, recoverable HTTP trust-influence research platform.
It runs repeated control/mutation experiments to test whether one request property reproducibly
changes an observed HTTP outcome.

> **Status: v0.4.0 research preview and expert-review candidate.** MRMA uses a semantic HTTPX
> transport. It does not provide wire-exact replay, prove exploitability, identify a proprietary
> component from black-box behavior, or claim enterprise readiness.

## What v0.4.0 enforces

- Every network attempt requires an accepted `mrma.authorization/v1` decision, a central budget
  lease, and journal context.
- Redirects are followed manually and reauthorized at every hop. Retries and setup/reset hooks are
  separate charged attempts.
- Research assurance uses isolated state, fresh observation clients, disabled retries, bounded
  bodies, and a predeclared fixed sample.
- Partial or resource-limited work returns `INCONCLUSIVE` with structured limitations.
- `mrma.experiment/v7` evidence records policy, budget, journal, comparison, semantic, transport,
  and runtime provenance without embedding the executable authorization grant.
- Deterministic evidence bundles include the result, append-only hash-chained journal, schema,
  release benchmark, runtime manifest, digests, and replay instructions.

## Install

```bash
python -m pip install mrma==0.4.0
mrma --version
```

Python 3.10 and 3.13 are tested on Linux, Windows, and macOS (six CI environments).

## Start locally

Run the loopback-only expert benchmark; it sends no traffic to public targets:

```bash
mrma benchmark --out-json benchmark.json
```

Validate an authorization manifest:

```bash
mrma authorization validate examples/authorization.local.json --json
```

Start a local service on `127.0.0.1:8000`, then inspect the complete maximum plan without
networking:

```bash
mrma experiment \
  --url http://127.0.0.1:8000/ \
  --set-header "X-Probe: 1" \
  --assurance research \
  --authorization examples/authorization.local.json \
  --journal local-plan.journal.jsonl \
  --dry-run
```

Remove `--dry-run` to execute and create a review bundle:

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

Authorization manifests are policy grants, not proof of legal authority. Replace the local example
with a short-lived manifest issued under the engagement's real approval process.

## Result semantics

- `INFLUENCE_DETECTED`: controls were stable and the 95% lower bound for changed mutation pairs
  met the predeclared reproducibility threshold.
- `NO_INFLUENCE_OBSERVED`: controls were stable and the 95% upper bound stayed below the
  predeclared no-influence threshold.
- `INCONCLUSIVE`: sampling, controls, transport, policy, body evidence, or comparator resources did
  not support either conclusion.

These are experiment conclusions, not severity or vulnerability labels. Exit codes remain opt-in:
`10` for influence and `11` for inconclusive under the selected `--fail-on` policy. Policy and
evidence-integrity failures return nonzero command errors and retain typed evidence where a run was
initialized.

## Workflow status

| Workflow | v0.4 status |
|---|---|
| `experiment` | Confirmatory fixed-sample `ExperimentOracle`; strict v7 result |
| `impact` | Exploratory ranking through the policy kernel; emits a candidate manifest |
| `run`, `diff`, `discover`, `isolate`, profiles, report | Authorization/budget/journal guarded, but statistically exploratory |
| Candidate confirmation | Independent `experiment` run bound to one candidate-manifest digest |

## Documentation

- [Expert review](docs/EXPERT_REVIEW.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Authorization](docs/AUTHORIZATION.md)
- [Budget model](docs/BUDGET_MODEL.md)
- [Evidence model](docs/EVIDENCE_MODEL.md)
- [Statistical model](docs/STATISTICAL_MODEL.md)
- [HTTP semantics](docs/HTTP_SEMANTICS.md)
- [Benchmark](docs/BENCHMARKS.md)
- [Python API](docs/API.md)
- [Roadmap](docs/ROADMAP.md)
- [Release verification](docs/RELEASE_SECURITY.md)

## Responsible use

Use MRMA only against targets and request effects explicitly authorized by the target owner. Keep
state-changing methods, path scope, redirect destinations, CIDRs, rates, byte limits, and expiry as
narrow as the research design permits. Report security defects through GitHub's private Security
Advisory flow as described in [SECURITY.md](SECURITY.md).

## Positioning

MRMA v0.4.0 is an authorization-enforcing, budgeted, recoverable HTTP trust-influence research
platform prepared for external expert evaluation. It remains a semantic-HTTP research tool; full
product-wide oracle migration and protocol-exact HTTP backends are separate future milestones.

## Author

Mohamed Abdelaal / [0xMRMA](https://0xmrma.com)
