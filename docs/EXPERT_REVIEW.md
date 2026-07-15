# Expert Review Guide

## Exact claim

MRMA v0.4.0 is an authorization-enforcing, budgeted, recoverable HTTP trust-influence research
platform prepared for external expert evaluation. It remains a semantic-HTTP research tool; full
product-wide oracle migration and protocol-exact HTTP backends are separate future milestones.

## Non-claims

MRMA does not prove a vulnerability, exploitability, severity, component attribution, legal
authorization, transport-byte identity, statistical independence of a remote system, or absence of
an influence outside the tested policy/design. It is not enterprise-ready.

## Architecture and threat model

The confirmatory path is `ExperimentPlan -> ExperimentOracle -> authorization -> lease -> journal ->
SemanticHttpAdapter`. Redirects, retries, hooks, and exploratory sends use the same policy kernel.
See [ARCHITECTURE.md](ARCHITECTURE.md) and [THREAT_MODEL.md](THREAT_MODEL.md).

The strongest authorization limitation is DNS/socket binding: all current answers are authorized
and rechecked immediately before send, but supported HTTPX APIs do not bind that set to the eventual
socket. Manifests are also unsigned local policy documents.

## Reproduce a result

1. Install the exact wheel/container and record its digest.
2. Review the manifest, method risk, path/CIDR scope, expiry, hooks, redirects, and worst-case budget.
3. Run `mrma experiment ... --dry-run`.
4. Execute one independent research run with a new journal path and bundle path.
5. Preserve result, journal, bundle, authorization grant separately, tool artifact digest, and any
   external approval record.
6. Repeat as a new independent run rather than extending a completed fixed sample.

## Verify evidence

```bash
mrma evidence verify result.json --json
mrma evidence verify run.journal.jsonl --json
mrma evidence verify run.zip --json
```

Bundle verification checks digests, file set, schema, journal chain, result linkage, observation
count, and packaged benchmark. It does not authenticate the bundle author.

## Benchmark procedure

Run `mrma benchmark --out-json benchmark.json` in the reviewed environment. Compare all 22
expected/actual cases and the platform fingerprint with the packaged baseline. Runtime and memory
may vary; conclusions must all pass. See [BENCHMARKS.md](BENCHMARKS.md).

## Known limitations

- Semantic HTTPX transport; no wire-exact HTTP/1 or protocol-native HTTP/2 backend.
- No stable connected-address, peer-certificate, cipher, or ALPN evidence on the supported adapter.
- `impact` and other legacy workflows are policy guarded but remain statistically exploratory.
- The CLI is not fully decomposed; the stable engine/policy/evidence APIs are separate.
- Request sent-byte accounting is conservative estimation, not wire telemetry.
- Hash chains provide integrity detection, not organizational identity.
- No signed authorization grants, encrypted evidence store, distributed budgets, or multi-user
  governance.
- The local benchmark is finite and cannot cover all HTTP intermediaries or state interactions.

## Requested review questions

1. Can any network path bypass authorization, budget reservation, or journal context?
2. Are host/path/method/CIDR/proxy/redirect semantics fail-closed under DNS and URL edge cases?
3. Are the fixed-sample verdict rules and control-instability handling defensible?
4. Can semantic equivalence create meaningful false positives or false negatives for the documented
   media/header registry?
5. Do v7 and bundle cross-field checks prevent overclaiming on partial/resource-limited runs?
6. Does standard/strict evidence leak target secrets, credentials, paths, environment values, or
   executable policy data?
7. Are the stated transport and integrity limitations complete and understandable?

## Quality evidence

The v0.4 pre-release baseline is 281 passing tests, 68% honest whole-repository branch coverage,
95.39% combined critical-runtime branch coverage (every listed module above 90%), 86.89% corrected
core branch coverage, strict mypy success on all 19 v0.4 modules, and 12/12 killed semantic critical
mutants. Re-run gates on the release commit; these numbers must be updated if code changes.

## Responsible testing and defects

Run only under explicit owner authorization. Treat setup/reset and state-changing methods as real
effects. Do not share target evidence publicly. Report security defects through the private GitHub
Security Advisory flow described in [../SECURITY.md](../SECURITY.md), including version, artifact
digest, minimal reproduction, affected invariant, and sanitized evidence.
