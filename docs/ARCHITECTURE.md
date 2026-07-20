# Architecture

## Product boundary

MRMA v0.4.1 has one confirmatory engine and one shared network policy kernel. The CLI parses input,
selects workflow policy, and renders output. It does not own transport authorization decisions.

```text
CLI / Python caller
        |
        v
ExperimentPlan + ComparisonPolicy
        |
        v
ExperimentOracle
  | authorization -> AuthorizedRequestContext
  | budget        -> BudgetLease
  | journal       -> EvidenceContext
        |
        v
SemanticHttpAdapter (HTTPX, follow_redirects=False)
        |
        v
CapturedResponse -> experiment analysis -> v8 evidence -> bundle
```

## Enforced boundaries

`SemanticHttpAdapter.send()` requires all three unforgeable-in-normal-use capability objects:
an accepted `AuthorizedRequestContext`, an active `BudgetLease`, and an `EvidenceContext`. The
adapter revalidates context identity, records `ATTEMPT_STARTED`, performs one semantic HTTP
attempt, commits actual bounded cost, and records completion. It cannot be called with only a URL.

`ExperimentOracle` owns retries, redirect traversal, setup/reset hooks, schedules, observations,
and partial-run conversion. One observation session owns redirect/retry cookie state and its
fresh-observation client. HTTPX redirect following is always disabled. Every hop becomes a new
authorization decision and budget lease.

## Packages

- `mrma.engine`: typed plan and confirmatory oracle.
- `mrma.policy`: authorization, budgets, comparison, method risk, and protocol interfaces.
- `mrma.transport`: semantic HTTP adapter and request-byte estimator.
- `mrma.evidence`: append-only journal, v8 model, schema validation, bundles, and verification.
- `mrma.workflows`: candidate manifests and guarded legacy exploratory dispatch.
- `mrma.core`: comparison, statistical experiment, HTTP semantics, request model, and retained
  legacy algorithms.

## Network path inventory

`experiment` calls the oracle directly. Legacy network commands execute inside
`_legacy_network_scope`, which installs `LegacyAuthorizedDispatcher`; the existing sender API then
resolves to `ExperimentOracle.send_observation`. Architectural tests reject direct HTTPX use outside
the approved transport/core compatibility boundary and prove that legacy commands enter policy
scope.

`impact` is migrated to this policy kernel and emits a candidate manifest, but its ranking remains
one-pass exploratory analysis. Discovery, isolation, profiles, run, diff, and report are likewise
policy guarded but do not yet use the fixed-sample verdict oracle.

## Deliberate constraints

- HTTPX may normalize request syntax, framing, duplicate fields, protocol selection, and
  connection behavior. `semantic-http` is never labeled exact replay.
- Supported HTTPX APIs do not reliably expose the connected address, peer certificate, TLS cipher,
  or ALPN for every transport. Evidence records `null` plus limitations instead of inspecting
  unstable internals.
- Authorization manifests are unsigned policy documents. Organizational signing and trust
  roots are deferred.
- The CLI remains a large module. Further decomposition is deferred while the network boundary is
  enforced and tested.
