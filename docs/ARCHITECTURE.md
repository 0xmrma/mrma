# Architecture

## Product boundary

MRMA v0.4.4 has one confirmatory engine and one shared network policy kernel. The CLI parses input,
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
  | prepare       -> opaque, adapter-sealed request capability
  | budget        -> BudgetLease for the prepared representation
  | revalidate    -> authorization + prepared capability
  | journal       -> EvidenceContext
        |
        v
SemanticHttpAdapter (HTTPX, follow_redirects=False)
        |
        v
CapturedResponse -> experiment analysis -> v8 evidence -> bundle
```

## Enforced boundaries

`SemanticHttpAdapter.prepare()` builds the final HTTPX request and returns an opaque capability with
safe accounting metadata; the mutable HTTPX object is not exported. The capability is sealed with
an adapter-local key over the authorization identity, arm, round, accounting values, mutation
delta, and a digest of the final method, URL, ordered raw fields, buffered content and stream,
extensions, effective `Host`, and represented size.

`SemanticHttpAdapter.send_prepared()` requires that capability plus an accepted
`AuthorizedRequestContext`, active `BudgetLease`, and matching `EvidenceContext`. Immediately before
network I/O it recomputes the request digest, verifies the adapter seal, repeats method/URL/`Host`
authorization checks, and compares actual body and representation sizes with the reservation. A
changed, stale-session, or already-consumed capability fails before `ATTEMPT_STARTED`. `send()` is
the single-call convenience path through the same prepare and send-prepared boundary; neither
method can be called with only a URL.

`ExperimentOracle` owns retries, redirect traversal, setup/reset hooks, schedules, observations,
and partial-run conversion. One observation session owns redirect/retry cookie state and its
fresh-observation client. HTTPX redirect following is always disabled. Every hop becomes a new
authorization decision and budget lease. Cross-origin policy is applied again to the final
HTTPX-built request so eligible cookie-jar state cannot bypass raw-field filtering.

## Packages

- `mrma.engine`: typed plan and confirmatory oracle.
- `mrma.policy`: authorization, budgets, comparison, method risk, and protocol interfaces.
- `mrma.transport`: semantic HTTP adapter, opaque prepared capability, and request-byte estimator.
  The capability preserves the public type name but does not expose a public HTTPX request field.
- `mrma.evidence`: append-only journal, v8 model, schema validation, bundles, and verification.
- `mrma.workflows`: candidate manifests and guarded legacy exploratory dispatch.
- `mrma.core`: comparison, statistical experiment, HTTP semantics, request model, and retained
  legacy algorithms.

## Network path inventory

`experiment` calls the oracle directly. Legacy network commands execute inside
`_legacy_network_scope`, which installs `LegacyAuthorizedDispatcher`; the existing sender API then
resolves to `ExperimentOracle.send_observation`. The dispatcher retains the immutable request loaded
at workflow entry and validates every outgoing header mutation against it before preparing a
transport. Architectural tests reject direct HTTPX use outside the approved transport/core
compatibility boundary and prove that legacy commands enter policy scope.

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
