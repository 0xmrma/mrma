# Budget Model

## Central ledger

`BudgetLedger` is concurrency safe and shared by controls, mutations, retries, redirects, setup,
reset, and exploratory attempts. Limits cover total attempts, role counts, per-origin and per-target
counts, request/response bytes, per-response and request-body bounds, cumulative attempt duration,
wall-clock admission deadline, timeout, concurrency, redirect depth, and mutation risk.

## Lease lifecycle

For each network attempt MRMA:

1. computes a conservative proposed cost;
2. checks per-attempt and aggregate policy;
3. atomically reserves counters, bytes, timeout, and concurrency;
4. records `BUDGET_RESERVED`;
5. sends one attempt;
6. commits bounded actual bytes and elapsed duration, or releases the lease;
7. records `BUDGET_UPDATED`.

No reservation is created when a check fails. A lease cannot be committed twice. Unused response
and timeout capacity is released. Active leases must be zero before final evidence is built.

## Byte accounting

Response bytes are measured while streaming and reading stops at the reserved bound. Request bytes
are a deterministic conservative semantic upper-bound: request line, represented headers, body,
and a fixed HTTP-library overhead. This is not wire telemetry because HTTPX may alter framing,
encoding, or protocol representation. v7 records estimator version
`semantic-request-upper-bound/1.0` and the `SEMANTIC_REQUEST_BYTE_ESTIMATE` limitation.

## Duration accounting

`total_duration_ms` has two fail-closed checks:

- cumulative attempt elapsed time, clamped to each timeout reservation;
- a monotonic wall-clock admission deadline that includes time spent in backoff and processing
  before the next attempt.

A new attempt is rejected unless its full timeout fits inside both remaining capacities. Small
scheduler overhead after the last admitted attempt is not a hard process deadline; the property is
that no later network attempt is admitted beyond the declared wall deadline.

## Exhaustion

Budget exhaustion is a policy stop, not evidence of influence. The run becomes partial and
`INCONCLUSIVE`, with consumed totals and the stop reason retained. Retries and redirects are never
free continuations.
