# Budget Model

## Central ledger

`BudgetLedger` is concurrency safe and shared by controls, mutations, retries, redirects, setup,
reset, and exploratory attempts. Limits cover total attempts, role counts, per-origin and per-target
counts, request/response bytes, per-response and request-body bounds, cumulative attempt duration,
wall-clock admission deadline, timeout, concurrency, redirect depth, and mutation risk.

## Lease lifecycle

For each network attempt MRMA:

1. authorizes the immutable request and any declared mutation delta;
2. asks HTTPX to build the final request, including cookie-jar and generated fields;
3. measures and seals that prepared representation after checking method, target, and `Host`;
4. atomically reserves counters, bytes, timeout, and concurrency;
5. revalidates authorization and records `BUDGET_RESERVED` plus `ATTEMPT_STARTED`;
6. recomputes the prepared digest, verifies the adapter seal and authorization fields, then sends
   the exact request object once;
7. commits bounded actual bytes and elapsed duration, or releases the lease;
8. records `BUDGET_UPDATED`.

No reservation is created when a check fails. A lease cannot be committed twice. Unused response
and timeout capacity is released. Active leases must be zero before final evidence is built.

## Byte accounting

Request accounting measures the final HTTPX request representation: request line, generated and
caller fields, cookie state, and body. Response accounting includes the represented status line,
fields, and bounded body; streaming stops when the remaining response allowance is consumed.

These values are semantic representation accounting, not wire telemetry. HTTP/2 framing,
compression, TLS records, and proxy protocol bytes are outside the supported HTTPX interface. Plan
summaries retain a declared-request preflight estimate because response-derived cookie state does
not exist before execution; every actual attempt still reserves its prepared size before sending.
HTTPX parses the response head before exposing the stream. A head that alone exceeds the allowance
is recorded as a policy abort with observed and charged representation sizes; MRMA cannot preempt
that parser step through HTTPX's supported interface.

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
