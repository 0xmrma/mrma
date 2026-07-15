# Statistical Model

## Fixed design

Confirmatory `experiment` uses a predeclared sample. The default bracketed schedule records
control-before, mutation, and control-after for each round. A seeded balanced mode uses AB/BA blocks.
Research assurance fixes 20 bracketed rounds, isolated response-cookie state, fresh observation
clients, disabled retries, standard privacy, and full retained bodies within the response bound.

The design does not stop early for a positive or negative result. Early termination is limited to
cancellation, policy/resource failure, or rejecting invalid/unstable controls. Such work is
`INCONCLUSIVE`.

## Pair classification

Pairs are `CHANGED`, `UNCHANGED`, or `INDETERMINATE`. Status, selected response headers, body
evidence, redirect semantics, retry outcome/error sequences, and final origin can be decision
bearing. Comparator failure, incomplete body evidence, or unsupported text semantics cannot be
treated as unchanged.

## Intervals and verdicts

MRMA uses two-sided 95% Wilson score intervals for mutation and repeated-control change rates.

- Influence requires confidently stable controls and the mutation interval lower bound at or above
  `min_reproducibility`.
- No influence observed requires confidently stable controls, zero indeterminate mutation pairs,
  and the mutation interval upper bound at or below `no_influence_threshold`.
- Missing pairs, invalid controls, confident control instability, incomplete fixed sampling, or
  comparator limits yield `INCONCLUSIVE`.

The output includes operating characteristics for the planned rounds before networking. MRMA does
not call these intervals Bayesian probability, severity, exploitability, or proof of absence.

## Exploration and confirmation

Exploratory ranking changes the hypothesis-selection process and therefore cannot reuse
confirmatory language. `impact` emits a digest-bound candidate manifest. Confirmation consumes one
candidate in a new research run with a new run ID and seed, checks baseline and authorization
digests, and uses the fixed design.

## Independence limitations

Fresh observation clients reduce shared cookie and pool state but cannot guarantee independent
upstream routing, rate limits, WAF scoring, or server state. Reuse/per-arm/per-round modes disclose
weaker connection-independence dimensions. Timing/backoff differences are quantitative context, not
single-sample binary influence signals.
