# Benchmarks

## Corpus

`mrma benchmark` starts a temporary loopback server and runs 22 ground-truth cases covering stable
and changed bodies/status/headers, redirects, retries, unstable controls, cookie/connection state,
Content-Type and XML semantics, binary/truncated bodies, comparator/normalization limits,
authorization rejection, budget exhaustion, cancellation, and binary raw input. It never contacts a
public target.

The result schema is `mrma.benchmark/v2`; corpus version is
`trust-influence-loopback/2.0`. Output includes each expected/actual conclusion, request cost, runtime,
false positive/negative counts, inconclusive count, peak traced memory, and platform/runtime.

## Release baseline

The exact machine-readable baseline is packaged at
`mrma/benchmarks/release-baseline.json`, validated against
`mrma/schemas/benchmark-v2.schema.json`, and included in default evidence bundles. Performance
is descriptive, not a cross-platform threshold. Correct expected/actual conclusions and zero false
results are the release gate. Counts describe this synthetic corpus only and are not estimates for
deployed HTTP systems.

## Reproduce

```bash
mrma benchmark --json
mrma benchmark --out-json benchmark-result.json
python -m pytest tests/test_benchmark.py
```

CI runs the full corpus independently on Linux and includes it in the six-platform/Python test
matrix. A passing finite local corpus does not establish correctness for all deployed HTTP systems.
