# Python API

## Stable v0.4 entry points

The public typed surfaces are exported from `mrma.engine`, `mrma.policy`, `mrma.transport`,
`mrma.evidence`, and `mrma.workflows`.

```python
from mrma.core.compare import EquivalenceConfig
from mrma.core.experiment import ExperimentConfig
from mrma.core.http_client import SendOptions
from mrma.core.raw_request import RawRequest
from mrma.core.sender import SendPolicy
from mrma.engine import ExperimentOracle, ExperimentPlan
from mrma.evidence import EvidenceJournal
from mrma.policy import (
    BudgetLedger,
    BudgetLimits,
    ComparisonPolicy,
    ManifestAuthorizationPolicy,
    load_authorization_manifest,
)
from mrma.transport import SemanticHttpAdapter

manifest = load_authorization_manifest("authorization.json")
authorization = ManifestAuthorizationPolicy(manifest)
journal = EvidenceJournal(
    run_id="independent-run-id",
    path="run.journal.jsonl",
    mode="durable",
)
budgets = BudgetLedger(BudgetLimits.from_mapping(manifest.budget), journal)
comparison = ComparisonPolicy(EquivalenceConfig())
transport = SemanticHttpAdapter(
    SendOptions(trust_env=False, timeout_s=10),
    journal=journal,
    state_mode="isolated",
    connection_mode="fresh-observation",
)

baseline = RawRequest("GET", "/", "HTTP/1.1", [], b"")
mutation = RawRequest("GET", "/", "HTTP/1.1", [("X-Probe", "1")], b"")
plan = ExperimentPlan(
    baseline=baseline,
    mutation=mutation,
    base_url="http://127.0.0.1:8000",
    experiment=ExperimentConfig(
        rounds=20,
        assurance_preset="research",
        state_mode="isolated",
        connection_mode="fresh-observation",
        body_storage="full",
    ),
    send=SendPolicy(retries=0),
    follow_redirects=False,
    mutation_family="header",
    mutation_risk_class="safe",
    exploration_role="confirmation",
)

oracle = ExperimentOracle(
    authorization=authorization,
    budgets=budgets,
    transport=transport,
    comparison=comparison,
    evidence=journal,
)
summary = oracle.dry_run(plan)  # no networking
result = oracle.run(plan)
journal.close()
```

Call `dry_run` before `run` when building programmatic plans. It validates comparison policy,
worst-case aggregate capacity, target/mutation/hook authorization, and request bounds without
consuming repetition or budget.

## Evidence APIs

- `build_experiment_v8`: convert an `OracleRunResult` plus provenance into strict evidence.
- `validate_result_document`: JSON Schema and semantic cross-field verification.
- `create_evidence_bundle`: deterministic atomic bundle creation from public evidence and journal.
- `verify_evidence`, `verify_evidence_bundle`, `verify_journal`: offline integrity verification.
- `validate_benchmark_document`: benchmark schema verification.

## Compatibility

The v0.4 SDK surface is typed and strict-mypy clean, but MRMA remains a research tool. Schema
versions are stronger compatibility contracts than Python object internals. No API accepts an
authorization bypass, and transport does not accept a bare URL/request.
