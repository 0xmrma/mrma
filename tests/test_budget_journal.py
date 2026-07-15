from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from mrma.evidence.journal import (
    EvidenceContext,
    EvidenceIntegrityError,
    EvidenceJournal,
    verify_journal,
)
from mrma.policy.budget import AttemptCost, BudgetError, BudgetLedger, BudgetLimits


def limits(**overrides) -> BudgetLimits:
    values = {
        "total_network_attempts": 100,
        "controls": 100,
        "mutations": 100,
        "retries": 100,
        "redirects": 100,
        "setup_reset_attempts": 100,
        "attempts_per_origin": 100,
        "requests_per_target": 100,
        "bytes_sent": 10000,
        "bytes_received": 10000,
        "maximum_response_bytes": 1000,
        "maximum_request_body_bytes": 1000,
        "total_duration_ms": 100000,
        "per_attempt_timeout_ms": 1000,
        "concurrency": 20,
        "redirect_depth": 5,
        "mutation_risk_level": "non-idempotent",
    }
    values.update(overrides)
    return BudgetLimits(**values)


def cost(kind: str = "control") -> AttemptCost:
    return AttemptCost(kind, "sha256:origin", "sha256:target", 10, 30, 100, 500)


def test_reserve_commit_release_and_no_double_charge():
    journal = EvidenceJournal(run_id="run")
    ledger = BudgetLedger(limits(), journal)
    context = EvidenceContext("run", "a1", "control", 1)
    lease = ledger.reserve(cost(), evidence=context)
    snapshot = lease.commit(bytes_sent=30, bytes_received=40, duration_ms=25)

    assert snapshot.total_network_attempts == 1
    assert snapshot.bytes_received == 40
    assert snapshot.active_leases == 0
    with pytest.raises(BudgetError, match="INACTIVE_LEASE"):
        lease.commit(bytes_sent=30, bytes_received=40)

    released = ledger.reserve(
        cost("retry"), evidence=EvidenceContext("run", "a2", "retry", 1)
    )
    released.release("cancelled")
    assert ledger.snapshot() == snapshot
    assert [event.event_type for event in journal.events].count("BUDGET_RESERVED") == 2


def test_concurrent_reservations_never_exceed_or_go_negative():
    journal = EvidenceJournal(run_id="run")
    ledger = BudgetLedger(limits(concurrency=20), journal)

    def execute(index: int) -> None:
        lease = ledger.reserve(
            cost("mutation"),
            evidence=EvidenceContext("run", f"a{index}", "mutation", 1),
        )
        lease.commit(bytes_sent=30, bytes_received=50, duration_ms=10)

    with ThreadPoolExecutor(max_workers=20) as pool:
        list(pool.map(execute, range(40)))

    snapshot = ledger.snapshot()
    assert snapshot.total_network_attempts == 40
    assert snapshot.mutations == 40
    assert snapshot.bytes_received == 2000
    assert snapshot.active_leases == 0


def test_retry_redirect_and_actual_partial_bytes_are_charged():
    journal = EvidenceJournal(run_id="run")
    ledger = BudgetLedger(limits(), journal)
    for index, kind in enumerate(("control", "retry", "redirect"), start=1):
        lease = ledger.reserve(
            cost(kind), evidence=EvidenceContext("run", f"a{index}", kind, 1)
        )
        lease.commit(bytes_sent=30, bytes_received=17, duration_ms=5)

    snapshot = ledger.snapshot()
    assert snapshot.total_network_attempts == 3
    assert snapshot.retries == 1
    assert snapshot.redirects == 1
    assert snapshot.bytes_received == 51


def test_budget_exhaustion_occurs_before_a_lease_exists():
    journal = EvidenceJournal(run_id="run")
    ledger = BudgetLedger(limits(total_network_attempts=1), journal)
    first = ledger.reserve(cost(), evidence=EvidenceContext("run", "a1", "control", 1))
    with pytest.raises(BudgetError, match="BUDGET_EXHAUSTED"):
        ledger.reserve(cost(), evidence=EvidenceContext("run", "a2", "control", 1))
    first.release()
    assert ledger.snapshot().total_network_attempts == 0


def test_file_journal_verifies_and_detects_tampering(tmp_path: Path):
    path = tmp_path / "journal.jsonl"
    with EvidenceJournal(run_id="run", path=path, mode="durable") as journal:
        journal.record("RUN_PLANNED", {"plan_digest": "sha256:" + "a" * 64})
        journal.record("RUN_COMPLETED", {"verdict": "INCONCLUSIVE"})

    verified = verify_journal(path)
    assert verified["verified"] is True
    assert verified["event_count"] == 2

    records = path.read_text(encoding="ascii").splitlines()
    payload = json.loads(records[1])
    payload["data"]["verdict"] = "INFLUENCE_DETECTED"
    records[1] = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(records) + "\n", encoding="ascii")
    with pytest.raises(EvidenceIntegrityError, match="JOURNAL_DIGEST_MISMATCH"):
        verify_journal(path)


def test_journal_refuses_sensitive_field_names():
    journal = EvidenceJournal(run_id="run")
    with pytest.raises(EvidenceIntegrityError, match="SENSITIVE_EVIDENCE_FIELD"):
        journal.record("RUN_FAILED", {"authorization_token": "secret"})


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        (lambda value: value.update(extra=1), "UNKNOWN_BUDGET_FIELD"),
        (lambda value: value.pop("controls"), "MISSING_BUDGET_FIELD"),
        (lambda value: value.update(bytes_sent=-1), "INVALID_BUDGET_LIMIT"),
        (lambda value: value.update(concurrency=0), "INVALID_BUDGET_LIMIT"),
        (lambda value: value.update(per_attempt_timeout_ms=0), "INVALID_BUDGET_LIMIT"),
        (lambda value: value.update(mutation_risk_level="invalid"), "INVALID_BUDGET_LIMIT"),
    ],
)
def test_budget_limit_mapping_is_strict(mutation, code: str):
    values = limits().__dict__.copy()
    mutation(values)
    with pytest.raises(BudgetError, match=code):
        BudgetLimits.from_mapping(values)


@pytest.mark.parametrize(
    "attempt",
    [
        lambda: AttemptCost("unknown", "o", "t", 0, 0, 0, 1),
        lambda: AttemptCost("control", "o", "t", -1, 0, 0, 1),
        lambda: AttemptCost("control", "o", "t", 2, 1, 0, 1),
    ],
)
def test_attempt_cost_rejects_invalid_dimensions(attempt):
    with pytest.raises(BudgetError):
        attempt()


@pytest.mark.parametrize(
    ("overrides", "attempt", "code"),
    [
        ({"maximum_request_body_bytes": 5}, cost(), "REQUEST_BODY_LIMIT"),
        ({"maximum_response_bytes": 50}, cost(), "RESPONSE_LIMIT"),
        ({"per_attempt_timeout_ms": 100}, cost(), "ATTEMPT_TIMEOUT_LIMIT"),
        (
            {"redirect_depth": 0},
            AttemptCost("redirect", "o", "t", 0, 20, 20, 10, redirect_depth=1),
            "REDIRECT_DEPTH_LIMIT",
        ),
        (
            {"mutation_risk_level": "safe"},
            AttemptCost(
                "mutation",
                "o",
                "t",
                0,
                20,
                20,
                10,
                mutation_risk_level="non-idempotent",
            ),
            "MUTATION_RISK_LIMIT",
        ),
    ],
)
def test_reservation_rejects_per_attempt_policy_overruns(overrides, attempt, code: str):
    ledger = BudgetLedger(limits(**overrides), EvidenceJournal(run_id="run"))
    with pytest.raises(BudgetError, match=code):
        ledger.reserve(attempt, evidence=EvidenceContext("run", "a", attempt.kind))


def test_commit_rejects_actual_overruns_and_negative_cost_then_can_release():
    ledger = BudgetLedger(limits(), EvidenceJournal(run_id="run"))
    lease = ledger.reserve(cost(), evidence=EvidenceContext("run", "a", "control"))
    with pytest.raises(BudgetError, match="LEASE_SEND_OVERRUN"):
        lease.commit(bytes_sent=31, bytes_received=0)
    with pytest.raises(BudgetError, match="LEASE_RECEIVE_OVERRUN"):
        lease.commit(bytes_sent=30, bytes_received=101)
    with pytest.raises(BudgetError, match="NEGATIVE_ACTUAL_COST"):
        lease.commit(bytes_sent=-1, bytes_received=0)
    lease.release("tested")


def test_concurrency_and_unsettled_lease_are_enforced():
    ledger = BudgetLedger(limits(concurrency=1), EvidenceJournal(run_id="run"))
    first = ledger.reserve(cost(), evidence=EvidenceContext("run", "a1", "control"))
    with pytest.raises(BudgetError, match="CONCURRENCY_LIMIT"):
        ledger.reserve(cost(), evidence=EvidenceContext("run", "a2", "control"))
    with pytest.raises(BudgetError, match="ACTIVE_LEASES_REMAIN"):
        ledger.assert_settled()
    first.release()
    ledger.assert_settled()


def test_lease_context_releases_unused_reservation_and_duration_is_clamped():
    journal = EvidenceJournal(run_id="run")
    ledger = BudgetLedger(limits(), journal)
    with ledger.reserve(cost(), evidence=EvidenceContext("run", "a1", "control")):
        pass
    assert ledger.snapshot().total_network_attempts == 0

    lease = ledger.reserve(cost(), evidence=EvidenceContext("run", "a2", "control"))
    snapshot = lease.commit(bytes_sent=30, bytes_received=1, duration_ms=10000)
    assert snapshot.duration_ms == cost().timeout_ms


def test_wall_clock_deadline_is_checked_before_every_reservation():
    now = 10.0
    ledger = BudgetLedger(
        limits(total_duration_ms=1000),
        EvidenceJournal(run_id="run"),
        monotonic=lambda: now,
    )
    now = 10.502
    with pytest.raises(BudgetError, match="insufficient wall-clock time"):
        ledger.reserve(cost(), evidence=EvidenceContext("run", "a", "control"))


def test_wall_clock_and_cumulative_duration_limits_are_both_enforced():
    now = 10.0
    ledger = BudgetLedger(
        limits(total_duration_ms=999),
        EvidenceJournal(run_id="run"),
        monotonic=lambda: now,
    )
    first = ledger.reserve(cost(), evidence=EvidenceContext("run", "a1", "control"))
    first.commit(bytes_sent=30, bytes_received=1, duration_ms=500)
    with pytest.raises(BudgetError, match="total_duration_ms"):
        ledger.reserve(cost(), evidence=EvidenceContext("run", "a2", "control"))


def test_exact_wall_clock_reservation_boundary_is_allowed():
    ledger = BudgetLedger(
        limits(total_duration_ms=500),
        EvidenceJournal(run_id="run"),
        monotonic=lambda: 10.0,
    )
    lease = ledger.reserve(cost(), evidence=EvidenceContext("run", "a", "control"))
    lease.release("boundary-tested")


def test_request_byte_budget_uses_full_semantic_estimate():
    ledger = BudgetLedger(limits(bytes_sent=59), EvidenceJournal(run_id="run"))
    first = ledger.reserve(cost(), evidence=EvidenceContext("run", "a1", "control"))
    first.commit(bytes_sent=30, bytes_received=0, duration_ms=1)
    with pytest.raises(BudgetError, match="bytes_sent"):
        ledger.reserve(cost(), evidence=EvidenceContext("run", "a2", "control"))
