from __future__ import annotations

import json
from collections.abc import Callable
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from threading import Event
from uuid import uuid4

import httpx
import pytest
from jsonschema import Draft202012Validator

from mrma.core.compare import EquivalenceConfig
from mrma.core.experiment import ExperimentConfig
from mrma.core.http_client import CapturedResponse, SemanticHttpTransport, SendOptions
from mrma.core.privacy import EvidenceRedactor
from mrma.core.raw_request import RawRequest
from mrma.core.sender import SendPolicy
from mrma.engine import ExperimentOracle, ExperimentPlan
from mrma.engine.oracle import _redirect_request
from mrma.evidence import EvidenceIntegrityError, EvidenceJournal, validate_result_document
from mrma.evidence.models import build_experiment_v7, build_experiment_v8
from mrma.policy.authorization import ManifestAuthorizationPolicy, load_authorization_manifest
from mrma.policy.budget import BudgetLedger, BudgetLimits
from mrma.policy.comparison import ComparisonPolicy
from mrma.transport import SemanticHttpAdapter


def build_oracle(
    payload: dict[str, object],
    write_authorization: Callable[[dict[str, object]], Path],
    monkeypatch,
    handler,
):
    manifest = load_authorization_manifest(write_authorization(payload))
    authorization = ManifestAuthorizationPolicy(
        manifest,
        resolver=lambda _host, _port: ("127.0.0.1",),
    )
    journal = EvidenceJournal(run_id="oracle-test")
    ledger = BudgetLedger(BudgetLimits.from_mapping(manifest.budget), journal)
    adapter = SemanticHttpAdapter(
        SendOptions(trust_env=False, timeout_s=1),
        journal=journal,
        state_mode="isolated",
        connection_mode="fresh-observation",
    )
    monkeypatch.setattr(
        SemanticHttpTransport,
        "_new_client",
        lambda _self: httpx.Client(transport=httpx.MockTransport(handler)),
    )
    return (
        ExperimentOracle(
            authorization=authorization,
            budgets=ledger,
            transport=adapter,
            comparison=ComparisonPolicy(EquivalenceConfig()),
            evidence=journal,
        ),
        journal,
    )


def plan(
    *,
    follow_redirects: bool = True,
    response_header_scope: str = "known",
) -> ExperimentPlan:
    baseline = RawRequest(
        "GET",
        "/start",
        "HTTP/1.1",
        [("Accept", "text/plain")],
        b"",
        original_sha256="baseline",
    )
    mutation = RawRequest(
        "GET",
        "/start",
        "HTTP/1.1",
        [("Accept", "text/plain"), ("X-Probe", "1")],
        b"",
        original_sha256="mutation",
    )
    return ExperimentPlan(
        baseline=baseline,
        mutation=mutation,
        base_url="http://example.test",
        experiment=ExperimentConfig(
            rounds=6,
            schedule_mode="bracketed",
            connection_mode="fresh-observation",
            max_response_bytes=1024,
            body_storage="full",
            assurance_preset="research",
            response_header_scope=response_header_scope,
        ),
        send=SendPolicy(retries=0),
        follow_redirects=follow_redirects,
        mutation_family="header",
        mutation_risk_class="safe",
        exploration_role="confirmation",
    )


def v8_document(oracle, journal, experiment_plan, result):
    journal.close()
    return build_experiment_v8(
        result,
        plan=experiment_plan,
        authorization=oracle.authorization,
        budgets=oracle.budgets,
        journal=journal,
        run_id=uuid4().hex,
        started_at="2026-07-15T12:00:00+00:00",
        completed_at="2026-07-15T12:01:00+00:00",
        duration_ms=60000,
        transport_configuration={
            "trust_environment": False,
            "tls": {"verification": "system", "ca_fingerprint": None},
            "proxy": {
                "mode": "none",
                "source": "none",
                "endpoint_fingerprint": None,
            },
        },
    )


def test_oracle_manually_authorizes_and_charges_every_redirect(
    authorization_payload,
    write_authorization,
    monkeypatch,
):
    requests: list[str] = []

    def handler(incoming: httpx.Request) -> httpx.Response:
        requests.append(str(incoming.url))
        if incoming.url.path == "/start":
            return httpx.Response(302, headers={"Location": "/final"})
        body = b"mutation" if incoming.headers.get("x-probe") == "1" else b"control"
        return httpx.Response(200, headers={"Content-Type": "text/plain"}, content=body)

    oracle, journal = build_oracle(
        authorization_payload,
        write_authorization,
        monkeypatch,
        handler,
    )
    result = oracle.run(plan())

    assert result.status == "completed"
    assert result.completed_rounds == 6
    assert result.budget.total_network_attempts == len(requests) == 36
    assert result.budget.controls == 12
    assert result.budget.mutations == 6
    assert result.budget.redirects == 18
    event_types = [event.event_type for event in journal.events]
    assert event_types.count("AUTHORIZATION_ACCEPTED") == 72
    assert event_types.count("BUDGET_RESERVED") == 36
    assert event_types.count("ATTEMPT_STARTED") == 36
    assert event_types.count("ATTEMPT_COMPLETED") == 36
    assert event_types.count("REDIRECT_AUTHORIZED") == 18
    assert event_types[-1] == "RUN_COMPLETED"


def test_isolated_observation_preserves_redirect_cookie_only_inside_chain(
    authorization_payload,
    write_authorization,
    monkeypatch,
):
    initial_cookies: list[str | None] = []
    continuation_cookies: list[str | None] = []

    def handler(incoming: httpx.Request) -> httpx.Response:
        if incoming.url.path == "/start":
            initial_cookies.append(incoming.headers.get("cookie"))
            return httpx.Response(
                302,
                headers={"Location": "/continue", "Set-Cookie": "flow=abc; Path=/"},
            )
        continuation_cookies.append(incoming.headers.get("cookie"))
        return httpx.Response(200, headers={"Content-Type": "text/plain"}, content=b"ok")

    oracle, _journal = build_oracle(
        authorization_payload,
        write_authorization,
        monkeypatch,
        handler,
    )
    result = oracle.run(plan())

    assert result.status == "completed"
    assert initial_cookies and set(initial_cookies) == {None}
    assert continuation_cookies and set(continuation_cookies) == {"flow=abc"}


def test_cross_origin_redirect_suppresses_domain_cookie_after_request_build(
    authorization_payload,
    write_authorization,
    monkeypatch,
):
    payload = deepcopy(authorization_payload)
    payload["rules"][0]["hosts"] = ["a.example.test", "b.example.test"]
    destination_cookies: list[tuple[str, str | None]] = []

    def handler(incoming: httpx.Request) -> httpx.Response:
        if incoming.url.host == "a.example.test":
            return httpx.Response(
                302,
                headers={
                    "Location": "http://b.example.test/final",
                    "Set-Cookie": "flow=abc; Domain=.example.test; Path=/",
                },
            )
        destination_cookies.append((incoming.url.path, incoming.headers.get("cookie")))
        if incoming.url.path == "/final":
            return httpx.Response(
                302,
                headers={
                    "Location": "/done",
                    "Set-Cookie": "destination=1; Path=/",
                },
            )
        return httpx.Response(200, headers={"Content-Type": "text/plain"}, content=b"ok")

    oracle, journal = build_oracle(payload, write_authorization, monkeypatch, handler)
    experiment_plan = replace(plan(), base_url="http://a.example.test")
    result = oracle.run(experiment_plan)

    assert result.status == "completed"
    assert destination_cookies
    assert len(destination_cookies) % 2 == 0
    assert all(
        pair == (("/final", None), ("/done", "destination=1"))
        for pair in zip(destination_cookies[::2], destination_cookies[1::2], strict=True)
    )
    redirect_attempts = [
        event
        for event in journal.events
        if event.event_type == "ATTEMPT_STARTED" and event.data["role"] == "redirect"
    ]
    assert redirect_attempts
    forwarding = [event.data["state_field_forwarding"] for event in redirect_attempts]
    assert len(forwarding) % 2 == 0
    assert all(
        pair == ("suppressed", "allowed")
        for pair in zip(forwarding[::2], forwarding[1::2], strict=True)
    )


def test_unauthorized_redirect_stops_before_second_network_attempt(
    authorization_payload,
    write_authorization,
    monkeypatch,
):
    payload = deepcopy(authorization_payload)
    payload["rules"][0]["path_prefixes"] = ["/start"]
    requests = 0

    def handler(_incoming: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(302, headers={"Location": "/outside"})

    oracle, journal = build_oracle(payload, write_authorization, monkeypatch, handler)
    result = oracle.run(plan())

    assert result.status == "partial"
    assert result.verdict == "INCONCLUSIVE"
    assert result.stop_reason == "target_not_authorized"
    assert requests == 1
    assert result.budget.total_network_attempts == 1
    event_types = [event.event_type for event in journal.events]
    assert event_types.count("ATTEMPT_STARTED") == 1
    assert event_types.count("AUTHORIZATION_REJECTED") == 1
    assert event_types[-1] == "RUN_FAILED"


def test_dry_run_authorizes_without_network_or_budget_consumption(
    authorization_payload,
    write_authorization,
    monkeypatch,
):
    def forbidden(_incoming: httpx.Request) -> httpx.Response:
        raise AssertionError("dry-run performed networking")

    oracle, journal = build_oracle(
        authorization_payload,
        write_authorization,
        monkeypatch,
        forbidden,
    )
    summary = oracle.dry_run(plan())

    assert summary.maximum_attempts_with_redirects == 90
    assert oracle.budgets.snapshot().total_network_attempts == 0
    assert [event.event_type for event in journal.events].count("ATTEMPT_STARTED") == 0


def test_v8_evidence_is_strict_and_schema_valid(
    authorization_payload,
    write_authorization,
    monkeypatch,
):
    def handler(incoming: httpx.Request) -> httpx.Response:
        body = b"mutation" if incoming.headers.get("x-probe") == "1" else b"control"
        return httpx.Response(200, headers={"Content-Type": "text/plain"}, content=body)

    oracle, journal = build_oracle(
        authorization_payload,
        write_authorization,
        monkeypatch,
        handler,
    )
    experiment_plan = plan(follow_redirects=False)
    result = oracle.run(experiment_plan)
    document = v8_document(oracle, journal, experiment_plan, result)
    schema = json.loads(Path("mrma/schemas/experiment-v8.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(document)
    assert document["authorization"]["bypass"] is False
    assert document["transport"]["wire_exact"] is False
    assert document["journal"]["event_count"] > 0
    assert document["privacy"]["fingerprint_policy"]["cross_run_correlation"] == "partial"
    assert (
        "journal mutation-delta identifiers"
        in document["privacy"]["fingerprint_policy"]["run_local_hmac_fields"]
    )
    mutation_attempts = [
        event
        for event in journal.events
        if event.event_type == "ATTEMPT_STARTED"
        and event.data.get("mutation_delta_fingerprint") is not None
    ]
    assert mutation_attempts
    assert all(
        str(event.data["mutation_delta_fingerprint"]).startswith("hmac-sha256:")
        for event in mutation_attempts
    )
    assert all("mutation_delta_digest" not in event.data for event in mutation_attempts)
    assert any(
        item["code"] == "CROSS_RUN_POLICY_LINKABILITY"
        for item in document["limitations"]
    )

    invalid = deepcopy(document)
    invalid["privacy"]["fingerprint_policy"]["cross_run_correlation"] = False
    assert list(Draft202012Validator(schema).iter_errors(invalid))


def test_partial_outcomes_are_valid_v8_evidence(
    authorization_payload,
    write_authorization,
    monkeypatch,
):
    scenarios = []

    unauthorized = deepcopy(authorization_payload)
    unauthorized["rules"][0]["path_prefixes"] = ["/allowed"]
    scenarios.append((unauthorized, None, None))

    exhausted = deepcopy(authorization_payload)
    exhausted["budget"]["total_network_attempts"] = 1
    scenarios.append((exhausted, None, None))

    cancelled = Event()
    cancelled.set()
    scenarios.append((deepcopy(authorization_payload), cancelled, None))
    scenarios.append((deepcopy(authorization_payload), None, RuntimeError("offline")))

    statuses = []
    for payload, cancellation, transport_error in scenarios:
        oracle, journal = build_oracle(
            payload,
            write_authorization,
            monkeypatch,
            lambda _request: httpx.Response(200, content=b"ok"),
        )
        if transport_error is not None:
                monkeypatch.setattr(
                    oracle.transport,
                    "send_prepared",
                    lambda *_args, error=transport_error, **_kwargs: (_ for _ in ()).throw(error),
                )
        experiment_plan = plan(follow_redirects=False)
        result = oracle.run(experiment_plan, cancellation=cancellation)
        document = v8_document(oracle, journal, experiment_plan, result)

        statuses.append(result.status)
        assert result.verdict == "INCONCLUSIVE"
        assert document["run"]["complete_sampling"] is (
            result.status == "completed"
            and result.completed_rounds == result.planned_rounds
            and len(result.experiment.observations)
            == result.plan.maximum_logical_observations
        )
        assert validate_result_document(document)["schema_valid"] is True
    assert set(statuses) == {"partial", "cancelled"}


def test_all_stable_headers_use_budgeted_controls_and_reject_volatile_fields(
    authorization_payload,
    write_authorization,
    monkeypatch,
):
    counter = 0

    def handler(incoming: httpx.Request) -> httpx.Response:
        nonlocal counter
        counter += 1
        body = b"mutation" if incoming.headers.get("x-probe") == "1" else b"control"
        return httpx.Response(
            200,
            headers={
                "Content-Type": "text/plain",
                "X-Stable-Unknown": "constant",
                "X-Volatile-Unknown": str(counter),
            },
            content=body,
        )

    oracle, journal = build_oracle(
        authorization_payload,
        write_authorization,
        monkeypatch,
        handler,
    )
    result = oracle.run(plan(follow_redirects=False, response_header_scope="all-stable"))

    assert result.status == "completed"
    assert result.budget.setup_reset_attempts == 3
    assert result.budget.total_network_attempts == 21
    assert result.header_coverage.complete is True
    assert "x-stable-unknown" in result.header_coverage.promoted_fields
    assert "x-volatile-unknown" in result.header_coverage.volatile_fields
    assert "x-volatile-unknown" not in result.header_coverage.promoted_fields
    assert [event.event_type for event in journal.events].count("OBSERVATION_COMPLETED") == 21


def test_oracle_rejects_a_comparison_policy_mismatch(
    authorization_payload,
    write_authorization,
    monkeypatch,
):
    oracle, _journal = build_oracle(
        authorization_payload,
        write_authorization,
        monkeypatch,
        lambda _request: httpx.Response(200, content=b"ok"),
    )
    mismatched = plan(follow_redirects=False)
    mismatched = replace(
        mismatched,
        experiment=replace(
            mismatched.experiment,
            equivalence=EquivalenceConfig(min_similarity=0.5),
        ),
    )

    with pytest.raises(ValueError, match="comparison policy must match"):
        oracle.run(mismatched)


def test_setup_and_per_round_reset_hooks_are_authorized_budgeted_and_evidenced(
    authorization_payload,
    write_authorization,
    monkeypatch,
):
    roles: list[str] = []

    def handler(incoming: httpx.Request) -> httpx.Response:
        roles.append(incoming.url.path)
        body = b"mutation" if incoming.headers.get("x-probe") == "1" else b"control"
        return httpx.Response(200, headers={"Content-Type": "text/plain"}, content=body)

    oracle, journal = build_oracle(
        authorization_payload,
        write_authorization,
        monkeypatch,
        handler,
    )
    experiment_plan = replace(
        plan(follow_redirects=False),
        setup_hooks=(
            RawRequest("GET", "/setup", "HTTP/1.1", [], b"", original_sha256="setup"),
        ),
        reset_hooks=(
            RawRequest("GET", "/reset", "HTTP/1.1", [], b"", original_sha256="reset"),
        ),
    )
    result = oracle.run(experiment_plan)

    assert result.status == "completed"
    assert result.budget.total_network_attempts == 25
    assert result.budget.setup_reset_attempts == 7
    assert roles.count("/setup") == 1
    assert roles.count("/reset") == 6
    attempts = [event for event in journal.events if event.event_type == "ATTEMPT_STARTED"]
    assert sum(event.data["role"] == "setup" for event in attempts) == 1
    assert sum(event.data["role"] == "reset" for event in attempts) == 6


def test_plan_rejects_invalid_roles_assurance_and_semantic_inputs():
    valid = plan(follow_redirects=False)
    with pytest.raises(ValueError, match="exploration_role"):
        replace(valid, exploration_role="invalid")
    with pytest.raises(ValueError, match="confirmatory plans"):
        replace(
            valid,
            experiment=replace(valid.experiment, assurance_preset="exploratory"),
        )
    with pytest.raises(ValueError, match="request input"):
        replace(
            valid,
            baseline=replace(valid.baseline, semantic_replay_eligible=False),
        )
    with pytest.raises(ValueError, match="hook request"):
        replace(
            valid,
            setup_hooks=(
                replace(valid.baseline, semantic_replay_eligible=False),
            ),
        )


def test_balanced_plan_summary_uses_two_observations_and_no_redirect_multiplier():
    experiment_plan = plan(follow_redirects=False)
    experiment_plan = replace(
        experiment_plan,
        experiment=replace(experiment_plan.experiment, schedule_mode="balanced"),
    )
    summary = experiment_plan.summary(4)

    assert summary.observations_per_round == 2
    assert summary.maximum_logical_observations == 12
    assert summary.maximum_attempts_with_redirects == 12
    assert summary.to_dict()["plan_digest"] == summary.plan_digest


def test_plan_digest_binds_effective_request_and_decision_policy():
    base = plan(follow_redirects=False)
    same_source_mutation = replace(
        base.mutation,
        headers=[("Accept", "text/plain"), ("X-Probe", "2")],
        original_sha256=base.baseline.original_sha256,
    )
    request_changed = replace(base, mutation=same_source_mutation)
    body_base = replace(base, mutation=replace(base.mutation, body=b"a"))
    body_changed = replace(body_base, mutation=replace(base.mutation, body=b"b"))
    retry_changed = replace(base, send=replace(base.send, retries=1))
    comparison_changed = replace(
        base,
        experiment=replace(
            base.experiment,
            equivalence=replace(base.experiment.equivalence, min_similarity=0.9),
        ),
    )

    digest = base.summary(0).plan_digest
    assert request_changed.summary(0).plan_digest != digest
    assert body_changed.summary(0).plan_digest != body_base.summary(0).plan_digest
    assert retry_changed.summary(0).plan_digest != digest
    assert comparison_changed.summary(0).plan_digest != digest
    assert base.summary(0, authorization_digest="sha256:" + "1" * 64).plan_digest != digest
    assert base.summary(
        0,
        transport_policy={"adapter": "semantic-http/changed"},
    ).plan_digest != digest


def test_private_approval_digest_is_stable_across_run_redactors():
    first = plan(follow_redirects=False)
    second = replace(
        first,
        experiment=replace(first.experiment, redactor=EvidenceRedactor()),
    )
    changed = replace(
        second,
        mutation=replace(second.mutation, headers=second.mutation.headers + [("X-Other", "1")]),
    )
    privacy_changed = replace(
        second,
        experiment=replace(second.experiment, redactor=EvidenceRedactor(policy="strict")),
    )

    first_summary = first.summary(0, authorization_digest="sha256:" + "1" * 64)
    second_summary = second.summary(0, authorization_digest="sha256:" + "1" * 64)
    changed_summary = changed.summary(0, authorization_digest="sha256:" + "1" * 64)
    privacy_summary = privacy_changed.summary(0, authorization_digest="sha256:" + "1" * 64)

    assert first_summary.plan_digest != second_summary.plan_digest
    assert first_summary.approval_plan_digest == second_summary.approval_plan_digest
    assert changed_summary.approval_plan_digest != first_summary.approval_plan_digest
    assert privacy_summary.approval_plan_digest != first_summary.approval_plan_digest
    assert "approval_plan_digest" not in first_summary.to_dict()
    assert first_summary.to_private_dict()["approval_plan_digest"] == (
        first_summary.approval_plan_digest
    )


def test_result_verifier_recomputes_effective_plan_digest(
    authorization_payload,
    write_authorization,
    monkeypatch,
):
    oracle, journal = build_oracle(
        authorization_payload,
        write_authorization,
        monkeypatch,
        lambda _request: httpx.Response(200, content=b"ok"),
    )
    experiment_plan = plan(follow_redirects=False)
    result = oracle.run(experiment_plan)
    document = v8_document(oracle, journal, experiment_plan, result)
    document["plan"]["effective_plan"]["send"]["retries"] = 99

    with pytest.raises(EvidenceIntegrityError, match="PLAN_DIGEST_MISMATCH"):
        validate_result_document(document)


def test_versioned_v7_builder_rejects_new_generation(
    authorization_payload,
    write_authorization,
    monkeypatch,
):
    oracle, journal = build_oracle(
        authorization_payload,
        write_authorization,
        monkeypatch,
        lambda _request: httpx.Response(200, content=b"ok"),
    )
    experiment_plan = plan(follow_redirects=False)
    result = oracle.run(experiment_plan)
    journal.close()
    with pytest.raises(ValueError, match="v7 generation is disabled"):
        build_experiment_v7(
            result,
            plan=experiment_plan,
            authorization=oracle.authorization,
            budgets=oracle.budgets,
            journal=journal,
            run_id=uuid4().hex,
            started_at="2026-07-15T12:00:00+00:00",
            completed_at="2026-07-15T12:01:00+00:00",
            duration_ms=60000,
            transport_configuration={
                "trust_environment": False,
                "tls": {"verification": "system", "ca_fingerprint": None},
                "proxy": {
                    "mode": "none",
                    "source": "none",
                    "endpoint_fingerprint": None,
                },
            },
        )

    legacy = v8_document(oracle, journal, experiment_plan, result)
    legacy["schema_version"] = "mrma.experiment/v7"
    for field_name in (
        "authority_mode",
        "host_mutation_authorized",
        "cross_origin_header_mode",
        "query_policy_version",
        "mutation_policy_version",
    ):
        legacy["authorization"].pop(field_name)
    legacy["plan"]["schema_version"] = "mrma.plan/v1"
    legacy["plan"].pop("effective_plan")
    legacy["privacy"] = {
        "policy": result.experiment.config.redactor.policy,
        "fingerprints": "per-run keyed HMAC-SHA256",
        "cross_run_correlation": False,
    }
    assert validate_result_document(legacy)["schema_valid"] is True


def test_oracle_components_must_share_one_journal(
    authorization_payload,
    write_authorization,
    monkeypatch,
):
    oracle, _journal = build_oracle(
        authorization_payload,
        write_authorization,
        monkeypatch,
        lambda _request: httpx.Response(200),
    )
    with pytest.raises(ValueError, match="share one evidence journal"):
        ExperimentOracle(
            authorization=oracle.authorization,
            budgets=oracle.budgets,
            transport=oracle.transport,
            comparison=ComparisonPolicy(EquivalenceConfig()),
            evidence=EvidenceJournal(run_id="other"),
        )


@pytest.mark.parametrize(
    ("budget_change", "plan_change", "message"),
    [
        ({"per_attempt_timeout_ms": 500}, {}, "transport timeout"),
        ({"total_network_attempts": 1}, {}, "planned total_network_attempts"),
        ({"maximum_response_bytes": 512}, {}, "response bound"),
        ({"maximum_request_body_bytes": 0}, {"body": b"x"}, "request body"),
        ({"redirect_depth": 0}, {}, "redirect depth"),
        (
            {"mutation_risk_level": "safe"},
            {"mutation_risk_class": "non-idempotent"},
            "mutation risk",
        ),
    ],
)
def test_dry_run_rejects_plans_that_exceed_policy_capacity(
    authorization_payload,
    write_authorization,
    monkeypatch,
    budget_change,
    plan_change,
    message: str,
):
    payload = deepcopy(authorization_payload)
    payload["budget"].update(budget_change)
    oracle, _journal = build_oracle(
        payload,
        write_authorization,
        monkeypatch,
        lambda _request: httpx.Response(200),
    )
    experiment_plan = plan()
    if "body" in plan_change:
        experiment_plan = replace(
            experiment_plan,
            baseline=replace(experiment_plan.baseline, body=plan_change["body"]),
            mutation=replace(experiment_plan.mutation, body=plan_change["body"]),
        )
    if "mutation_risk_class" in plan_change:
        experiment_plan = replace(
            experiment_plan,
            mutation_risk_class=plan_change["mutation_risk_class"],
        )

    with pytest.raises(Exception, match=message):
        oracle.dry_run(experiment_plan)


def test_dry_run_authorizes_setup_and_reset_hooks(
    authorization_payload,
    write_authorization,
    monkeypatch,
):
    oracle, journal = build_oracle(
        authorization_payload,
        write_authorization,
        monkeypatch,
        lambda _request: httpx.Response(200),
    )
    experiment_plan = replace(
        plan(follow_redirects=False),
        setup_hooks=(RawRequest("GET", "/setup", "HTTP/1.1", [], b""),),
        reset_hooks=(RawRequest("GET", "/reset", "HTTP/1.1", [], b""),),
    )
    oracle.dry_run(experiment_plan)
    accepted_roles = [
        event.data["role"]
        for event in journal.events
        if event.event_type == "AUTHORIZATION_ACCEPTED"
    ]
    assert accepted_roles == ["control", "mutation", "setup", "reset"]


def test_oracle_converts_keyboard_interrupt_and_unexpected_failure_to_partial_results(
    authorization_payload,
    write_authorization,
    monkeypatch,
):
    oracle, _journal = build_oracle(
        authorization_payload,
        write_authorization,
        monkeypatch,
        lambda _request: httpx.Response(200),
    )
    monkeypatch.setattr(
        "mrma.engine.oracle.run_experiment",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(KeyboardInterrupt()),
    )
    interrupted = oracle.run(plan(follow_redirects=False))
    assert interrupted.status == "cancelled"
    assert interrupted.stop_reason == "keyboard_interrupt"

    oracle, _journal = build_oracle(
        authorization_payload,
        write_authorization,
        monkeypatch,
        lambda _request: httpx.Response(200),
    )
    monkeypatch.setattr(
        "mrma.engine.oracle.run_experiment",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("fault")),
    )
    failed = oracle.run(plan(follow_redirects=False))
    assert failed.status == "partial"
    assert failed.stop_reason == "transport_or_policy_failure"


def test_all_stable_marks_fields_missing_from_one_control_as_volatile(
    authorization_payload,
    write_authorization,
    monkeypatch,
):
    counter = 0

    def handler(incoming: httpx.Request) -> httpx.Response:
        nonlocal counter
        counter += 1
        headers = [("Content-Type", "text/plain")]
        if counter != 2:
            headers.append(("X-Optional", "stable"))
        body = b"mutation" if incoming.headers.get("x-probe") == "1" else b"control"
        return httpx.Response(200, headers=headers, content=body)

    oracle, _journal = build_oracle(
        authorization_payload, write_authorization, monkeypatch, handler
    )
    result = oracle.run(plan(follow_redirects=False, response_header_scope="all-stable"))
    assert "x-optional" in result.header_coverage.volatile_fields


def test_retry_controller_records_transport_and_status_retries(
    authorization_payload,
    write_authorization,
    monkeypatch,
):
    oracle, _journal = build_oracle(
        authorization_payload,
        write_authorization,
        monkeypatch,
        lambda _request: httpx.Response(200),
    )
    response = CapturedResponse(
        200,
        (),
        b"ok",
        2,
        "sha256:" + "0" * 64,
        True,
        True,
        False,
        (),
        "http://example.test:80",
        final_url="http://example.test/",
    )
    calls = 0

    def transport_then_success(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("transient")
        return response

    monkeypatch.setattr(oracle, "_attempt", transport_then_success)
    retry_plan = replace(
        plan(follow_redirects=False),
        send=SendPolicy(retries=1, backoff_base_s=0, backoff_cap_s=0),
    )
    outcome = oracle._send_with_retries(
        retry_plan,
        request=retry_plan.baseline,
        base_url=retry_plan.base_url,
        role="control",
        arm="control",
        round_index=1,
        sequence=1,
        redirect_depth=0,
    )
    assert outcome.succeeded
    assert outcome.attempt_trace[0].retry_reason == "transport-error"

    responses = iter((replace(response, status_code=503), response))
    monkeypatch.setattr(oracle, "_attempt", lambda *_args, **_kwargs: next(responses))
    outcome = oracle._send_with_retries(
        retry_plan,
        request=retry_plan.baseline,
        base_url=retry_plan.base_url,
        role="control",
        arm="control",
        round_index=1,
        sequence=1,
        redirect_depth=0,
    )
    assert outcome.attempt_trace[0].retry_reason == "configured-status"


def test_redirect_method_and_credential_policy_transformations():
    request = RawRequest(
        "POST",
        "/submit",
        "HTTP/1.1",
        [
            ("Host", "example.test"),
            ("Authorization", "secret"),
            ("X-API-Key", "api-secret"),
            ("X-Client-Secret", "client-secret"),
            ("Content-Type", "text/plain"),
            ("Content-Encoding", "identity"),
            ("Content-Digest", "sha-256=:AAAA:"),
            ("Content-Length", "4"),
            ("X-Test", "1"),
        ],
        b"body",
    )
    redirected, changed, credentials, retained_names, stripped_names = _redirect_request(
        request,
        "https://other.test/final",
        303,
        cross_origin=True,
        cross_origin_mode="safe-default",
        cross_origin_allow=(),
    )
    assert redirected.method == "GET"
    assert redirected.body == b""
    assert changed is True
    assert credentials == "stripped"
    assert redirected.headers == []
    assert retained_names == ()
    assert set(stripped_names) == {
        "host",
        "authorization",
        "x-api-key",
        "x-client-secret",
        "content-type",
        "content-encoding",
        "content-digest",
        "content-length",
        "x-test",
    }

    retained, changed, credentials, retained_names, stripped_names = _redirect_request(
        request,
        "https://other.test/final",
        307,
        cross_origin=True,
        cross_origin_mode="explicit",
        cross_origin_allow=(
            "authorization",
            "x-api-key",
            "x-client-secret",
            "content-type",
            "content-encoding",
            "content-digest",
            "content-length",
            "x-test",
        ),
    )
    assert retained.method == "POST"
    assert retained.body == b"body"
    assert changed is False
    assert credentials == "retained"
    assert retained_names == (
        "authorization",
        "x-api-key",
        "x-client-secret",
        "content-type",
        "content-encoding",
        "content-digest",
        "content-length",
        "x-test",
    )
    assert stripped_names == ("host",)
