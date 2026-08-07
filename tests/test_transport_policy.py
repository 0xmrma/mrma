from __future__ import annotations

from dataclasses import replace

import httpx
import pytest

from mrma.core.http_client import CapturedResponse, SendOptions
from mrma.core.raw_request import RawRequest
from mrma.evidence import EvidenceJournal
from mrma.evidence.journal import EvidenceContext
from mrma.policy.authorization import (
    ManifestAuthorizationPolicy,
    load_authorization_manifest,
    request_fingerprint,
)
from mrma.policy.budget import AttemptCost, BudgetLedger, BudgetLimits
from mrma.transport.semantic_http import (
    SemanticHttpAdapter,
    TransportPolicyError,
    estimate_semantic_request_bytes,
    origin_fingerprint,
)


def _components(
    authorization_payload: dict[str, object],
    write_authorization,
):
    manifest = load_authorization_manifest(write_authorization(authorization_payload))
    policy = ManifestAuthorizationPolicy(
        manifest,
        resolver=lambda _host, _port: ("127.0.0.1",),
    )
    request = RawRequest("GET", "/", "HTTP/1.1", [("Accept", "text/plain")], b"")
    context = policy.authorize(
        request,
        base_url="http://example.test",
        attempt_kind="control",
        risk_class="safe",
    )
    journal = EvidenceJournal(run_id="transport")
    ledger = BudgetLedger(BudgetLimits.from_mapping(manifest.budget), journal)
    evidence = EvidenceContext("transport", "a1", "control", 1)
    estimated = estimate_semantic_request_bytes(request, context.canonical_url)
    cost = AttemptCost(
        "control",
        origin_fingerprint(context.decision.canonical_origin),
        context.decision.target_fingerprint,
        len(request.body),
        estimated,
        1024,
        1000,
    )
    return request, context, journal, ledger, evidence, cost


def test_adapter_normalizes_redirect_policy_and_context_lifecycle():
    journal = EvidenceJournal(run_id="transport")
    adapter = SemanticHttpAdapter(
        SendOptions(trust_env=False, follow_redirects=True),
        journal=journal,
    )
    assert adapter.options.follow_redirects is False
    adapter.close()
    with adapter as entered:
        assert entered is adapter
    adapter.close()
    with pytest.raises(TransportPolicyError, match="TRANSPORT_NOT_ENTERED"):
        adapter.clear_observation_cookies()
    with pytest.raises(TransportPolicyError, match="TRANSPORT_NOT_ENTERED"):
        with adapter.observation_session(arm="control", round_index=1):
            pass


@pytest.mark.parametrize(
    ("variant", "code"),
    [
        ("method", "PREPARED_METHOD_MISMATCH"),
        ("target", "PREPARED_TARGET_MISMATCH"),
        ("missing-host", "PREPARED_HOST_INVALID"),
        ("malformed-host", "PREPARED_HOST_INVALID"),
        ("other-host", "PREPARED_HOST_MISMATCH"),
    ],
)
def test_prepare_revalidates_effective_httpx_request(
    authorization_payload,
    write_authorization,
    monkeypatch,
    variant: str,
    code: str,
):
    request, context, journal, _ledger, _evidence, _cost = _components(
        authorization_payload, write_authorization
    )
    adapter = SemanticHttpAdapter(SendOptions(trust_env=False), journal=journal)

    def prepared_request(*_args, **_kwargs) -> httpx.Request:
        method = "POST" if variant == "method" else "GET"
        url = "http://example.test/other" if variant == "target" else context.canonical_url
        host = "example.test"
        if variant == "malformed-host":
            host = "example.test:"
        elif variant == "other-host":
            host = "other.test"
        prepared = httpx.Request(method, url, headers={"Host": host})
        if variant == "missing-host":
            prepared.headers.pop("host")
        return prepared

    monkeypatch.setattr(adapter._transport, "prepare", prepared_request)
    with adapter, adapter.observation_session(arm="control", round_index=1):
        with pytest.raises(TransportPolicyError, match=code):
            adapter.prepare(
                request,
                authorization=context,
                arm="control",
                round_index=1,
            )


def test_transport_rejects_missing_or_mismatched_policy_contexts(
    authorization_payload,
    write_authorization,
):
    request, context, journal, ledger, evidence, cost = _components(
        authorization_payload, write_authorization
    )
    adapter = SemanticHttpAdapter(SendOptions(trust_env=False), journal=journal)
    lease = ledger.reserve(cost, evidence=evidence)
    with pytest.raises(TransportPolicyError, match="TRANSPORT_NOT_ENTERED"):
        adapter.send(
            request,
            authorization=context,
            lease=lease,
            evidence=evidence,
            arm="control",
            round_index=1,
            body_storage="full",
        )
    lease.release()

    with adapter, adapter.observation_session(arm="control", round_index=1):
        inactive = ledger.reserve(cost, evidence=evidence)
        inactive.release()
        with pytest.raises(TransportPolicyError, match="BUDGET_LEASE_REQUIRED"):
            adapter.send(
                request,
                authorization=context,
                lease=inactive,
                evidence=evidence,
                arm="control",
                round_index=1,
                body_storage="full",
            )

        lease = ledger.reserve(cost, evidence=evidence)
        with pytest.raises(TransportPolicyError, match="EVIDENCE_CONTEXT_MISMATCH"):
            adapter.send(
                request,
                authorization=context,
                lease=lease,
                evidence=replace(evidence, attempt_id="other"),
                arm="control",
                round_index=1,
                body_storage="full",
            )
        lease.release()

        other_run = EvidenceContext("other", "a2", "control", 1)
        lease = ledger.reserve(cost, evidence=other_run)
        with pytest.raises(TransportPolicyError, match="EVIDENCE_RUN_MISMATCH"):
            adapter.send(
                request,
                authorization=context,
                lease=lease,
                evidence=other_run,
                arm="control",
                round_index=1,
                body_storage="full",
            )
        lease.release()

        lease = ledger.reserve(cost, evidence=evidence)
        with pytest.raises(TransportPolicyError, match="AUTHORIZATION_REQUEST_MISMATCH"):
            adapter.send(
                replace(request, headers=[("X-Changed", "1")]),
                authorization=context,
                lease=lease,
                evidence=evidence,
                arm="control",
                round_index=1,
                body_storage="full",
            )
        lease.release()

        wrong_target = replace(cost, target_fingerprint="sha256:" + "0" * 64)
        lease = ledger.reserve(wrong_target, evidence=evidence)
        with pytest.raises(TransportPolicyError, match="LEASE_TARGET_MISMATCH"):
            adapter.send(
                request,
                authorization=context,
                lease=lease,
                evidence=evidence,
                arm="control",
                round_index=1,
                body_storage="full",
            )
        lease.release()

        wrong_origin = replace(cost, origin_fingerprint="sha256:" + "0" * 64)
        lease = ledger.reserve(wrong_origin, evidence=evidence)
        with pytest.raises(TransportPolicyError, match="LEASE_ORIGIN_MISMATCH"):
            adapter.send(
                request,
                authorization=context,
                lease=lease,
                evidence=evidence,
                arm="control",
                round_index=1,
                body_storage="full",
            )
        lease.release()

        body_request = replace(request, body=b"x")
        body_context = replace(
            context,
            request_fingerprint=request_fingerprint(body_request, context.canonical_url),
        )
        lease = ledger.reserve(cost, evidence=evidence)
        with pytest.raises(TransportPolicyError, match="request body exceeds"):
            adapter.send(
                body_request,
                authorization=body_context,
                lease=lease,
                evidence=evidence,
                arm="control",
                round_index=1,
                body_storage="full",
            )
        lease.release()

        undersized = replace(cost, request_bytes=0)
        lease = ledger.reserve(undersized, evidence=evidence)
        with pytest.raises(TransportPolicyError, match="prepared request representation exceeds"):
            adapter.send(
                request,
                authorization=context,
                lease=lease,
                evidence=evidence,
                arm="control",
                round_index=1,
                body_storage="full",
            )
        lease.release()


def test_transport_error_is_charged_and_evidenced(
    authorization_payload,
    write_authorization,
    monkeypatch,
):
    request, context, journal, ledger, evidence, cost = _components(
        authorization_payload, write_authorization
    )
    adapter = SemanticHttpAdapter(SendOptions(trust_env=False), journal=journal)
    lease = ledger.reserve(cost, evidence=evidence)
    monkeypatch.setattr(
        adapter._transport,
        "capture_prepared",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("failed")),
    )
    with adapter, adapter.observation_session(arm="control", round_index=1):
        with pytest.raises(RuntimeError, match="failed"):
            adapter.send(
                request,
                authorization=context,
                lease=lease,
                evidence=evidence,
                arm="setup",
                round_index=1,
                body_storage="full",
            )
    assert lease.active is False
    assert ledger.snapshot().total_network_attempts == 1
    assert [event.event_type for event in journal.events][-1] == "ATTEMPT_COMPLETED"


def test_mutation_arm_requires_delta_bound_authorization(
    authorization_payload,
    write_authorization,
):
    request, context, journal, _ledger, _evidence, _cost = _components(
        authorization_payload, write_authorization
    )
    adapter = SemanticHttpAdapter(SendOptions(trust_env=False), journal=journal)
    with adapter, adapter.observation_session(arm="mutation", round_index=1):
        with pytest.raises(TransportPolicyError, match="MUTATION_AUTHORIZATION_REQUIRED"):
            adapter.prepare(
                request,
                authorization=context,
                arm="mutation",
                round_index=1,
            )


def test_prepared_mutation_is_bound_to_delta_digest(
    authorization_payload,
    write_authorization,
):
    manifest = load_authorization_manifest(write_authorization(authorization_payload))
    policy = ManifestAuthorizationPolicy(
        manifest,
        resolver=lambda _host, _port: ("127.0.0.1",),
    )
    baseline = RawRequest("GET", "/", "HTTP/1.1", [], b"")
    mutation = replace(baseline, headers=[("X-Probe", "1")])
    context = policy.authorize_mutation(
        baseline,
        mutation,
        mutation,
        base_url="http://example.test",
        attempt_kind="mutation",
        mutation_family="header",
        risk_class="safe",
    )
    journal = EvidenceJournal(run_id="mutation-transport")
    ledger = BudgetLedger(BudgetLimits.from_mapping(manifest.budget), journal)
    evidence = EvidenceContext("mutation-transport", "a1", "mutation", 1)
    adapter = SemanticHttpAdapter(SendOptions(trust_env=False), journal=journal)

    with adapter, adapter.observation_session(arm="mutation", round_index=1):
        prepared = adapter.prepare(
            mutation,
            authorization=context,
            arm="mutation",
            round_index=1,
        )
        cost = AttemptCost(
            "mutation",
            origin_fingerprint(context.decision.canonical_origin),
            context.decision.target_fingerprint,
            len(mutation.body),
            prepared.represented_bytes,
            1024,
            1000,
        )
        lease = ledger.reserve(cost, evidence=evidence)
        with pytest.raises(TransportPolicyError, match="MUTATION_AUTHORIZATION_MISMATCH"):
            adapter.send_prepared(
                replace(prepared, mutation_delta_digest="sha256:" + "0" * 64),
                authorization=context,
                lease=lease,
                evidence=evidence,
                body_storage="full",
            )
        lease.release()


def test_prepared_request_accounts_for_cookie_jar_fields(
    authorization_payload,
    write_authorization,
):
    request, context, journal, _ledger, _evidence, _cost = _components(
        authorization_payload, write_authorization
    )
    adapter = SemanticHttpAdapter(SendOptions(trust_env=False), journal=journal)
    with adapter, adapter.observation_session(arm="control", round_index=1):
        active = adapter._transport._active_observation
        assert active is not None
        active[0].cookies.set("session", "x" * 4096, domain="example.test", path="/")
        prepared = adapter.prepare(
            request,
            authorization=context,
            arm="control",
            round_index=1,
        )

    assert prepared.represented_bytes > estimate_semantic_request_bytes(
        request,
        context.canonical_url,
    )
    assert any(name.lower() == b"cookie" for name, _value in prepared.request.headers.raw)


def test_response_budget_charges_headers_and_body(
    authorization_payload,
    write_authorization,
    monkeypatch,
):
    request, context, journal, ledger, evidence, cost = _components(
        authorization_payload, write_authorization
    )
    response = CapturedResponse(
        status_code=200,
        headers=(("content-type", "text/plain"),),
        content=b"ok",
        body_length=2,
        body_sha256="0" * 64,
        body_digest_complete=True,
        body_retained_complete=True,
        response_limit_exceeded=False,
        redirect_chain=(),
        final_origin="http://example.test:80",
        represented_bytes=300,
        response_head_bytes=298,
    )
    adapter = SemanticHttpAdapter(SendOptions(trust_env=False), journal=journal)
    monkeypatch.setattr(adapter._transport, "capture_prepared", lambda *_args, **_kwargs: response)

    with adapter, adapter.observation_session(arm="control", round_index=1):
        lease = ledger.reserve(cost, evidence=evidence)
        adapter.send(
            request,
            authorization=context,
            lease=lease,
            evidence=evidence,
            arm="control",
            round_index=1,
            body_storage="full",
        )

    assert ledger.snapshot().bytes_received == 300
    completed = [event for event in journal.events if event.event_type == "ATTEMPT_COMPLETED"][-1]
    assert completed.data["response_representation_bytes_charged"] == 300
    assert completed.data["body_bytes_charged"] == 2


def test_response_head_exhaustion_charges_no_body_bytes(
    authorization_payload,
    write_authorization,
    monkeypatch,
):
    request, context, journal, ledger, evidence, cost = _components(
        authorization_payload, write_authorization
    )
    response = CapturedResponse(
        status_code=431,
        headers=(),
        content=b"",
        body_length=1,
        body_sha256="0" * 64,
        body_digest_complete=False,
        body_retained_complete=False,
        response_limit_exceeded=True,
        redirect_chain=(),
        final_origin="http://example.test:80",
        represented_bytes=cost.response_bytes + 100,
        response_head_bytes=cost.response_bytes + 100,
    )
    adapter = SemanticHttpAdapter(SendOptions(trust_env=False), journal=journal)
    monkeypatch.setattr(adapter._transport, "capture_prepared", lambda *_args, **_kwargs: response)

    with adapter, adapter.observation_session(arm="control", round_index=1):
        lease = ledger.reserve(cost, evidence=evidence)
        adapter.send(
            request,
            authorization=context,
            lease=lease,
            evidence=evidence,
            arm="control",
            round_index=1,
            body_storage="full",
        )

    assert ledger.snapshot().bytes_received == cost.response_bytes
    completed = [event for event in journal.events if event.event_type == "ATTEMPT_COMPLETED"][-1]
    assert completed.data["outcome"] == "policy-abort"
    assert completed.data["body_bytes_charged"] == 0
