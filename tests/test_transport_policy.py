from __future__ import annotations

from dataclasses import replace

import pytest

from mrma.core.http_client import SendOptions
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

    with adapter:
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
        with pytest.raises(TransportPolicyError, match="semantic request estimate exceeds"):
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
        "capture",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("failed")),
    )
    with adapter, pytest.raises(RuntimeError, match="failed"):
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
