from __future__ import annotations

from copy import deepcopy

import httpx
import pytest

from mrma.core.http_client import SemanticHttpTransport, SendOptions
from mrma.core.privacy import EvidenceRedactor
from mrma.core.raw_request import RawRequest
from mrma.evidence import EvidenceJournal
from mrma.policy.authorization import (
    AuthorizationError,
    ManifestAuthorizationPolicy,
    load_authorization_manifest,
)
from mrma.policy.budget import BudgetLedger, BudgetLimits
from mrma.workflows.legacy import LegacyAuthorizedDispatcher


def _v2_manifest(payload: dict[str, object]) -> dict[str, object]:
    upgraded = deepcopy(payload)
    upgraded["schema_version"] = "mrma.authorization/v2"
    for rule in upgraded["rules"]:
        rule["query_policy"] = {
            "mode": "allow-any",
            "allowed_keys": [],
            "required_keys": [],
            "forbidden_keys": [],
            "maximum_query_bytes": 4096,
        }
    upgraded["authority"] = {
        "mode": "match-target",
        "allowed_host_fields": [],
        "allow_host_mutation": False,
        "allow_duplicate_host": False,
        "sni_policy": "match-target",
        "proxy_connect_authority_policy": "match-target",
    }
    upgraded["redirects"] = {
        "mode": "authorized-targets",
        "maximum_depth": 4,
        "cross_origin_headers": {"mode": "safe-default", "allow": []},
    }
    upgraded["mutation_policy"] = {
        "headers": {
            "allow_names": ["X-Approved-Test"],
            "deny_names": ["X-Forbidden"],
            "operations": ["add"],
            "maximum_value_bytes": 8,
        }
    }
    return upgraded


def _dispatcher(payload, write_authorization, monkeypatch, baseline, observed):
    manifest = load_authorization_manifest(write_authorization(payload))
    policy = ManifestAuthorizationPolicy(
        manifest,
        resolver=lambda _host, _port: ("127.0.0.1",),
    )
    journal = EvidenceJournal(run_id="legacy-policy-test")
    ledger = BudgetLedger(BudgetLimits.from_mapping(manifest.budget), journal)

    def handler(request: httpx.Request) -> httpx.Response:
        observed.append(request)
        return httpx.Response(200, content=b"ok")

    monkeypatch.setattr(
        SemanticHttpTransport,
        "_new_client",
        lambda _self: httpx.Client(transport=httpx.MockTransport(handler)),
    )
    return (
        LegacyAuthorizedDispatcher(
            baseline=baseline,
            authorization=policy,
            budgets=ledger,
            evidence=journal,
            redactor=EvidenceRedactor(policy="standard"),
        ),
        journal,
    )


def test_legacy_dispatcher_binds_allowed_forbidden_and_oversized_headers(
    authorization_payload,
    write_authorization,
    monkeypatch,
):
    baseline = RawRequest("GET", "/allowed", "HTTP/1.1", [("Accept", "text/plain")], b"")
    observed: list[httpx.Request] = []
    dispatcher, journal = _dispatcher(
        _v2_manifest(authorization_payload),
        write_authorization,
        monkeypatch,
        baseline,
        observed,
    )
    options = SendOptions(trust_env=False)
    try:
        dispatcher(baseline, "http://example.test", options)
        allowed = RawRequest(
            "GET",
            "/allowed",
            "HTTP/1.1",
            [("Accept", "text/plain"), ("X-Approved-Test", "yes")],
            b"",
        )
        dispatcher(allowed, "http://example.test", options)
        attempts_before = len(
            [event for event in journal.events if event.event_type == "ATTEMPT_STARTED"]
        )

        forbidden = RawRequest(
            "GET",
            "/allowed",
            "HTTP/1.1",
            [("Accept", "text/plain"), ("X-Forbidden", "1")],
            b"",
        )
        oversized = RawRequest(
            "GET",
            "/allowed",
            "HTTP/1.1",
            [("Accept", "text/plain"), ("X-Approved-Test", "123456789")],
            b"",
        )
        with pytest.raises(AuthorizationError, match="HEADER_MUTATION_NOT_AUTHORIZED"):
            dispatcher(forbidden, "http://example.test", options)
        with pytest.raises(AuthorizationError, match="HEADER_MUTATION_VALUE_TOO_LARGE"):
            dispatcher(oversized, "http://example.test", options)
    finally:
        dispatcher.close()

    assert len(observed) == 2
    assert len([event for event in journal.events if event.event_type == "ATTEMPT_STARTED"]) == (
        attempts_before
    )


@pytest.mark.parametrize(
    "headers",
    [
        [("Accept", "text/plain")],
        [("Accept", "text/plain"), ("X-Approved-Test", "new")],
    ],
)
def test_legacy_dispatcher_rejects_disallowed_remove_and_replace_without_attempt(
    headers,
    authorization_payload,
    write_authorization,
    monkeypatch,
):
    baseline = RawRequest(
        "GET",
        "/allowed",
        "HTTP/1.1",
        [("Accept", "text/plain"), ("X-Approved-Test", "old")],
        b"",
    )
    observed: list[httpx.Request] = []
    dispatcher, journal = _dispatcher(
        _v2_manifest(authorization_payload),
        write_authorization,
        monkeypatch,
        baseline,
        observed,
    )
    try:
        with pytest.raises(AuthorizationError, match="HEADER_MUTATION_OPERATION_NOT_AUTHORIZED"):
            dispatcher(
                RawRequest("GET", "/allowed", "HTTP/1.1", headers, b""),
                "http://example.test",
                SendOptions(trust_env=False),
            )
    finally:
        dispatcher.close()

    assert observed == []
    assert not any(event.event_type == "ATTEMPT_STARTED" for event in journal.events)
