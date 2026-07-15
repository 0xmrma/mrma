from __future__ import annotations

import json
from collections.abc import Callable
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from mrma.core.raw_request import RawRequest
from mrma.policy.authorization import (
    AuthorizationError,
    ManifestAuthorizationPolicy,
    load_authorization_manifest,
)


def request(method: str = "GET", path: str = "/allowed", body: bytes = b"") -> RawRequest:
    headers = [("Idempotency-Key", "test-key")] if method == "POST" else []
    return RawRequest(method, path, "HTTP/1.1", headers, body)


def policy(
    payload: dict[str, object],
    write_authorization: Callable[[dict[str, object]], Path],
    *,
    addresses: tuple[str, ...] = ("127.0.0.1",),
) -> ManifestAuthorizationPolicy:
    manifest = load_authorization_manifest(write_authorization(payload))
    return ManifestAuthorizationPolicy(manifest, resolver=lambda _host, _port: addresses)


def test_manifest_authorizes_exact_target_and_explicit_private_range(
    authorization_payload,
    write_authorization,
):
    context = policy(authorization_payload, write_authorization).authorize(
        request(),
        base_url="http://example.test",
        attempt_kind="control",
        risk_class="safe",
    )

    assert context.decision.accepted is True
    assert context.resolved_addresses == ("127.0.0.1",)
    assert context.decision.target_fingerprint.startswith("sha256:")
    assert "example.test" not in str(context.decision)


def test_every_a_and_aaaa_answer_must_be_authorized(authorization_payload, write_authorization):
    guarded = policy(
        authorization_payload,
        write_authorization,
        addresses=("127.0.0.1", "203.0.113.9"),
    )

    with pytest.raises(AuthorizationError, match="RESOLVED_ADDRESS_NOT_AUTHORIZED"):
        guarded.authorize(
            request(),
            base_url="http://example.test",
            attempt_kind="control",
            risk_class="safe",
        )


def test_immediate_dns_revalidation_rejects_unauthorized_change(
    authorization_payload,
    write_authorization,
):
    answers = iter((("127.0.0.1",), ("203.0.113.9",)))
    manifest = load_authorization_manifest(write_authorization(authorization_payload))
    guarded = ManifestAuthorizationPolicy(
        manifest,
        resolver=lambda _host, _port: next(answers),
    )
    context = guarded.authorize(
        request(),
        base_url="http://example.test",
        attempt_kind="control",
        risk_class="safe",
    )

    with pytest.raises(AuthorizationError, match="RESOLVED_ADDRESS_NOT_AUTHORIZED"):
        guarded.revalidate(context)


def test_immediate_dns_revalidation_records_authorized_answer_change(
    authorization_payload,
    write_authorization,
):
    answers = iter((("127.0.0.1",), ("127.0.0.2",)))
    manifest = load_authorization_manifest(write_authorization(authorization_payload))
    guarded = ManifestAuthorizationPolicy(
        manifest,
        resolver=lambda _host, _port: next(answers),
    )
    context = guarded.authorize(
        request(),
        base_url="http://example.test",
        attempt_kind="control",
        risk_class="safe",
    )
    revalidated = guarded.revalidate(context)

    assert revalidated.resolved_addresses == ("127.0.0.2",)
    assert revalidated.decision.code == "AUTHORIZED_DNS_CHANGED"
    assert (
        revalidated.decision.address_set_fingerprint
        != context.decision.address_set_fingerprint
    )


def test_path_scope_is_segment_bounded(authorization_payload, write_authorization):
    payload = deepcopy(authorization_payload)
    payload["rules"][0]["path_prefixes"] = ["/admin"]
    guarded = policy(payload, write_authorization)

    guarded.authorize(
        request(path="/admin/users"),
        base_url="http://example.test",
        attempt_kind="control",
        risk_class="safe",
    )
    with pytest.raises(AuthorizationError, match="TARGET_NOT_AUTHORIZED"):
        guarded.authorize(
            request(path="/administrator"),
            base_url="http://example.test",
            attempt_kind="control",
            risk_class="safe",
        )


def test_expiration_userinfo_and_proxy_are_rejected(authorization_payload, write_authorization):
    expired = deepcopy(authorization_payload)
    now = datetime.now(timezone.utc)
    expired["issued_at"] = (now - timedelta(hours=2)).isoformat()
    expired["expires_at"] = (now - timedelta(hours=1)).isoformat()
    with pytest.raises(AuthorizationError, match="AUTHORIZATION_EXPIRED"):
        policy(expired, write_authorization).authorize(
            request(),
            base_url="http://example.test",
            attempt_kind="control",
            risk_class="safe",
        )

    guarded = policy(authorization_payload, write_authorization)
    with pytest.raises(AuthorizationError, match="URL_USERINFO_REJECTED"):
        guarded.authorize(
            request(path="http://user:pass@example.test/allowed"),
            base_url="http://example.test",
            attempt_kind="control",
            risk_class="safe",
        )
    with pytest.raises(AuthorizationError, match="PROXY_NOT_AUTHORIZED"):
        guarded.authorize(
            request(),
            base_url="http://example.test",
            attempt_kind="control",
            risk_class="safe",
            proxy_url="http://127.0.0.1:8080",
        )


def test_expiration_boundary_is_exclusive(authorization_payload, write_authorization):
    payload = deepcopy(authorization_payload)
    boundary = datetime.now(timezone.utc).replace(microsecond=0)
    payload["issued_at"] = (boundary - timedelta(hours=1)).isoformat()
    payload["expires_at"] = boundary.isoformat()
    manifest = load_authorization_manifest(write_authorization(payload))
    guarded = ManifestAuthorizationPolicy(
        manifest,
        resolver=lambda _host, _port: ("127.0.0.1",),
        now=lambda: boundary,
    )

    with pytest.raises(AuthorizationError, match="AUTHORIZATION_EXPIRED"):
        guarded.authorize(
            request(),
            base_url="http://example.test",
            attempt_kind="control",
            risk_class="safe",
        )


def test_repeated_post_requires_key_and_obeys_manifest_limit(
    authorization_payload,
    write_authorization,
):
    guarded = policy(authorization_payload, write_authorization)
    without_key = RawRequest("POST", "/allowed", "HTTP/1.1", [], b"x")
    with pytest.raises(AuthorizationError, match="IDEMPOTENCY_KEY_REQUIRED"):
        guarded.authorize(
            without_key,
            base_url="http://example.test",
            attempt_kind="mutation",
            mutation_family="header",
            risk_class="non-idempotent",
        )

    for _ in range(4):
        guarded.authorize(
            request("POST", body=b"x"),
            base_url="http://example.test",
            attempt_kind="mutation",
            mutation_family="header",
            risk_class="non-idempotent",
        )
    with pytest.raises(AuthorizationError, match="METHOD_REPETITION_EXHAUSTED"):
        guarded.authorize(
            request("POST", body=b"x"),
            base_url="http://example.test",
            attempt_kind="mutation",
            mutation_family="header",
            risk_class="non-idempotent",
        )


def test_authorized_method_tokens_are_case_sensitive(
    authorization_payload,
    write_authorization,
):
    payload = deepcopy(authorization_payload)
    payload["mutation_risk_classes"].append("unknown-extension")
    guarded = policy(payload, write_authorization)
    with pytest.raises(AuthorizationError, match="TARGET_NOT_AUTHORIZED"):
        guarded.authorize(
            RawRequest("get", "/allowed", "HTTP/1.1", [], b""),
            base_url="http://example.test",
            attempt_kind="control",
            risk_class="safe",
        )


def test_manifest_is_strict_and_supplied_digest_must_match(
    authorization_payload,
    write_authorization,
):
    unknown = deepcopy(authorization_payload)
    unknown["secret"] = "not-allowed"
    with pytest.raises(AuthorizationError, match="UNKNOWN_MANIFEST_FIELD"):
        load_authorization_manifest(write_authorization(unknown))

    bad_digest = deepcopy(authorization_payload)
    bad_digest["authorization_digest"] = "sha256:" + "0" * 64
    with pytest.raises(AuthorizationError, match="AUTHORIZATION_DIGEST_MISMATCH"):
        load_authorization_manifest(write_authorization(bad_digest))


def test_authorization_schema_accepts_fixture_and_rejects_unknown_fields(
    authorization_payload,
):
    schema = json.loads(Path("mrma/schemas/authorization-v1.schema.json").read_text())
    validator = Draft202012Validator(schema)

    validator.validate(authorization_payload)
    invalid = deepcopy(authorization_payload)
    invalid["rules"][0]["unexpected"] = True
    assert list(validator.iter_errors(invalid))


def test_attempt_kind_and_disposable_hook_policy_are_explicit(
    authorization_payload,
    write_authorization,
):
    missing_kind = deepcopy(authorization_payload)
    missing_kind["rules"][0]["attempt_kinds"].remove("reset")
    with pytest.raises(AuthorizationError, match="TARGET_NOT_AUTHORIZED"):
        policy(missing_kind, write_authorization).authorize(
            request(),
            base_url="http://example.test",
            attempt_kind="reset",
            risk_class="safe",
        )

    not_disposable = deepcopy(authorization_payload)
    not_disposable["rules"][0]["disposable_environment"] = False
    with pytest.raises(AuthorizationError, match="HOOK_ENVIRONMENT_NOT_DISPOSABLE"):
        policy(not_disposable, write_authorization).authorize(
            request(),
            base_url="http://example.test",
            attempt_kind="setup",
            risk_class="safe",
        )


def test_explicit_proxy_name_port_and_every_address_are_authorized(
    authorization_payload,
    write_authorization,
):
    payload = deepcopy(authorization_payload)
    payload["proxy"] = {
        "mode": "allow-explicit",
        "hosts": ["proxy.test"],
        "ports": [8080],
        "cidrs": ["192.0.2.0/24"],
    }
    manifest = load_authorization_manifest(write_authorization(payload))
    guarded = ManifestAuthorizationPolicy(
        manifest,
        resolver=lambda host, _port: (
            ("192.0.2.10", "203.0.113.10")
            if host == "proxy.test"
            else ("127.0.0.1",)
        ),
    )

    with pytest.raises(AuthorizationError, match="PROXY_ADDRESS_NOT_AUTHORIZED"):
        guarded.authorize(
            request(),
            base_url="http://example.test",
            attempt_kind="control",
            risk_class="safe",
            proxy_url="http://proxy.test:8080",
        )
