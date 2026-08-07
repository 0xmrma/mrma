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
    AuthorizedMutationContext,
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


def authorization_v2(payload: dict[str, object]) -> dict[str, object]:
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
            "allow_names": ["X-Probe"],
            "deny_names": ["Authorization", "Cookie", "Proxy-Authorization", "Host"],
            "operations": ["add", "replace", "remove"],
            "maximum_value_bytes": 256,
        }
    }
    return upgraded


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


def test_authorization_v2_binds_host_authority_and_rejects_duplicates(
    authorization_payload,
    write_authorization,
):
    payload = authorization_v2(authorization_payload)
    guarded = policy(payload, write_authorization)

    unauthorized_host = request()
    unauthorized_host.headers.append(("Host", "internal-admin.test"))
    with pytest.raises(AuthorizationError, match="HOST_AUTHORITY_NOT_AUTHORIZED"):
        guarded.authorize(
            unauthorized_host,
            base_url="http://example.test",
            attempt_kind="control",
            risk_class="safe",
        )

    duplicate_host = request()
    duplicate_host.headers.extend([("Host", "example.test"), ("host", "example.test")])
    with pytest.raises(AuthorizationError, match="DUPLICATE_HOST_REJECTED"):
        guarded.authorize(
            duplicate_host,
            base_url="http://example.test",
            attempt_kind="control",
            risk_class="safe",
        )

    for value in (
        "internal admin.test",
        "example.test:",
        "example\\evil.test",
        "exa%6dple.test",
        "example.test\x00",
    ):
        malformed_host = request()
        malformed_host.headers.append(("Host", value))
        with pytest.raises(AuthorizationError, match="INVALID_HOST_AUTHORITY"):
            guarded.authorize(
                malformed_host,
                base_url="http://example.test",
                attempt_kind="control",
                risk_class="safe",
            )


def test_authorization_v2_accepts_only_explicit_host_mutation(
    authorization_payload,
    write_authorization,
):
    payload = authorization_v2(authorization_payload)
    payload["authority"] = {
        "mode": "explicit",
        "allowed_host_fields": ["example.test", "alternate-vhost.test"],
        "allow_host_mutation": True,
        "allow_duplicate_host": False,
        "sni_policy": "match-target",
        "proxy_connect_authority_policy": "match-target",
    }
    payload["mutation_policy"]["headers"] = {
        "allow_names": ["Host"],
        "deny_names": [],
        "operations": ["add"],
        "maximum_value_bytes": 256,
    }
    guarded = policy(payload, write_authorization)
    baseline = request()
    mutation = request()
    mutation.headers.append(("Host", "alternate-vhost.test"))

    guarded.validate_mutation(baseline, mutation, mutation_family="header")
    context = guarded.authorize(
        mutation,
        base_url="http://example.test",
        attempt_kind="mutation",
        mutation_family="header",
        risk_class="safe",
    )

    assert context.effective_host_authority == "alternate-vhost.test"
    assert context.decision.host_authority_fingerprint.startswith("sha256:")
    assert context.decision.sni_authority_fingerprint is None


def test_authorization_v2_rejects_canonically_duplicate_authorities(
    authorization_payload,
    write_authorization,
):
    payload = authorization_v2(authorization_payload)
    payload["authority"] = {
        "mode": "explicit",
        "allowed_host_fields": ["EXAMPLE.test", "example.test."],
        "allow_host_mutation": True,
        "allow_duplicate_host": False,
        "sni_policy": "match-target",
        "proxy_connect_authority_policy": "match-target",
    }

    with pytest.raises(AuthorizationError, match="canonically duplicate"):
        policy(payload, write_authorization)


def test_authorization_v2_rejects_invalid_policy_combinations(
    authorization_payload,
    write_authorization,
):
    invalid_cases: list[tuple[dict[str, object], str]] = []

    def add(mutator, code: str) -> None:
        payload = authorization_v2(authorization_payload)
        mutator(payload)
        invalid_cases.append((payload, code))

    add(lambda payload: payload.__setitem__("authority", None), "INVALID_AUTHORITY_POLICY")
    add(
        lambda payload: payload["authority"].__setitem__("mode", "unknown"),
        "INVALID_AUTHORITY_POLICY",
    )
    add(
        lambda payload: payload["authority"].__setitem__("allow_duplicate_host", True),
        "INVALID_AUTHORITY_POLICY",
    )
    add(
        lambda payload: payload["authority"].__setitem__("allow_host_mutation", "yes"),
        "INVALID_AUTHORITY_POLICY",
    )
    add(
        lambda payload: payload["authority"].__setitem__("sni_policy", "explicit"),
        "INVALID_AUTHORITY_POLICY",
    )
    add(
        lambda payload: payload["authority"].__setitem__(
            "proxy_connect_authority_policy", "explicit"
        ),
        "INVALID_AUTHORITY_POLICY",
    )
    add(
        lambda payload: payload["redirects"].__setitem__("cross_origin_headers", None),
        "INVALID_REDIRECT_POLICY",
    )
    add(
        lambda payload: payload["redirects"]["cross_origin_headers"].__setitem__(
            "mode", "unknown"
        ),
        "INVALID_REDIRECT_POLICY",
    )
    add(
        lambda payload: payload["redirects"]["cross_origin_headers"].__setitem__(
            "allow", ["X-Trace"]
        ),
        "INVALID_REDIRECT_POLICY",
    )
    add(lambda payload: payload.__setitem__("mutation_policy", None), "INVALID_MUTATION_POLICY")
    add(
        lambda payload: payload["mutation_policy"].__setitem__("headers", None),
        "INVALID_MUTATION_POLICY",
    )
    add(
        lambda payload: payload["mutation_policy"]["headers"].__setitem__(
            "deny_names", ["X-Probe"]
        ),
        "INVALID_MUTATION_POLICY",
    )
    add(
        lambda payload: payload["mutation_policy"]["headers"].__setitem__(
            "operations", ["copy"]
        ),
        "INVALID_MUTATION_POLICY",
    )
    add(
        lambda payload: payload["mutation_policy"]["headers"].__setitem__(
            "maximum_value_bytes", -1
        ),
        "INVALID_MUTATION_POLICY",
    )

    for payload, code in invalid_cases:
        with pytest.raises(AuthorizationError, match=code):
            policy(payload, write_authorization)


def test_authorization_v2_rejects_invalid_query_policy_combinations(
    authorization_payload,
    write_authorization,
):
    invalid_policies = [
        None,
        {
            "mode": "unknown",
            "allowed_keys": [],
            "required_keys": [],
            "forbidden_keys": [],
            "maximum_query_bytes": 10,
        },
        {
            "mode": "allow-any",
            "allowed_keys": [],
            "required_keys": [],
            "forbidden_keys": [],
            "maximum_query_bytes": -1,
        },
        {
            "mode": "explicit",
            "allowed_keys": ["page"],
            "required_keys": [],
            "forbidden_keys": ["page"],
            "maximum_query_bytes": 10,
        },
        {
            "mode": "allow-any",
            "allowed_keys": ["page"],
            "required_keys": [],
            "forbidden_keys": [],
            "maximum_query_bytes": 10,
        },
        {
            "mode": "deny",
            "allowed_keys": [],
            "required_keys": [],
            "forbidden_keys": ["token"],
            "maximum_query_bytes": 10,
        },
        {
            "mode": "explicit",
            "allowed_keys": ["page"],
            "required_keys": ["lang"],
            "forbidden_keys": [],
            "maximum_query_bytes": 10,
        },
    ]
    for query_policy in invalid_policies:
        payload = authorization_v2(authorization_payload)
        payload["rules"][0]["query_policy"] = query_policy
        with pytest.raises(AuthorizationError, match="INVALID_QUERY_POLICY"):
            policy(payload, write_authorization)


def test_authorization_v2_enforces_query_and_header_mutation_scope(
    authorization_payload,
    write_authorization,
):
    payload = authorization_v2(authorization_payload)
    payload["rules"][0]["query_policy"] = {
        "mode": "explicit",
        "allowed_keys": ["page", "lang"],
        "required_keys": ["page"],
        "forbidden_keys": ["token"],
        "maximum_query_bytes": 64,
    }
    guarded = policy(payload, write_authorization)
    guarded.authorize(
        request(path="/allowed?page=1&lang=en"),
        base_url="http://example.test",
        attempt_kind="control",
        risk_class="safe",
    )
    with pytest.raises(AuthorizationError, match="TARGET_NOT_AUTHORIZED"):
        guarded.authorize(
            request(path="/allowed?page=1&token=secret"),
            base_url="http://example.test",
            attempt_kind="control",
            risk_class="safe",
        )

    baseline = request()
    forbidden = request()
    forbidden.headers.append(("Authorization", "secret"))
    with pytest.raises(AuthorizationError, match="HEADER_MUTATION_NOT_AUTHORIZED"):
        guarded.validate_mutation(baseline, forbidden, mutation_family="header")

    non_octet = request()
    non_octet.headers.append(("X-Probe", "snowman-\u2603"))
    with pytest.raises(AuthorizationError, match="INVALID_HEADER_VALUE"):
        guarded.validate_mutation(baseline, non_octet, mutation_family="header")

    oversized = request()
    oversized.headers.append(("X-Probe", "x" * 257))
    with pytest.raises(AuthorizationError, match="HEADER_MUTATION_VALUE_TOO_LARGE"):
        guarded.validate_mutation(baseline, oversized, mutation_family="header")


@pytest.mark.parametrize(
    "path",
    [
        "/allowed%2F..%2Fadmin",
        "/allowed/%252e%252e%252fadmin",
        "/allowed\\..\\admin",
        "/allowed?%74oken=secret",
        "/allowed?token=%2526page%253D1",
        "/allowed?token=x%3Badmin=true",
        "/allowed?token=%00admin",
        "/allowed?token=%E2%88%95admin",
        "/allowed\u2215admin",
    ],
)
def test_authorization_v2_rejects_ambiguous_target_encodings(
    authorization_payload,
    write_authorization,
    path: str,
):
    guarded = policy(authorization_v2(authorization_payload), write_authorization)
    with pytest.raises(
        AuthorizationError,
        match="AMBIGUOUS_TARGET_ENCODING|AMBIGUOUS_QUERY_KEY",
    ):
        guarded.authorize(
            request(path=path),
            base_url="http://example.test",
            attempt_kind="control",
            risk_class="safe",
        )


def test_authorization_requires_explicit_ascii_host_labels(
    authorization_payload,
    write_authorization,
):
    guarded = policy(authorization_v2(authorization_payload), write_authorization)
    with pytest.raises(AuthorizationError, match="NON_ASCII_HOST_REJECTED"):
        guarded.authorize(
            request(path="http://fa\u00df.de/allowed"),
            base_url="http://example.test",
            attempt_kind="control",
            risk_class="safe",
        )


def test_header_mutation_authorization_accounts_for_duplicate_operations(
    authorization_payload,
    write_authorization,
):
    payload = authorization_v2(authorization_payload)
    guarded = policy(payload, write_authorization)
    baseline = request()
    baseline.headers.append(("X-Probe", "a"))
    mutation = request()
    mutation.headers.extend([("X-Probe", "b"), ("X-Probe", "c")])

    validation = guarded.validate_mutation(baseline, mutation, mutation_family="header")
    assert validation.required_operations == ("x-probe:add", "x-probe:replace")
    context = guarded.authorize_mutation(
        baseline,
        mutation,
        mutation,
        base_url="http://example.test",
        attempt_kind="mutation",
        mutation_family="header",
        risk_class="safe",
    )
    assert isinstance(context, AuthorizedMutationContext)
    assert context.mutation == validation

    add_only = authorization_v2(authorization_payload)
    add_only["mutation_policy"]["headers"]["operations"] = ["add"]
    with pytest.raises(AuthorizationError, match="replace is outside"):
        policy(add_only, write_authorization).validate_mutation(
            baseline,
            mutation,
            mutation_family="header",
        )

    replace_only = authorization_v2(authorization_payload)
    replace_only["mutation_policy"]["headers"]["operations"] = ["replace"]
    with pytest.raises(AuthorizationError, match="add is outside"):
        policy(replace_only, write_authorization).validate_mutation(
            baseline,
            mutation,
            mutation_family="header",
        )


def test_header_mutation_reordering_fails_closed(
    authorization_payload,
    write_authorization,
):
    guarded = policy(authorization_v2(authorization_payload), write_authorization)
    baseline = request()
    baseline.headers.extend([("X-Probe", "a"), ("X-Probe", "b")])
    mutation = request()
    mutation.headers.extend([("X-Probe", "b"), ("X-Probe", "a")])

    with pytest.raises(AuthorizationError, match="HEADER_MUTATION_REORDER_NOT_AUTHORIZED"):
        guarded.validate_mutation(baseline, mutation, mutation_family="header")


def test_mutation_context_rejects_unvalidated_outgoing_changes(
    authorization_payload,
    write_authorization,
):
    guarded = policy(authorization_v2(authorization_payload), write_authorization)
    baseline = request()
    mutation = request()
    mutation.headers.append(("X-Probe", "1"))
    changed_after_validation = request()
    changed_after_validation.headers.extend([("X-Probe", "1"), ("X-Other", "1")])

    with pytest.raises(AuthorizationError, match="MUTATION_DERIVATION_NOT_AUTHORIZED"):
        guarded.authorize_mutation(
            baseline,
            mutation,
            changed_after_validation,
            base_url="http://example.test",
            attempt_kind="mutation",
            mutation_family="header",
            risk_class="safe",
        )


def test_authorization_v2_rejects_malformed_and_bounded_queries(
    authorization_payload,
    write_authorization,
):
    payload = authorization_v2(authorization_payload)
    payload["rules"][0]["query_policy"]["maximum_query_bytes"] = 8
    guarded = policy(payload, write_authorization)

    for path in ("/allowed?too-long=1", "/allowed?bad=%GG"):
        with pytest.raises(
            AuthorizationError,
            match="TARGET_NOT_AUTHORIZED|AMBIGUOUS_TARGET_ENCODING",
        ):
            guarded.authorize(
                request(path=path),
                base_url="http://example.test",
                attempt_kind="control",
                risk_class="safe",
            )


def test_authorization_v2_schema_is_strict(authorization_payload):
    payload = authorization_v2(authorization_payload)
    schema = json.loads(Path("mrma/schemas/authorization-v2.schema.json").read_text())
    validator = Draft202012Validator(schema)

    validator.validate(payload)
    payload["authority"]["allow_duplicate_host"] = True
    assert list(validator.iter_errors(payload))


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
