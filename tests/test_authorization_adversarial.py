from __future__ import annotations

import json
import socket
from copy import deepcopy
from datetime import timedelta
from pathlib import Path

import pytest

from mrma.core.raw_request import RawRequest
from mrma.policy.authorization import (
    AuthorizationError,
    ManifestAuthorizationPolicy,
    load_authorization_manifest,
    system_resolver,
)
from mrma.policy.method_risk import classify_method


def _write(path: Path, payload: object) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _rule(payload: dict[str, object]) -> dict[str, object]:
    return payload["rules"][0]  # type: ignore[index,return-value]


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        (lambda value: value.update(schema_version="wrong"), "UNSUPPORTED_AUTHORIZATION_SCHEMA"),
        (lambda value: value.update(issuer=""), "INVALID_MANIFEST_FIELD"),
        (lambda value: value.update(issued_at="not-a-time"), "INVALID_TIME"),
        (lambda value: value.update(issued_at="2026-01-01T00:00:00"), "INVALID_TIME"),
        (lambda value: value.update(rules=[]), "INVALID_MANIFEST_FIELD"),
        (lambda value: value.update(rules=["bad"]), "INVALID_MANIFEST_FIELD"),
        (lambda value: _rule(value).update(schemes=["ftp"]), "INVALID_SCHEME"),
        (lambda value: _rule(value).update(hosts=["*.example.test"]), "INVALID_HOST"),
        (lambda value: _rule(value).update(ports=[0]), "INVALID_PORT"),
        (lambda value: _rule(value).update(path_prefixes=["relative"]), "INVALID_PATH_SCOPE"),
        (lambda value: _rule(value).update(attempt_kinds=["unknown"]), "INVALID_ATTEMPT_KIND"),
        (lambda value: _rule(value).update(cidrs=["127.0.0.1/24"]), "INVALID_CIDR"),
        (lambda value: _rule(value).update(maximum_request_body_bytes=-1), "INVALID_BODY_LIMIT"),
        (
            lambda value: _rule(value).update(maximum_repetitions_by_method={"POST": 0}),
            "INVALID_METHOD_REPETITIONS",
        ),
        (
            lambda value: _rule(value).update(require_idempotency_key="POST"),
            "INVALID_MANIFEST_FIELD",
        ),
        (
            lambda value: _rule(value).update(disposable_environment="yes"),
            "INVALID_MANIFEST_FIELD",
        ),
        (lambda value: value.update(proxy="bad"), "INVALID_MANIFEST_FIELD"),
        (
            lambda value: value.update(
                proxy={"mode": "unknown", "hosts": [], "ports": [], "cidrs": []}
            ),
            "INVALID_PROXY_POLICY",
        ),
        (
            lambda value: value.update(
                proxy={
                    "mode": "deny",
                    "hosts": ["proxy.test"],
                    "ports": [],
                    "cidrs": [],
                }
            ),
            "INVALID_PROXY_POLICY",
        ),
        (
            lambda value: value.update(
                proxy={
                    "mode": "allow-explicit",
                    "hosts": ["proxy.test"],
                    "ports": [8080],
                    "cidrs": [],
                }
            ),
            "INVALID_PROXY_POLICY",
        ),
        (
            lambda value: value.update(
                proxy={
                    "mode": "allow-explicit",
                    "hosts": ["proxy.test"],
                    "ports": [8080],
                    "cidrs": ["bad"],
                }
            ),
            "INVALID_CIDR",
        ),
        (lambda value: value.update(redirects="bad"), "INVALID_MANIFEST_FIELD"),
        (
            lambda value: value.update(
                redirects={
                    "mode": "unknown",
                    "maximum_depth": 1,
                    "forward_credentials_cross_origin": False,
                }
            ),
            "INVALID_REDIRECT_POLICY",
        ),
        (
            lambda value: value.update(
                redirects={
                    "mode": "deny",
                    "maximum_depth": 21,
                    "forward_credentials_cross_origin": False,
                }
            ),
            "INVALID_REDIRECT_POLICY",
        ),
        (
            lambda value: value.update(
                redirects={
                    "mode": "deny",
                    "maximum_depth": 0,
                    "forward_credentials_cross_origin": "no",
                }
            ),
            "INVALID_REDIRECT_POLICY",
        ),
        (lambda value: value.update(organizational_metadata=[]), "INVALID_MANIFEST_FIELD"),
        (lambda value: value.update(budget=[]), "INVALID_MANIFEST_FIELD"),
        (lambda value: value["budget"].update(unexpected=1), "INVALID_BUDGET"),
        (lambda value: value["budget"].update(total_duration_ms=0), "INVALID_BUDGET"),
        (
            lambda value: _rule(value).update(methods=["GET", "CUSTOM"]),
            "INVALID_METHOD_POLICY",
        ),
    ],
)
def test_manifest_rejects_invalid_policy_shapes(
    tmp_path: Path,
    authorization_payload: dict[str, object],
    mutation,
    code: str,
):
    payload = deepcopy(authorization_payload)
    mutation(payload)
    with pytest.raises(AuthorizationError, match=code):
        load_authorization_manifest(_write(tmp_path / "authorization.json", payload))


def test_manifest_rejects_invalid_validity_window(
    tmp_path: Path,
    authorization_payload: dict[str, object],
):
    payload = deepcopy(authorization_payload)
    payload["expires_at"] = payload["issued_at"]
    with pytest.raises(AuthorizationError, match="INVALID_VALIDITY_WINDOW"):
        load_authorization_manifest(_write(tmp_path / "authorization.json", payload))


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        (b"\xff", "INVALID_MANIFEST_ENCODING"),
        (b"{", "INVALID_MANIFEST_JSON"),
        (b"[]", "INVALID_MANIFEST"),
        (b'{"schema_version":"a","schema_version":"b"}', "DUPLICATE_MANIFEST_KEY"),
        (b'{"value":NaN}', "NONFINITE_NUMBER"),
        (b'{"schema_version":"mrma.authorization/v1"}', "MISSING_MANIFEST_FIELD"),
    ],
)
def test_manifest_parser_rejects_ambiguous_or_malformed_json(
    tmp_path: Path,
    raw: bytes,
    code: str,
):
    path = tmp_path / "authorization.json"
    path.write_bytes(raw)
    with pytest.raises(AuthorizationError, match=code):
        load_authorization_manifest(path)


def test_policy_rejects_not_yet_valid_and_unsupported_targets(
    tmp_path: Path,
    authorization_payload: dict[str, object],
):
    manifest = load_authorization_manifest(
        _write(tmp_path / "authorization.json", authorization_payload)
    )
    guarded = ManifestAuthorizationPolicy(
        manifest,
        resolver=lambda _host, _port: ("127.0.0.1",),
        now=lambda: manifest.issued_at - timedelta(seconds=1),
    )
    with pytest.raises(AuthorizationError, match="AUTHORIZATION_NOT_YET_VALID"):
        guarded.authorize(
            RawRequest("GET", "/", "HTTP/1.1", [], b""),
            base_url="http://example.test",
            attempt_kind="control",
            risk_class="safe",
        )

    guarded = ManifestAuthorizationPolicy(
        manifest,
        resolver=lambda _host, _port: ("127.0.0.1",),
    )
    for target_form in ("authority", "asterisk"):
        with pytest.raises(AuthorizationError, match="UNSUPPORTED_SEMANTIC_TARGET_FORM"):
            guarded.authorize(
                RawRequest("GET", "*", "HTTP/1.1", [], b"", target_form=target_form),
                base_url="http://example.test",
                attempt_kind="control",
                risk_class="safe",
            )
    with pytest.raises(AuthorizationError, match="INVALID_TARGET_URL"):
        guarded.authorize(
            RawRequest("GET", "ftp://example.test/file", "HTTP/1.1", [], b"", target_form="absolute"),
            base_url="http://example.test",
            attempt_kind="control",
            risk_class="safe",
        )


def test_policy_rejects_resolution_and_mutation_policy_failures(
    tmp_path: Path,
    authorization_payload: dict[str, object],
):
    manifest = load_authorization_manifest(
        _write(tmp_path / "authorization.json", authorization_payload)
    )
    request = RawRequest("GET", "/", "HTTP/1.1", [], b"")
    for answers, code in (((), "DNS_EMPTY_ANSWER"), (("not-an-ip",), "INVALID_RESOLVER_RESULT")):
        guarded = ManifestAuthorizationPolicy(
            manifest,
            resolver=lambda _host, _port, answers=answers: answers,
        )
        with pytest.raises(AuthorizationError, match=code):
            guarded.authorize(
                request,
                base_url="http://example.test",
                attempt_kind="control",
                risk_class="safe",
            )

    guarded = ManifestAuthorizationPolicy(
        manifest,
        resolver=lambda _host, _port: ("127.0.0.1",),
    )
    with pytest.raises(AuthorizationError, match="MUTATION_FAMILY_NOT_AUTHORIZED"):
        guarded.authorize(
            request,
            base_url="http://example.test",
            attempt_kind="mutation",
            mutation_family="body",
            risk_class="safe",
        )
    with pytest.raises(AuthorizationError, match="MUTATION_RISK_NOT_AUTHORIZED"):
        guarded.authorize(
            request,
            base_url="http://example.test",
            attempt_kind="mutation",
            mutation_family="header",
            risk_class="unknown-extension",
        )


def test_proxy_validation_and_revalidation_are_address_bound(
    tmp_path: Path,
    authorization_payload: dict[str, object],
):
    payload = deepcopy(authorization_payload)
    payload["proxy"] = {
        "mode": "allow-explicit",
        "hosts": ["proxy.test"],
        "ports": [8080],
        "cidrs": ["192.0.2.0/24"],
    }
    manifest = load_authorization_manifest(_write(tmp_path / "authorization.json", payload))
    target = RawRequest("GET", "/", "HTTP/1.1", [], b"")

    for proxy_url, code in (
        ("http://user:pass@proxy.test:8080", "PROXY_CREDENTIALS_REJECTED"),
        ("socks5://proxy.test:8080", "INVALID_PROXY_URL"),
        ("http://other.test:8080", "PROXY_NOT_AUTHORIZED"),
    ):
        guarded = ManifestAuthorizationPolicy(
            manifest,
            resolver=lambda host, _port: (
                ("192.0.2.10",) if host == "proxy.test" else ("127.0.0.1",)
            ),
        )
        with pytest.raises(AuthorizationError, match=code):
            guarded.authorize(
                target,
                base_url="http://example.test",
                attempt_kind="control",
                risk_class="safe",
                proxy_url=proxy_url,
            )

    answers = iter(("192.0.2.10", "192.0.2.11"))
    guarded = ManifestAuthorizationPolicy(
        manifest,
        resolver=lambda host, _port: (
            (next(answers),) if host == "proxy.test" else ("127.0.0.1",)
        ),
    )
    context = guarded.authorize(
        target,
        base_url="http://example.test",
        attempt_kind="control",
        risk_class="safe",
        proxy_url="http://proxy.test:8080",
    )
    updated = guarded.revalidate(context)
    assert updated.decision.code == "AUTHORIZED_DNS_CHANGED"
    assert updated.decision.proxy_address_set_fingerprint != context.decision.proxy_address_set_fingerprint


def test_system_resolver_handles_literals_dns_and_errors(monkeypatch):
    assert system_resolver("127.0.0.1", 80) == ("127.0.0.1",)
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.2", 80)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 80)),
        ],
    )
    assert system_resolver("example.test", 80) == ("192.0.2.1", "192.0.2.2")

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(socket.gaierror()),
    )
    with pytest.raises(AuthorizationError, match="DNS_RESOLUTION_FAILED"):
        system_resolver("example.test", 80)

    monkeypatch.setattr(socket, "getaddrinfo", lambda *_args, **_kwargs: [])
    with pytest.raises(AuthorizationError, match="DNS_EMPTY_ANSWER"):
        system_resolver("example.test", 80)


@pytest.mark.parametrize(
    ("method", "risk", "repeated"),
    [
        ("GET", "safe", False),
        ("get", "unknown-extension", True),
        ("DELETE", "idempotent-destructive", True),
        ("PATCH", "non-idempotent", True),
        ("CUSTOM", "unknown-extension", True),
    ],
)
def test_method_risk_classification_is_explicit(method: str, risk: str, repeated: bool):
    result = classify_method(method)
    assert result.method == method
    assert result.risk_class == risk
    assert result.repeat_requires_explicit_authorization is repeated
