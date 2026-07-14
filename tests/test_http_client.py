import gzip
import hashlib

import httpx
import pytest

from mrma.core.http_client import SemanticHttpTransport, SendOptions
from mrma.core.raw_request import RawRequest


def request(path: str = "/") -> RawRequest:
    return RawRequest("GET", path, "HTTP/1.1", [("Host", "example.test")], b"")


def mock_transport(monkeypatch, state_mode: str, handler, *, follow_redirects: bool = False):
    transport = SemanticHttpTransport(
        SendOptions(trust_env=False, follow_redirects=follow_redirects),
        state_mode=state_mode,
    )

    def new_client():
        return httpx.Client(
            transport=httpx.MockTransport(handler),
            follow_redirects=follow_redirects,
        )

    monkeypatch.setattr(transport, "_new_client", new_client)
    return transport


def test_client_transport_inputs_are_explicit_and_environment_trust_defaults_off(monkeypatch):
    captured: dict[str, object] = {}

    class DummyClient:
        def close(self):
            return None

    def capture_client(**kwargs):
        captured.update(kwargs)
        return DummyClient()

    monkeypatch.setattr("mrma.core.http_client.httpx.Client", capture_client)
    transport = SemanticHttpTransport(
        SendOptions(trust_env=False, proxy="http://proxy.test:8080")
    )
    transport._new_client()

    assert captured["trust_env"] is False
    assert captured["proxy"] == "http://proxy.test:8080"
    assert captured["verify"] is True


def test_custom_ca_uses_an_explicit_ssl_context_and_rejects_disabled_verification(
    monkeypatch,
):
    captured: dict[str, object] = {}
    marker = object()

    class DummyClient:
        def close(self):
            return None

    monkeypatch.setattr(
        "mrma.core.http_client.ssl.create_default_context",
        lambda *, cafile: marker if cafile == "approved.pem" else None,
    )
    monkeypatch.setattr(
        "mrma.core.http_client.httpx.Client",
        lambda **kwargs: captured.update(kwargs) or DummyClient(),
    )

    SemanticHttpTransport(SendOptions(trust_env=False, ca_bundle="approved.pem"))._new_client()

    assert captured["verify"] is marker
    with pytest.raises(ValueError, match="cannot be combined"):
        SendOptions(trust_env=False, verify_tls=False, ca_bundle="approved.pem")


def test_isolated_mode_prevents_cookie_carryover_and_preserves_explicit_cookie(monkeypatch):
    observed: list[str | None] = []

    def handler(incoming: httpx.Request) -> httpx.Response:
        observed.append(incoming.headers.get("cookie"))
        return httpx.Response(200, headers={"set-cookie": "session=server"}, content=b"ok")

    with mock_transport(monkeypatch, "isolated", handler) as transport:
        transport.capture(
            request(), "https://example.test", "control", max_response_bytes=1024, body_storage="full"
        )
        transport.capture(
            request(), "https://example.test", "mutation", max_response_bytes=1024, body_storage="full"
        )
        explicit = request()
        explicit.headers.append(("Cookie", "baseline=explicit"))
        transport.capture(
            explicit, "https://example.test", "control", max_response_bytes=1024, body_storage="full"
        )

    assert observed == [None, None, "baseline=explicit"]


def test_shared_and_per_arm_state_modes_have_distinct_cookie_semantics(monkeypatch):
    shared_observed: list[str | None] = []

    def shared_handler(incoming: httpx.Request) -> httpx.Response:
        shared_observed.append(incoming.headers.get("cookie"))
        return httpx.Response(200, headers={"set-cookie": "session=shared"}, content=b"ok")

    with mock_transport(monkeypatch, "shared-session", shared_handler) as transport:
        for arm in ("control", "mutation"):
            transport.capture(
                request(), "https://example.test", arm, max_response_bytes=1024, body_storage="full"
            )
    assert shared_observed == [None, "session=shared"]

    per_arm_observed: list[tuple[str, str | None]] = []

    def per_arm_handler(incoming: httpx.Request) -> httpx.Response:
        arm = incoming.headers["x-arm"]
        per_arm_observed.append((arm, incoming.headers.get("cookie")))
        return httpx.Response(200, headers={"set-cookie": f"session={arm}"}, content=b"ok")

    with mock_transport(monkeypatch, "per-arm", per_arm_handler) as transport:
        for arm in ("control", "mutation", "control", "mutation"):
            arm_request = request()
            arm_request.headers.append(("X-Arm", arm))
            transport.capture(
                arm_request,
                "https://example.test",
                arm,
                max_response_bytes=1024,
                body_storage="full",
            )
    assert per_arm_observed == [
        ("control", None),
        ("mutation", None),
        ("control", "session=control"),
        ("mutation", "session=mutation"),
    ]


def test_redirect_chain_records_cross_origin_and_redirect_cookie_is_observation_local(monkeypatch):
    initial_cookies: list[str | None] = []
    final_cookies: list[str | None] = []

    def handler(incoming: httpx.Request) -> httpx.Response:
        if incoming.url.path == "/start":
            initial_cookies.append(incoming.headers.get("cookie"))
            return httpx.Response(
                302,
                headers={
                    "location": "https://other.test/final",
                    "set-cookie": "redirect=1",
                },
            )
        final_cookies.append(incoming.headers.get("cookie"))
        return httpx.Response(200, content=b"done")

    with mock_transport(monkeypatch, "isolated", handler, follow_redirects=True) as transport:
        first = transport.capture(
            request("/start"),
            "https://example.test",
            "control",
            max_response_bytes=1024,
            body_storage="full",
        )
        transport.capture(
            request("/start"),
            "https://example.test",
            "mutation",
            max_response_bytes=1024,
            body_storage="full",
        )

    assert initial_cookies == [None, None]
    assert len(first.redirect_chain) == 1
    assert first.redirect_chain[0].cross_origin is True
    assert first.redirect_chain[0].resolved_target == "https://other.test/final"
    assert first.final_origin == "https://other.test"
    assert first.final_url == "https://other.test/final"
    # Cookie domain rules may suppress a cross-origin cookie; the chain remains isolated either way.
    assert len(final_cookies) == 2


def test_redirect_trace_records_cross_origin_credential_stripping(monkeypatch):
    def handler(incoming: httpx.Request) -> httpx.Response:
        if incoming.url.host == "example.test":
            return httpx.Response(302, headers={"location": "https://other.test/final"})
        return httpx.Response(200, content=b"done")

    authorized = request("/start")
    authorized.headers.append(("Authorization", "Bearer secret"))
    with mock_transport(monkeypatch, "isolated", handler, follow_redirects=True) as transport:
        captured = transport.capture(
            authorized,
            "https://example.test",
            "control",
            max_response_bytes=1024,
            body_storage="full",
        )

    assert captured.redirect_chain[0].credential_forwarding == "stripped"


def test_capture_enforces_response_read_and_storage_bounds(monkeypatch):
    def handler(_incoming: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * 100_000)

    with mock_transport(monkeypatch, "isolated", handler) as transport:
        limited = transport.capture(
            request(),
            "https://example.test",
            "control",
            max_response_bytes=1024,
            body_storage="full",
        )
        sampled = transport.capture(
            request(),
            "https://example.test",
            "control",
            max_response_bytes=100_000,
            body_storage="sample",
        )
        none = transport.capture(
            request(),
            "https://example.test",
            "control",
            max_response_bytes=100_000,
            body_storage="none",
        )

    assert limited.response_limit_exceeded is True
    assert limited.body_digest_complete is False
    assert len(limited.content) <= 1024
    assert sampled.body_digest_complete is True
    assert sampled.body_retained_complete is False
    assert len(sampled.content) == 64 * 1024
    assert none.content == b""
    assert none.body_digest_complete is True


def test_capture_hashes_compressed_transfer_bytes_without_decompression(monkeypatch):
    compressed = gzip.compress(b"x" * 1_000_000)

    def handler(_incoming: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-encoding": "gzip"},
            stream=httpx.ByteStream(compressed),
        )

    with mock_transport(monkeypatch, "isolated", handler) as transport:
        captured = transport.capture(
            request(),
            "https://example.test",
            "control",
            max_response_bytes=4096,
            body_storage="full",
        )

    assert len(compressed) < 4096
    assert captured.response_limit_exceeded is False
    assert captured.body_length == len(compressed)
    assert captured.content == compressed
    assert captured.body_sha256 == hashlib.sha256(compressed).hexdigest()


def test_connection_modes_create_the_declared_pool_scopes(monkeypatch):
    def exercise(mode: str) -> int:
        created = 0
        transport = SemanticHttpTransport(
            SendOptions(trust_env=False),
            state_mode="isolated",
            connection_mode=mode,
        )

        def new_client():
            nonlocal created
            created += 1
            return httpx.Client(
                transport=httpx.MockTransport(
                    lambda _incoming: httpx.Response(200, content=b"ok")
                )
            )

        monkeypatch.setattr(transport, "_new_client", new_client)
        with transport:
            for round_index, arm in ((1, "control"), (1, "mutation"), (2, "control")):
                captured = transport.capture(
                    request(),
                    "https://example.test",
                    arm,
                    round_index=round_index,
                    max_response_bytes=1024,
                    body_storage="full",
                )
                assert captured.http_version == "HTTP/1.1"
                if mode == "per-round" and arm == "mutation":
                    transport.complete_round(round_index)
        return created

    assert exercise("reuse") == 1
    assert exercise("per-arm") == 2
    assert exercise("per-round") == 2
    assert exercise("fresh-observation") == 3


def test_fresh_connections_can_preserve_explicit_shared_cookie_state(monkeypatch):
    observed: list[str | None] = []
    transport = SemanticHttpTransport(
        SendOptions(trust_env=False),
        state_mode="shared-session",
        connection_mode="fresh-observation",
    )

    def handler(incoming: httpx.Request) -> httpx.Response:
        observed.append(incoming.headers.get("cookie"))
        return httpx.Response(200, headers={"set-cookie": "session=shared"}, content=b"ok")

    monkeypatch.setattr(
        transport,
        "_new_client",
        lambda: httpx.Client(transport=httpx.MockTransport(handler)),
    )
    with transport:
        for arm in ("control", "mutation"):
            transport.capture(
                request(),
                "https://example.test",
                arm,
                round_index=1,
                max_response_bytes=1024,
                body_storage="full",
            )

    assert observed == [None, "session=shared"]
