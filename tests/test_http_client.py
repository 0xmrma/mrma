import httpx

from mrma.core.http_client import SemanticHttpTransport, SendOptions
from mrma.core.raw_request import RawRequest


def request(path: str = "/") -> RawRequest:
    return RawRequest("GET", path, "HTTP/1.1", [("Host", "example.test")], b"")


def mock_transport(monkeypatch, state_mode: str, handler, *, follow_redirects: bool = False):
    transport = SemanticHttpTransport(
        SendOptions(follow_redirects=follow_redirects),
        state_mode=state_mode,
    )

    def new_client():
        return httpx.Client(
            transport=httpx.MockTransport(handler),
            follow_redirects=follow_redirects,
        )

    monkeypatch.setattr(transport, "_new_client", new_client)
    return transport


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
    assert first.final_origin == "https://other.test"
    # Cookie domain rules may suppress a cross-origin cookie; the chain remains isolated either way.
    assert len(final_cookies) == 2


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
