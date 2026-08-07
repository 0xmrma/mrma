from __future__ import annotations

import hashlib
import os
import ssl
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from types import TracebackType
from urllib.parse import urljoin, urlparse

import httpx

from .http_semantics import canonical_uri
from .raw_request import RawRequest

STATE_MODES = ("isolated", "per-arm", "shared-session")
CONNECTION_MODES = ("reuse", "per-arm", "per-round", "fresh-observation")
BODY_STORAGE_MODES = ("none", "sample", "full")
SAMPLE_BODY_BYTES = 64 * 1024
_GUARDED_TRANSPORT_CAPABILITY = object()

_AuthorizedDispatch = Callable[[RawRequest, str, "SendOptions"], object]
_AUTHORIZED_DISPATCH: ContextVar[_AuthorizedDispatch | None] = ContextVar(
    "mrma_authorized_http_dispatch",
    default=None,
)


class NetworkPolicyError(RuntimeError):
    mrma_fatal_policy_error = True


@contextmanager
def authorized_http_dispatch(dispatch: _AuthorizedDispatch) -> Iterator[None]:
    token = _AUTHORIZED_DISPATCH.set(dispatch)
    try:
        yield
    finally:
        _AUTHORIZED_DISPATCH.reset(token)


def ssl_context_from_ca_bytes(ca_bytes: bytes) -> ssl.SSLContext:
    """Build a client context from the exact CA bytes recorded in provenance."""
    if b"-----BEGIN CERTIFICATE-----" in ca_bytes:
        try:
            cadata: str | bytes = ca_bytes.decode("ascii")
        except UnicodeDecodeError as exc:
            raise ValueError("PEM CA bundle must contain ASCII certificate data") from exc
    else:
        cadata = ca_bytes
    return ssl.create_default_context(cadata=cadata)


@dataclass(frozen=True)
class SendOptions:
    trust_env: bool
    timeout_s: float = 15.0
    follow_redirects: bool = False
    verify_tls: bool = True
    proxy: str | None = None
    ssl_context: ssl.SSLContext | None = field(default=None, repr=False, compare=False)
    environment_snapshot: tuple[tuple[str, str | None], ...] | None = field(
        default=None,
        repr=False,
    )

    def __post_init__(self) -> None:
        if not self.verify_tls and self.ssl_context is not None:
            raise ValueError("ssl_context cannot be combined with disabled TLS verification")
        if not self.trust_env and self.environment_snapshot is not None:
            raise ValueError("environment_snapshot requires trust_env=True")


@dataclass(frozen=True)
class RedirectHop:
    status: int
    method: str
    origin: str
    target_origin: str
    location: str | None
    cross_origin: bool
    method_changed: bool
    credential_forwarding: str
    resolved_target: str | None = None


@dataclass(frozen=True)
class CapturedResponse:
    status_code: int
    headers: tuple[tuple[str, str], ...]
    content: bytes
    body_length: int
    body_sha256: str
    body_digest_complete: bool
    body_retained_complete: bool
    response_limit_exceeded: bool
    redirect_chain: tuple[RedirectHop, ...]
    final_origin: str
    http_version: str | None = None
    final_url: str | None = None
    response_head_bytes: int = 0
    represented_bytes: int = 0


class SemanticHttpTransport:
    """Reusable semantic HTTP transport with an explicit cookie-state model."""

    def __init__(
        self,
        opts: SendOptions,
        state_mode: str = "shared-session",
        connection_mode: str = "reuse",
        *,
        authorization_kernel: object | None = None,
    ) -> None:
        if authorization_kernel is not _GUARDED_TRANSPORT_CAPABILITY:
            raise NetworkPolicyError(
                "low-level semantic transport requires the authorization kernel capability"
            )
        if state_mode not in STATE_MODES:
            raise ValueError(f"state_mode must be one of: {', '.join(STATE_MODES)}")
        if connection_mode not in CONNECTION_MODES:
            raise ValueError(
                f"connection_mode must be one of: {', '.join(CONNECTION_MODES)}"
            )
        self.opts = opts
        self.state_mode = state_mode
        self.connection_mode = connection_mode
        self._clients: dict[str, httpx.Client] = {}
        self._state_cookies: dict[str, httpx.Cookies] = {}
        self._active_observation: tuple[httpx.Client, bool, str, int | None] | None = None

    def __enter__(self) -> SemanticHttpTransport:
        keys: tuple[str, ...]
        if self.connection_mode == "reuse":
            keys = ("shared",)
        elif self.connection_mode == "per-arm":
            keys = ("control", "mutation")
        else:
            keys = ()
        self._clients = {key: self._new_client() for key in keys}
        self._state_cookies = {}
        self._active_observation = None
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def _new_client(self) -> httpx.Client:
        self._assert_environment_snapshot()
        verify: bool | ssl.SSLContext = (
            self.opts.ssl_context
            if self.opts.ssl_context is not None
            else self.opts.verify_tls
        )
        client = httpx.Client(
            timeout=self.opts.timeout_s,
            follow_redirects=self.opts.follow_redirects,
            verify=verify,
            trust_env=self.opts.trust_env,
            proxy=self.opts.proxy,
        )
        try:
            self._assert_environment_snapshot()
        except RuntimeError:
            client.close()
            raise
        return client

    def _assert_environment_snapshot(self) -> None:
        snapshot = self.opts.environment_snapshot
        if snapshot is None:
            return
        changed = [name for name, expected in snapshot if os.environ.get(name) != expected]
        if changed:
            raise RuntimeError(
                "transport environment changed after evidence snapshot: "
                + ", ".join(changed)
            )

    def close(self) -> None:
        if self._active_observation is not None:
            raise RuntimeError("cannot close transport during an active observation")
        for client in self._clients.values():
            client.close()
        self._clients = {}
        self._state_cookies = {}

    def _client_for(self, arm: str, round_index: int | None) -> tuple[httpx.Client, bool]:
        if arm not in {"control", "mutation"}:
            raise ValueError("arm must be 'control' or 'mutation'")
        if self.connection_mode == "reuse":
            return self._clients["shared"], False
        if self.connection_mode == "per-arm":
            return self._clients[arm], False
        if self.connection_mode == "per-round":
            if round_index is None:
                raise ValueError("round_index is required for per-round connections")
            key = f"round:{round_index}"
            if key not in self._clients:
                self._clients[key] = self._new_client()
            return self._clients[key], False
        return self._new_client(), True

    def _cookie_state_key(self, arm: str) -> str:
        return arm if self.state_mode == "per-arm" else "shared"

    def complete_round(self, round_index: int) -> None:
        """Close a round-scoped pool as soon as its bracket has completed."""
        if self.connection_mode != "per-round":
            return
        client = self._clients.pop(f"round:{round_index}", None)
        if client is not None:
            client.close()

    def clear_observation_cookies(self) -> None:
        """Discard response-derived cookie state inside the active observation."""
        if self._active_observation is None:
            raise RuntimeError("cookie state can only be cleared during an observation")
        client, _, _, _ = self._active_observation
        client.cookies.clear()

    def _before_observation(self, client: httpx.Client, arm: str) -> None:
        client.cookies.clear()
        if self.state_mode != "isolated":
            stored = self._state_cookies.get(self._cookie_state_key(arm))
            if stored is not None:
                client.cookies.update(stored)

    def _after_observation(self, client: httpx.Client, arm: str) -> None:
        if self.state_mode == "isolated":
            client.cookies.clear()
        else:
            self._state_cookies[self._cookie_state_key(arm)] = httpx.Cookies(client.cookies)

    @contextmanager
    def observation_session(
        self,
        *,
        arm: str,
        round_index: int | None,
    ) -> Iterator[None]:
        """Keep cookies and a fresh-observation client for one logical observation."""
        if self._active_observation is not None:
            raise RuntimeError("observation sessions cannot be nested")
        client, close_after = self._client_for(arm, round_index)
        self._before_observation(client, arm)
        self._active_observation = (client, close_after, arm, round_index)
        try:
            yield
        finally:
            self._active_observation = None
            self._after_observation(client, arm)
            if close_after:
                client.close()

    def send(self, req: RawRequest, base_url: str, arm: str = "control") -> httpx.Response:
        """Send a fully buffered response; retained for legacy non-experiment commands."""
        client, close_after = self._client_for(arm, 0)
        self._before_observation(client, arm)
        try:
            return _send(client, req, base_url)
        finally:
            self._after_observation(client, arm)
            if close_after:
                client.close()

    def capture(
        self,
        req: RawRequest,
        base_url: str,
        arm: str,
        *,
        max_response_bytes: int,
        body_storage: str,
        round_index: int | None = None,
        allow_cookie_field: bool = True,
    ) -> CapturedResponse:
        """Stream and bound one experiment response without retaining an unbounded body."""
        if max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be positive")
        if body_storage not in BODY_STORAGE_MODES:
            raise ValueError(f"body_storage must be one of: {', '.join(BODY_STORAGE_MODES)}")

        active = self._active_observation
        if active is None:
            client, close_after = self._client_for(arm, round_index)
            self._before_observation(client, arm)
        else:
            client, close_after, active_arm, active_round = active
            if arm != active_arm or round_index != active_round:
                raise RuntimeError("capture does not belong to the active observation")
        request = _build_request(
            client,
            req,
            base_url,
            allow_cookie_field=allow_cookie_field,
        )
        response: httpx.Response | None = None
        try:
            response = client.send(request, stream=True)
            return _capture_response(response, max_response_bytes, body_storage)
        finally:
            if response is not None:
                response.close()
            if active is None:
                self._after_observation(client, arm)
                if close_after:
                    client.close()

    def prepare(
        self,
        req: RawRequest,
        base_url: str,
        arm: str,
        *,
        round_index: int | None = None,
        allow_cookie_field: bool = True,
    ) -> httpx.Request:
        """Build the exact HTTPX request that a current observation will send."""
        active = self._active_observation
        if active is None:
            raise RuntimeError("request preparation requires an active observation session")
        client, _close_after, active_arm, active_round = active
        if arm != active_arm or round_index != active_round:
            raise RuntimeError("prepared request does not belong to the active observation")
        return _build_request(
            client,
            req,
            base_url,
            allow_cookie_field=allow_cookie_field,
        )

    def capture_prepared(
        self,
        request: httpx.Request,
        arm: str,
        *,
        max_response_bytes: int,
        body_storage: str,
        round_index: int | None = None,
    ) -> CapturedResponse:
        """Send one previously built request without rebuilding effective fields."""
        if max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be positive")
        if body_storage not in BODY_STORAGE_MODES:
            raise ValueError(f"body_storage must be one of: {', '.join(BODY_STORAGE_MODES)}")
        active = self._active_observation
        if active is None:
            raise RuntimeError("prepared requests require an active observation session")
        client, _close_after, active_arm, active_round = active
        if arm != active_arm or round_index != active_round:
            raise RuntimeError("prepared request does not belong to the active observation")
        response: httpx.Response | None = None
        try:
            response = client.send(request, stream=True)
            return _capture_response(
                response,
                max_response_bytes,
                body_storage,
                include_headers_in_limit=True,
            )
        finally:
            if response is not None:
                response.close()


def _merge_url(base_url: str, path: str) -> str:
    if path.startswith("http://") or path.startswith("https://"):
        return path
    return urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))


def _request_parts(req: RawRequest, base_url: str) -> tuple[str, list[tuple[str, str]]]:
    url = _merge_url(base_url, req.path)
    headers: list[tuple[str, str]] = list(req.headers)
    if not any(name.lower() == "host" for name, _ in headers):
        headers.append(("Host", urlparse(url).netloc))
    return url, headers


def _build_request(
    client: httpx.Client,
    req: RawRequest,
    base_url: str,
    *,
    allow_cookie_field: bool = True,
) -> httpx.Request:
    url, headers = _request_parts(req, base_url)
    request = client.build_request(
        method=req.method,
        url=url,
        headers=headers,
        content=req.body if req.body else None,
    )
    if not allow_cookie_field:
        request.headers.pop("cookie", None)
    return request


def _send(client: httpx.Client, req: RawRequest, base_url: str) -> httpx.Response:
    return client.send(_build_request(client, req, base_url))


def _origin(url: httpx.URL) -> str:
    default_port = 443 if url.scheme == "https" else 80
    port = "" if url.port in (None, default_port) else f":{url.port}"
    host = f"[{url.host}]" if ":" in url.host else url.host
    return f"{url.scheme}://{host}{port}"


def _redirect_chain(response: httpx.Response) -> tuple[RedirectHop, ...]:
    history = list(response.history)
    hops: list[RedirectHop] = []
    for index, item in enumerate(history):
        next_response = history[index + 1] if index + 1 < len(history) else response
        location = item.headers.get("location")
        source_credentials = _credential_headers(item.request)
        target_credentials = _credential_headers(next_response.request)
        hops.append(
            RedirectHop(
                status=item.status_code,
                method=item.request.method,
                origin=_origin(item.request.url),
                target_origin=_origin(next_response.request.url),
                location=location,
                cross_origin=_origin(item.request.url) != _origin(next_response.request.url),
                method_changed=item.request.method != next_response.request.method,
                credential_forwarding=_credential_forwarding(
                    source_credentials,
                    target_credentials,
                ),
                resolved_target=canonical_uri(str(next_response.request.url)),
            )
        )
    return tuple(hops)


def _credential_headers(request: httpx.Request) -> dict[str, tuple[str, ...]]:
    evidence_names = {"authorization", "cookie", "proxy-authorization"}
    selected: dict[str, list[str]] = {}
    for name, value in request.headers.multi_items():
        lowered = name.lower()
        if lowered in evidence_names:
            selected.setdefault(lowered, []).append(value)
    return {name: tuple(values) for name, values in selected.items()}


def _credential_forwarding(
    source: dict[str, tuple[str, ...]],
    target: dict[str, tuple[str, ...]],
) -> str:
    if not source and not target:
        return "none"
    if source == target:
        return "retained"
    if source and target.keys() < source.keys() and all(
        target[name] == source[name] for name in target
    ):
        return "stripped"
    return "changed"


def _capture_response(
    response: httpx.Response,
    max_response_bytes: int,
    body_storage: str,
    *,
    include_headers_in_limit: bool = False,
) -> CapturedResponse:
    version = (response.http_version or "HTTP/1.1").encode("ascii", errors="replace")
    reason = response.reason_phrase.encode("latin-1", errors="replace")
    response_head_bytes = (
        len(version)
        + 1
        + 3
        + 1
        + len(reason)
        + 2
        + sum(len(name) + 2 + len(value) + 2 for name, value in response.headers.raw)
        + 2
    )
    body_limit = (
        max(0, max_response_bytes - response_head_bytes)
        if include_headers_in_limit
        else max_response_bytes
    )
    retention_limit = {
        "none": 0,
        "sample": min(SAMPLE_BODY_BYTES, body_limit),
        "full": body_limit,
    }[body_storage]
    retained = bytearray()
    digest = hashlib.sha256()
    observed_length = 0
    limit_exceeded = include_headers_in_limit and response_head_bytes > max_response_bytes

    # Raw transfer bytes keep the read bound effective even for adversarial content encodings.
    # Mock/custom transports may legally return an already-buffered response.
    chunks = (response.content,) if response.is_stream_consumed else response.iter_raw()
    for chunk in chunks:
        next_length = observed_length + len(chunk)
        if next_length > body_limit:
            allowed = max(0, body_limit - observed_length)
            if allowed:
                digest.update(chunk[:allowed])
                if len(retained) < retention_limit:
                    retained.extend(chunk[: min(allowed, retention_limit - len(retained))])
            observed_length = body_limit + 1
            limit_exceeded = True
            break
        digest.update(chunk)
        observed_length = next_length
        if len(retained) < retention_limit:
            retained.extend(chunk[: retention_limit - len(retained)])

    digest_complete = not limit_exceeded
    retained_complete = digest_complete and len(retained) == observed_length
    headers = tuple((str(name).lower(), str(value)) for name, value in response.headers.multi_items())
    represented_bytes = response_head_bytes + min(observed_length, body_limit)
    return CapturedResponse(
        status_code=response.status_code,
        headers=headers,
        content=bytes(retained),
        body_length=observed_length,
        body_sha256=digest.hexdigest(),
        body_digest_complete=digest_complete,
        body_retained_complete=retained_complete,
        response_limit_exceeded=limit_exceeded,
        redirect_chain=_redirect_chain(response),
        final_origin=_origin(response.request.url),
        http_version=response.http_version or None,
        final_url=canonical_uri(str(response.request.url)),
        response_head_bytes=response_head_bytes,
        represented_bytes=represented_bytes,
    )


def send_raw_request(req: RawRequest, base_url: str, opts: SendOptions) -> httpx.Response:
    """Dispatch through the active authorization-first scope."""
    dispatch = _AUTHORIZED_DISPATCH.get()
    if dispatch is None:
        raise NetworkPolicyError(
            "direct semantic HTTP sends require an authorization-first dispatch scope"
        )
    return dispatch(req, base_url, opts)  # type: ignore[return-value]
