from __future__ import annotations

import hashlib
import ssl
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import httpx

from .http_semantics import canonical_uri
from .raw_request import RawRequest

STATE_MODES = ("isolated", "per-arm", "shared-session")
CONNECTION_MODES = ("reuse", "per-arm", "per-round", "fresh-observation")
BODY_STORAGE_MODES = ("none", "sample", "full")
SAMPLE_BODY_BYTES = 64 * 1024


@dataclass(frozen=True)
class SendOptions:
    trust_env: bool
    timeout_s: float = 15.0
    follow_redirects: bool = False
    verify_tls: bool = True
    proxy: str | None = None
    ca_bundle: str | None = None

    def __post_init__(self) -> None:
        if not self.verify_tls and self.ca_bundle is not None:
            raise ValueError("ca_bundle cannot be combined with disabled TLS verification")


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


class SemanticHttpTransport:
    """Reusable semantic HTTP transport with an explicit cookie-state model."""

    def __init__(
        self,
        opts: SendOptions,
        state_mode: str = "shared-session",
        connection_mode: str = "reuse",
    ) -> None:
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
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()

    def _new_client(self) -> httpx.Client:
        verify: bool | ssl.SSLContext = self.opts.verify_tls
        if self.opts.ca_bundle is not None:
            verify = ssl.create_default_context(cafile=self.opts.ca_bundle)
        return httpx.Client(
            timeout=self.opts.timeout_s,
            follow_redirects=self.opts.follow_redirects,
            verify=verify,
            trust_env=self.opts.trust_env,
            proxy=self.opts.proxy,
        )

    def close(self) -> None:
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
    ) -> CapturedResponse:
        """Stream and bound one experiment response without retaining an unbounded body."""
        if max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be positive")
        if body_storage not in BODY_STORAGE_MODES:
            raise ValueError(f"body_storage must be one of: {', '.join(BODY_STORAGE_MODES)}")

        client, close_after = self._client_for(arm, round_index)
        self._before_observation(client, arm)
        request = _build_request(client, req, base_url)
        response: httpx.Response | None = None
        try:
            response = client.send(request, stream=True)
            return _capture_response(response, max_response_bytes, body_storage)
        finally:
            if response is not None:
                response.close()
            self._after_observation(client, arm)
            if close_after:
                client.close()


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


def _build_request(client: httpx.Client, req: RawRequest, base_url: str) -> httpx.Request:
    url, headers = _request_parts(req, base_url)
    return client.build_request(
        method=req.method,
        url=url,
        headers=headers,
        content=req.body if req.body else None,
    )


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
) -> CapturedResponse:
    retention_limit = {
        "none": 0,
        "sample": min(SAMPLE_BODY_BYTES, max_response_bytes),
        "full": max_response_bytes,
    }[body_storage]
    retained = bytearray()
    digest = hashlib.sha256()
    observed_length = 0
    limit_exceeded = False

    # Raw transfer bytes keep the read bound effective even for adversarial content encodings.
    # Mock/custom transports may legally return an already-buffered response.
    chunks = (response.content,) if response.is_stream_consumed else response.iter_raw()
    for chunk in chunks:
        next_length = observed_length + len(chunk)
        if next_length > max_response_bytes:
            allowed = max(0, max_response_bytes - observed_length)
            if allowed:
                digest.update(chunk[:allowed])
                if len(retained) < retention_limit:
                    retained.extend(chunk[: min(allowed, retention_limit - len(retained))])
            observed_length = max_response_bytes + 1
            limit_exceeded = True
            break
        digest.update(chunk)
        observed_length = next_length
        if len(retained) < retention_limit:
            retained.extend(chunk[: retention_limit - len(retained)])

    digest_complete = not limit_exceeded
    retained_complete = digest_complete and len(retained) == observed_length
    headers = tuple((str(name).lower(), str(value)) for name, value in response.headers.multi_items())
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
    )


def send_raw_request(req: RawRequest, base_url: str, opts: SendOptions) -> httpx.Response:
    """Send one semantic HTTP request using a short-lived client."""
    with SemanticHttpTransport(opts) as transport:
        return transport.send(req, base_url)
