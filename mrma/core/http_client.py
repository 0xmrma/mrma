from __future__ import annotations

import hashlib
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import httpx

from .raw_request import RawRequest

STATE_MODES = ("isolated", "per-arm", "shared-session")
BODY_STORAGE_MODES = ("none", "sample", "full")
SAMPLE_BODY_BYTES = 64 * 1024


@dataclass(frozen=True)
class SendOptions:
    timeout_s: float = 15.0
    follow_redirects: bool = False
    verify_tls: bool = True


@dataclass(frozen=True)
class RedirectHop:
    status: int
    method: str
    origin: str
    location: str | None
    cross_origin: bool
    method_changed: bool


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


class SemanticHttpTransport:
    """Reusable semantic HTTP transport with an explicit cookie-state model."""

    def __init__(self, opts: SendOptions, state_mode: str = "shared-session") -> None:
        if state_mode not in STATE_MODES:
            raise ValueError(f"state_mode must be one of: {', '.join(STATE_MODES)}")
        self.opts = opts
        self.state_mode = state_mode
        self._clients: dict[str, httpx.Client] = {}

    def __enter__(self) -> SemanticHttpTransport:
        keys = ("control", "mutation") if self.state_mode == "per-arm" else ("shared",)
        self._clients = {key: self._new_client() for key in keys}
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()

    def _new_client(self) -> httpx.Client:
        return httpx.Client(
            timeout=self.opts.timeout_s,
            follow_redirects=self.opts.follow_redirects,
            verify=self.opts.verify_tls,
        )

    def close(self) -> None:
        for client in self._clients.values():
            client.close()
        self._clients = {}

    def _client_for(self, arm: str) -> httpx.Client:
        if not self._clients:
            raise RuntimeError("SemanticHttpTransport must be used as a context manager")
        key = arm if self.state_mode == "per-arm" else "shared"
        if key not in self._clients:
            raise ValueError("arm must be 'control' or 'mutation' in per-arm mode")
        return self._clients[key]

    def _before_observation(self, client: httpx.Client) -> None:
        if self.state_mode == "isolated":
            client.cookies.clear()

    def _after_observation(self, client: httpx.Client) -> None:
        if self.state_mode == "isolated":
            client.cookies.clear()

    def send(self, req: RawRequest, base_url: str, arm: str = "control") -> httpx.Response:
        """Send a fully buffered response; retained for legacy non-experiment commands."""
        client = self._client_for(arm)
        self._before_observation(client)
        try:
            return _send(client, req, base_url)
        finally:
            self._after_observation(client)

    def capture(
        self,
        req: RawRequest,
        base_url: str,
        arm: str,
        *,
        max_response_bytes: int,
        body_storage: str,
    ) -> CapturedResponse:
        """Stream and bound one experiment response without retaining an unbounded body."""
        if max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be positive")
        if body_storage not in BODY_STORAGE_MODES:
            raise ValueError(f"body_storage must be one of: {', '.join(BODY_STORAGE_MODES)}")

        client = self._client_for(arm)
        request = _build_request(client, req, base_url)
        self._before_observation(client)
        response: httpx.Response | None = None
        try:
            response = client.send(request, stream=True)
            return _capture_response(response, max_response_bytes, body_storage)
        finally:
            if response is not None:
                response.close()
            self._after_observation(client)


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
        hops.append(
            RedirectHop(
                status=item.status_code,
                method=item.request.method,
                origin=_origin(item.request.url),
                location=location,
                cross_origin=_origin(item.request.url) != _origin(next_response.request.url),
                method_changed=item.request.method != next_response.request.method,
            )
        )
    return tuple(hops)


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
    )


def send_raw_request(req: RawRequest, base_url: str, opts: SendOptions) -> httpx.Response:
    """Send one semantic HTTP request using a short-lived client."""
    with SemanticHttpTransport(opts) as transport:
        return transport.send(req, base_url)
