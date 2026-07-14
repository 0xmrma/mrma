from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import httpx

from .raw_request import RawRequest


@dataclass
class SendOptions:
    timeout_s: float = 15.0
    follow_redirects: bool = False
    verify_tls: bool = True


class SemanticHttpTransport:
    """Reusable httpx transport for semantic, rather than wire-exact, replay."""

    def __init__(self, opts: SendOptions) -> None:
        self.opts = opts
        self._client: httpx.Client | None = None

    def __enter__(self) -> SemanticHttpTransport:
        self._client = httpx.Client(
            timeout=self.opts.timeout_s,
            follow_redirects=self.opts.follow_redirects,
            verify=self.opts.verify_tls,
        )
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def send(self, req: RawRequest, base_url: str) -> httpx.Response:
        if self._client is None:
            raise RuntimeError("SemanticHttpTransport must be used as a context manager")
        return _send(self._client, req, base_url)


def _merge_url(base_url: str, path: str) -> str:
    # If path is absolute URL in request line, use it
    if path.startswith("http://") or path.startswith("https://"):
        return path
    # Otherwise join with base_url
    return urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))

def _send(client: httpx.Client, req: RawRequest, base_url: str) -> httpx.Response:
    url = _merge_url(base_url, req.path)

    # httpx headers object supports duplicates via list of tuples
    headers: list[tuple[str, str]] = list(req.headers)

    # If Host is missing, derive from URL
    has_host = any(k.lower() == "host" for k, _ in headers)
    if not has_host:
        host = urlparse(url).netloc
        headers.append(("Host", host))

    return client.request(
        method=req.method,
        url=url,
        headers=headers,
        content=req.body if req.body else None,
    )


def send_raw_request(req: RawRequest, base_url: str, opts: SendOptions) -> httpx.Response:
    """Send one semantic HTTP request using a short-lived client."""
    with SemanticHttpTransport(opts) as transport:
        return transport.send(req, base_url)
