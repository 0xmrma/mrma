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

def _merge_url(base_url: str, path: str) -> str:
    # If path is absolute URL in request line, use it
    if path.startswith("http://") or path.startswith("https://"):
        return path
    # Otherwise join with base_url
    return urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))

def send_raw_request(req: RawRequest, base_url: str, opts: SendOptions) -> httpx.Response:
    """
    Sends the RawRequest to base_url + req.path.
    - Preserves header order roughly, but httpx ultimately uses dict-like headers.
    - Keeps duplicates by joining with commas when repeated keys appear.
    """
    url = _merge_url(base_url, req.path)

    # httpx headers object supports duplicates via list of tuples
    headers: list[tuple[str, str]] = list(req.headers)

    # If Host is missing, derive from URL
    has_host = any(k.lower() == "host" for k, _ in headers)
    if not has_host:
        host = urlparse(url).netloc
        headers.append(("Host", host))

    with httpx.Client(
        timeout=opts.timeout_s,
        follow_redirects=opts.follow_redirects,
        verify=opts.verify_tls,
    ) as client:
        resp = client.request(
            method=req.method,
            url=url,
            headers=headers,
            content=req.body if req.body else None,
        )
        return resp
