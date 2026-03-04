from __future__ import annotations

from urllib.parse import urlparse

from .raw_request import RawRequest

Header = tuple[str, str]


def build_request_from_url(
    url: str,
    method: str = "GET",
    headers: list[Header] | None = None,
    body: bytes = b"",
) -> tuple[str, RawRequest]:
    """
    Returns (base_url, RawRequest)
    base_url: scheme://host[:port]
    RawRequest.path: path + ?query
    """
    p = urlparse(url)
    if not p.scheme or not p.netloc:
        raise ValueError(f"Invalid URL: {url!r} (must include scheme and host)")

    base_url = f"{p.scheme}://{p.netloc}"

    path = p.path or "/"
    if p.query:
        path = f"{path}?{p.query}"

    hdrs: list[Header] = []
    if headers:
        hdrs.extend(headers)

    # Ensure Host exists in the raw request (even though client may set it)
    if not any(k.lower() == "host" for k, _ in hdrs):
        hdrs.append(("Host", p.netloc))

    return base_url, RawRequest(
        method=method.upper(),
        path=path,
        http_version="HTTP/1.1",
        headers=hdrs,
        body=body or b"",
    )
