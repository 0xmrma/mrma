from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

IMPORTANT_RESPONSE_HEADERS = [
    "content-type",
    "location",
    "set-cookie",
    "cache-control",
    "vary",
    "server",
]

@dataclass
class ResponseFingerprint:
    status_code: int
    body_len: int
    body_sha256: str
    headers: dict[str, str]  # selected headers (lowercase)

def fingerprint_response(resp, ignore_headers: tuple[str, ...] = (), ignore_body_regex: tuple[str, ...] = ()) -> ResponseFingerprint:
    body = resp.content or b""

    if ignore_body_regex:
        text = body.decode("utf-8", errors="replace")
        for pat in ignore_body_regex:
            try:
                text = re.sub(pat, "<MRMA_IGNORED>", text, flags=re.MULTILINE)
            except re.error:
                continue
        body = text.encode("utf-8", errors="replace")

    sha = hashlib.sha256(body).hexdigest()

    ignore = {h.lower() for h in ignore_headers}

    selected: dict[str, str] = {}
    for h in IMPORTANT_RESPONSE_HEADERS:
        if h in ignore:
            continue
        if h in resp.headers:
            selected[h] = resp.headers.get(h, "")

    return ResponseFingerprint(
        status_code=resp.status_code,
        body_len=len(body),
        body_sha256=sha,
        headers=selected,
    )
