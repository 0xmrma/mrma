from __future__ import annotations

import shlex

from .raw_request import RawRequest
from .render import render_raw_request

Header = tuple[str, str]

def to_curl(base_url: str, req: RawRequest) -> str:
    url = base_url.rstrip("/") + req.path
    parts: list[str] = ["curl", "-i", "-sS", "-X", req.method]

    # headers
    for k, v in req.headers:
        # skip Host because curl sets it from URL (unless user explicitly wants it)
        if k.lower() == "host":
            continue
        parts += ["-H", f"{k}: {v}"]

    # body
    if req.body:
        # safest: send as binary via --data-binary
        body_str = req.body.decode("utf-8", errors="replace")
        parts += ["--data-binary", body_str]

    parts.append(url)
    return " ".join(shlex.quote(p) for p in parts)

def to_raw(req: RawRequest) -> str:
    return render_raw_request(req.method, req.path, req.headers, body=req.body)
