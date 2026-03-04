from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class RawRequest:
    method: str
    path: str
    http_version: str
    headers: list[tuple[str, str]]  # keep order + duplicates
    body: bytes

    def header_dict_last_wins(self) -> dict[str, str]:
        d: dict[str, str] = {}
        for k, v in self.headers:
            d[k] = v
        return d

def _split_header_line(line: str) -> tuple[str, str]:
    if ":" not in line:
        return line.strip(), ""
    k, v = line.split(":", 1)
    return k.strip(), v.lstrip()

def parse_raw_http_request(text: str) -> RawRequest:
    """
    Parses a raw HTTP request (e.g., Burp "Copy to file"):

    GET /path HTTP/1.1
    Host: example.com
    User-Agent: ...
    ...

    <blank line>
    body...
    """
    # Normalize line endings
    text = text.replace("\r\n", "\n").replace("\r", "\n")

    if "\n\n" in text:
        head, body = text.split("\n\n", 1)
        body_bytes = body.encode("utf-8", errors="replace")
    else:
        head, body_bytes = text, b""

    lines = [ln for ln in head.split("\n") if ln.strip() != "" or ln == ""]
    if not lines:
        raise ValueError("Empty request file")

    # Request line
    req_line = lines[0].strip()
    m = re.match(r"^(\S+)\s+(\S+)\s+(HTTP/\d\.\d)$", req_line)
    if not m:
        raise ValueError(f"Invalid request line: {req_line!r}")

    method, path, http_version = m.group(1), m.group(2), m.group(3)

    headers: list[tuple[str, str]] = []
    for ln in lines[1:]:
        if ln.strip() == "":
            continue
        k, v = _split_header_line(ln)
        headers.append((k, v))

    return RawRequest(method=method, path=path, http_version=http_version, headers=headers, body=body_bytes)
