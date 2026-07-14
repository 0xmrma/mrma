from __future__ import annotations

import hashlib
import hmac
import ipaddress
import secrets
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

from .raw_request import RawRequest

REDACTION_POLICIES = ("standard", "strict", "forensic")


@dataclass(frozen=True)
class EvidenceRedactor:
    policy: str = "standard"
    _key: bytes = field(default_factory=lambda: secrets.token_bytes(32), repr=False)

    def __post_init__(self) -> None:
        if self.policy not in REDACTION_POLICIES:
            raise ValueError(f"redaction policy must be one of: {', '.join(REDACTION_POLICIES)}")

    def fingerprint(self, value: str | bytes, *, label: str = "value", length: int = 20) -> str:
        raw = value if isinstance(value, bytes) else value.encode("utf-8", errors="replace")
        digest = hmac.new(self._key, label.encode("ascii") + b"\0" + raw, hashlib.sha256)
        return f"hmac-sha256:{digest.hexdigest()[:length]}"

    def header_name(self, name: str) -> str:
        if self.policy == "strict":
            return self.fingerprint(name.lower(), label="header-name", length=12)
        return name.lower()

    def size(self, value: int) -> int | str:
        if self.policy == "forensic":
            return value
        if value <= 0:
            return "0 B"
        lower = 1 << (value.bit_length() - 1)
        upper = lower * 2
        return f"{lower}-{upper - 1} B"

    def elapsed_ms(self, value: float) -> float | str:
        if self.policy == "forensic":
            return round(value, 3)
        bucket = 100 if self.policy == "strict" else 10
        lower = int(value // bucket) * bucket
        return f"{lower}-{lower + bucket - 1} ms"

    def origin(self, origin: str) -> str:
        parts = urlsplit(origin)
        hostname = parts.hostname or ""
        if self.policy == "strict" or (self.policy == "standard" and _is_internal_host(hostname)):
            hostname = f"host-{self.fingerprint(hostname, label='host', length=12).split(':', 1)[1]}"
        display_host = f"[{hostname}]" if ":" in hostname else hostname
        port = f":{parts.port}" if parts.port is not None else ""
        return urlunsplit((parts.scheme, f"{display_host}{port}", "", "", ""))

    def path(self, path: str) -> str:
        normalized = path or "/"
        if self.policy == "forensic":
            return normalized
        segments = normalized.split("/")
        masked = [
            f"~{self.fingerprint(segment, label='path-segment', length=12).split(':', 1)[1]}"
            if segment
            else ""
            for segment in segments
        ]
        result = "/".join(masked)
        return result or "/"

    def target_metadata(self, base_url: str, req: RawRequest) -> dict[str, object]:
        origin_parts = urlsplit(base_url)
        hostname = origin_parts.hostname or ""
        display_host = f"[{hostname}]" if ":" in hostname else hostname
        port = f":{origin_parts.port}" if origin_parts.port is not None else ""
        clear_origin = urlunsplit(
            (origin_parts.scheme, f"{display_host}{port}", "", "", "")
        )

        request_target = urlsplit(req.path)
        query = request_target.query
        metadata: dict[str, object] = {
            "origin": self.origin(clear_origin),
            "method": req.method,
            "path": self.path(request_target.path or "/"),
            "query_present": bool(query),
        }
        if query:
            metadata["query_fingerprint"] = self.fingerprint(query, label="query")
        return metadata


def _is_internal_host(hostname: str) -> bool:
    lowered = hostname.rstrip(".").lower()
    if lowered in {"localhost", "localhost.localdomain"}:
        return True
    try:
        address = ipaddress.ip_address(lowered)
    except ValueError:
        pass
    else:
        return not address.is_global
    if "." not in lowered:
        return True
    return lowered.endswith((".internal", ".local", ".lan", ".home", ".test", ".invalid"))
