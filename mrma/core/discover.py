from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from .compare import EquivalenceConfig, equivalent_response
from .raw_request import RawRequest

Header = tuple[str, str]

ALWAYS_IMPLICIT = {
    "host",            # http clients will set from URL
    "content-length",  # set automatically when body exists
}

@dataclass
class DiscoverResult:
    required: list[Header]
    optional: list[Header]
    implicit: list[Header]
    requests_sent: int

def _apply_keep(headers: list[Header], keep_idx: set[int]) -> list[Header]:
    return [h for i, h in enumerate(headers) if i in keep_idx]

def _send_and_check(
    sender: Callable[[RawRequest], object],
    base_status: int,
    base_body: bytes,
    req: RawRequest,
    cfg: EquivalenceConfig,
) -> bool:
    resp = sender(req)
    body = resp.content or b""
    res = equivalent_response(base_status, base_body, resp.status_code, body, cfg)
    return res.equivalent

def discover_required_headers(
    original: RawRequest,
    sender: Callable[[RawRequest], object],
    cfg: EquivalenceConfig,
    protected_names: set[str] | None = None,
    chunk_start: int = 8,
) -> DiscoverResult:
    """
    Delta-debugging header minimizer.
    protected_names: header names (lower) that we never remove (cookie/auth/etc).
    chunk_start: initial partition count for ddmin.
    """
    protected_names = protected_names or set()

    headers = list(original.headers)

    # Separate implicit headers (client will likely add them anyway)
    implicit = [(k, v) for (k, v) in headers if k.lower() in ALWAYS_IMPLICIT]
    explicit_headers = [(k, v) for (k, v) in headers if k.lower() not in ALWAYS_IMPLICIT]

    headers = explicit_headers
    n = len(headers)

    # Baseline
    base_resp = sender(original)
    base_body = base_resp.content or b""
    base_status = base_resp.status_code
    sent = 1

    # Indices we are allowed to remove (not protected)
    removable = [i for i, (k, _) in enumerate(headers) if k.lower() not in protected_names]
    keep = set(range(n))  # currently keeping all

    # ddmin-ish approach: try removing chunks of removable headers
    # while keeping protected always
    granularity = min(chunk_start, max(2, len(removable)))

    def test_remove(indices_to_remove: set[int]) -> bool:
        nonlocal sent
        new_keep = keep - indices_to_remove
        # Ensure protected headers are still kept
        for i, (k, _) in enumerate(headers):
            if k.lower() in protected_names:
                new_keep.add(i)

        new_headers = _apply_keep(headers, new_keep)
        test_req = RawRequest(
            method=original.method,
            path=original.path,
            http_version=original.http_version,
            headers=new_headers,
            body=original.body,
        )
        ok = _send_and_check(sender, base_status, base_body, test_req, cfg)
        sent += 1
        return ok

    while True:
        current_removable = [i for i in removable if i in keep]
        if len(current_removable) == 0:
            break

        # partition indices into chunks
        g = min(granularity, len(current_removable))
        chunk_size = (len(current_removable) + g - 1) // g
        chunks = [
            set(current_removable[j : j + chunk_size])
            for j in range(0, len(current_removable), chunk_size)
        ]

        removed_any = False
        for chunk in chunks:
            if not chunk:
                continue
            # Try removing this chunk
            if test_remove(chunk):
                # Removal succeeded, commit it
                keep -= chunk
                removed_any = True
                # After successful reduction, try same granularity again
        if removed_any:
            continue

        # If no chunk could be removed at this granularity, increase granularity
        if granularity >= len(current_removable):
            break
        granularity = min(len(current_removable), granularity * 2)

    required = [headers[i] for i in sorted(keep)]
    optional = [headers[i] for i in range(n) if i not in keep]

    return DiscoverResult(
        required=required,
        optional=optional,
        implicit=implicit,
        requests_sent=sent,
    )
