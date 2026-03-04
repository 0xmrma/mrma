from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from .compare import EquivalenceConfig, equivalent_response
from .mutate import set_header
from .raw_request import RawRequest

Header = tuple[str, str]

@dataclass
class IsolateResult:
    culprit_headers: list[Header]
    requests_sent: int

def _send(sender: Callable[[RawRequest], object], req: RawRequest):
    return sender(req)

def isolate_added_headers(
    baseline_req: RawRequest,
    sender: Callable[[RawRequest], object],
    cfg: EquivalenceConfig,
    headers_to_add: list[Header],
    ddmin_start: int = 4,
) -> IsolateResult:
    """
    Find minimal subset of headers_to_add that causes response to CHANGE vs baseline.
    (Opposite of discover; here we want smallest set that flips equivalence -> changed.)
    """
    # Baseline fingerprint
    base_resp = _send(sender, baseline_req)
    base_body = base_resp.content or b""
    base_status = base_resp.status_code
    sent = 1

    def is_changed(req: RawRequest) -> bool:
        nonlocal sent
        r = _send(sender, req)
        body = r.content or b""
        sent += 1
        res = equivalent_response(base_status, base_body, r.status_code, body, cfg)
        return not res.equivalent

    # First: confirm that adding all headers actually changes
    all_req = baseline_req
    for k, v in headers_to_add:
        all_req = set_header(all_req, k, v, override=False)

    if not is_changed(all_req):
        return IsolateResult(culprit_headers=[], requests_sent=sent)

    # ddmin-like to minimize the "causing set"
    idxs = list(range(len(headers_to_add)))
    current: set[int] = set(idxs)
    gran = min(ddmin_start, max(2, len(current)))

    def build_req(sel: set[int]) -> RawRequest:
        rq = baseline_req
        for i in sorted(sel):
            k, v = headers_to_add[i]
            rq = set_header(rq, k, v, override=False)
        return rq

    while True:
        if len(current) <= 1:
            break

        g = min(gran, len(current))
        cur_list = sorted(current)
        chunk_size = (len(cur_list) + g - 1) // g
        chunks = [
            set(cur_list[j : j + chunk_size])
            for j in range(0, len(cur_list), chunk_size)
        ]

        reduced = False

        # Try removing each chunk from the current set (still want change)
        for chunk in chunks:
            trial = current - chunk
            if not trial:
                continue
            if is_changed(build_req(trial)):
                current = trial
                reduced = True

        if reduced:
            continue

        if gran >= len(current):
            break
        gran = min(len(current), gran * 2)

    culprit = [headers_to_add[i] for i in sorted(current)]
    return IsolateResult(culprit_headers=culprit, requests_sent=sent)
