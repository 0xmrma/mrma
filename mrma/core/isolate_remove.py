from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from .compare import EquivalenceConfig, equivalent_response
from .mutate import remove_header
from .raw_request import RawRequest

HeaderName = str


@dataclass
class IsolateRemoveResult:
    culprit_removals: list[HeaderName]
    requests_sent: int


def isolate_removed_headers(
    baseline_req: RawRequest,
    sender: Callable[[RawRequest], object],
    cfg: EquivalenceConfig,
    headers_to_remove: list[HeaderName],
    ddmin_start: int = 4,
) -> IsolateRemoveResult:
    """
    Find minimal subset of headers_to_remove such that removing them causes response to CHANGE.
    """
    base_resp = sender(baseline_req)
    base_body = base_resp.content or b""
    base_status = base_resp.status_code
    sent = 1

    def build_req(removals: set[int]) -> RawRequest:
        rq = baseline_req
        for i in sorted(removals):
            rq = remove_header(rq, headers_to_remove[i])
        return rq

    def is_changed(removals: set[int]) -> bool:
        nonlocal sent
        r = sender(build_req(removals))
        body = r.content or b""
        sent += 1
        cmp = equivalent_response(base_status, base_body, r.status_code, body, cfg)
        return not cmp.equivalent

    # confirm that removing ALL actually changes; otherwise no culprit
    all_set = set(range(len(headers_to_remove)))
    if not headers_to_remove:
        return IsolateRemoveResult(culprit_removals=[], requests_sent=sent)

    if not is_changed(all_set):
        return IsolateRemoveResult(culprit_removals=[], requests_sent=sent)

    current: set[int] = set(all_set)
    gran = min(ddmin_start, max(2, len(current)))

    while True:
        if len(current) <= 1:
            break

        g = min(gran, len(current))
        cur_list = sorted(current)
        chunk_size = (len(cur_list) + g - 1) // g
        chunks = [set(cur_list[j : j + chunk_size]) for j in range(0, len(cur_list), chunk_size)]

        reduced = False

        # Try removing fewer headers (keep change)
        for chunk in chunks:
            trial = current - chunk
            if not trial:
                continue
            if is_changed(trial):
                current = trial
                reduced = True

        if reduced:
            continue

        if gran >= len(current):
            break
        gran = min(len(current), gran * 2)

    culprits = [headers_to_remove[i] for i in sorted(current)]
    return IsolateRemoveResult(culprit_removals=culprits, requests_sent=sent)
