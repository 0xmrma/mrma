from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from .compare import EquivalenceConfig, equivalent_response
from .mutate import remove_header, set_header
from .mutations import Mutation
from .raw_request import RawRequest


@dataclass
class ImpactRow:
    name: str
    detail: str
    equivalent: bool
    similarity: float
    status_base: int
    status_mut: int
    len_base: int
    len_mut: int


def run_impact(
    baseline_req: RawRequest,
    sender: Callable[[RawRequest], object],
    cfg: EquivalenceConfig,
    mutations: list[Mutation],
) -> list[ImpactRow]:
    base_resp = sender(baseline_req)
    base_body = base_resp.content or b""
    base_status = base_resp.status_code

    out: list[ImpactRow] = []

    for m in mutations:
        detail = ""
        if m.remove:
            detail = f"remove {m.remove}"
        elif m.set_header:
            detail = f"set {m.set_header[0]}: {m.set_header[1]}"

        rq = baseline_req
        if m.remove:
            rq = remove_header(rq, m.remove)
        if m.set_header:
            k, v = m.set_header
            rq = set_header(rq, k, v, override=True)

        r = sender(rq)
        body = r.content or b""
        cmp = equivalent_response(base_status, base_body, r.status_code, body, cfg)

        out.append(
            ImpactRow(
                name=m.name,
                detail=detail,
                equivalent=cmp.equivalent,
                similarity=cmp.sim,
                status_base=cmp.status_a,
                status_mut=cmp.status_b,
                len_base=cmp.len_a,
                len_mut=cmp.len_b,
            )
        )

    # Sort: changed first, then lowest similarity
    out.sort(key=lambda x: (x.equivalent, x.similarity))
    return out
