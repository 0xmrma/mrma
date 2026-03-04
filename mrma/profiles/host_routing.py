from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from ..core.compare import EquivalenceConfig, equivalent_response
from ..core.mutate import set_header
from ..core.raw_request import RawRequest

Header = tuple[str, str]

IMPORTANT = ["location", "set-cookie", "cache-control", "vary", "content-type", "server"]


@dataclass
class HostRoutingCase:
    name: str
    headers: list[Header]


@dataclass
class HostRoutingResult:
    name: str
    equivalent: bool
    similarity: float
    status_base: int
    status_case: int
    len_base: int
    len_case: int
    location_base: str
    location_case: str
    changed_headers: list[tuple[str, str, str]]  # (header, base, case)


def default_host_routing_cases(fake_host: str = "example.invalid") -> list[HostRoutingCase]:
    return [
        HostRoutingCase("xfh-fakehost", [("X-Forwarded-Host", fake_host)]),
        HostRoutingCase("xoriginalhost-fakehost", [("X-Original-Host", fake_host)]),
        HostRoutingCase("xhost-fakehost", [("X-Host", fake_host)]),
        HostRoutingCase("forwarded-host", [("Forwarded", f'host="{fake_host}"')]),
    ]


def run_host_routing_profile(
    baseline_req: RawRequest,
    sender: Callable[[RawRequest], object],
    cfg: EquivalenceConfig,
    cases: list[HostRoutingCase],
) -> list[HostRoutingResult]:
    base_resp = sender(baseline_req)
    base_body = base_resp.content or b""
    base_status = base_resp.status_code
    base_loc = base_resp.headers.get("location", "")

    bh = {k.lower(): v for k, v in base_resp.headers.items()}

    results: list[HostRoutingResult] = []

    for c in cases:
        rq = baseline_req
        for k, v in c.headers:
            rq = set_header(rq, k, v, override=True)

        r = sender(rq)
        body = r.content or b""
        cmp = equivalent_response(base_status, base_body, r.status_code, body, cfg)

        mh = {k.lower(): v for k, v in r.headers.items()}
        changed: list[tuple[str, str, str]] = []
        for k in IMPORTANT:
            bval = bh.get(k, "")
            mval = mh.get(k, "")
            if bval != mval:
                changed.append((k, bval, mval))

        results.append(
            HostRoutingResult(
                name=c.name,
                equivalent=cmp.equivalent,
                similarity=cmp.sim,
                status_base=base_status,
                status_case=r.status_code,
                len_base=len(base_body),
                len_case=len(body),
                location_base=base_loc,
                location_case=r.headers.get("location", ""),
                changed_headers=changed,
            )
        )

    results.sort(key=lambda x: (x.equivalent, x.similarity))
    return results
