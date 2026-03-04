from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass


@dataclass
class SendPolicy:
    delay_s: float = 0.0          # fixed delay between requests
    rps: float = 0.0              # if >0, enforce minimum spacing 1/rps
    retries: int = 0
    retry_status: tuple[int, ...] = (429, 502, 503, 504)
    backoff_base_s: float = 0.4   # exponential backoff base
    backoff_cap_s: float = 4.0    # max backoff


class RateGate:
    def __init__(self) -> None:
        self._last_ts: float = 0.0

    def wait(self, policy: SendPolicy) -> None:
        # compute required minimum spacing
        min_spacing = 0.0
        if policy.delay_s and policy.delay_s > 0:
            min_spacing = max(min_spacing, policy.delay_s)
        if policy.rps and policy.rps > 0:
            min_spacing = max(min_spacing, 1.0 / policy.rps)

        if min_spacing <= 0:
            return

        now = time.monotonic()
        if self._last_ts == 0.0:
            self._last_ts = now
            return

        elapsed = now - self._last_ts
        sleep_s = min_spacing - elapsed
        if sleep_s > 0:
            time.sleep(sleep_s)
        self._last_ts = time.monotonic()


def send_with_policy(
    send_once: Callable[[], object],
    policy: SendPolicy,
    gate: RateGate | None = None,
) -> object:
    """
    send_once(): performs one request and returns response-like object with .status_code
    Applies rate limiting + retries for selected status codes.
    """
    if gate is None:
        gate = RateGate()

    attempt = 0
    while True:
        gate.wait(policy)
        resp = send_once()

        code = getattr(resp, "status_code", None)
        if code is None:
            return resp

        if attempt >= policy.retries or code not in set(policy.retry_status):
            return resp

        # exponential backoff
        backoff = min(policy.backoff_cap_s, policy.backoff_base_s * (2 ** attempt))
        time.sleep(backoff)
        attempt += 1
