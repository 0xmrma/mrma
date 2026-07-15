from __future__ import annotations

import time
from collections.abc import Callable
from contextvars import ContextVar
from dataclasses import dataclass


@dataclass
class SendPolicy:
    delay_s: float = 0.0          # fixed delay between requests
    rps: float = 0.0              # if >0, enforce minimum spacing 1/rps
    retries: int = 0
    retry_status: tuple[int, ...] = (429, 502, 503, 504)
    backoff_base_s: float = 0.4   # exponential backoff base
    backoff_cap_s: float = 4.0    # max backoff


@dataclass(frozen=True)
class AttemptRecord:
    attempt: int
    response: object | None
    error: Exception | None
    elapsed_ms: float
    retry_reason: str | None
    backoff_ms: float | None


@dataclass(frozen=True)
class SendOutcome:
    response: object | None
    error: Exception | None
    attempts: int
    attempt_trace: tuple[AttemptRecord, ...] = ()

    @property
    def succeeded(self) -> bool:
        return self.error is None and self.response is not None


_ATTEMPT_KIND: ContextVar[str | None] = ContextVar("mrma_attempt_kind", default=None)


def current_attempt_kind() -> str | None:
    return _ATTEMPT_KIND.get()


def _send_scoped(send_once: Callable[[], object], kind: str) -> object:
    token = _ATTEMPT_KIND.set(kind)
    try:
        return send_once()
    finally:
        _ATTEMPT_KIND.reset(token)


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
        resp = _send_scoped(send_once, "exploratory" if attempt == 0 else "retry")

        code = getattr(resp, "status_code", None)
        if code is None:
            return resp

        if attempt >= policy.retries or code not in set(policy.retry_status):
            return resp

        # exponential backoff
        backoff = min(policy.backoff_cap_s, policy.backoff_base_s * (2 ** attempt))
        time.sleep(backoff)
        attempt += 1


def send_with_policy_outcome(
    send_once: Callable[[], object],
    policy: SendPolicy,
    gate: RateGate | None = None,
) -> SendOutcome:
    """Apply request policy and preserve every attempt as bounded experiment evidence."""
    if gate is None:
        gate = RateGate()

    retry_statuses = set(policy.retry_status)
    attempt = 0
    trace: list[AttemptRecord] = []
    while True:
        gate.wait(policy)
        attempt += 1
        started = time.perf_counter()
        response: object | None = None
        attempt_error: Exception | None = None
        try:
            response = _send_scoped(
                send_once,
                "exploratory" if attempt == 1 else "retry",
            )
        except Exception as exc:
            attempt_error = exc
            elapsed_ms = round((time.perf_counter() - started) * 1000, 3)
            if attempt > policy.retries:
                trace.append(
                    AttemptRecord(
                        attempt=attempt,
                        response=None,
                        error=exc,
                        elapsed_ms=elapsed_ms,
                        retry_reason=None,
                        backoff_ms=None,
                    )
                )
                return SendOutcome(
                    response=None,
                    error=exc,
                    attempts=attempt,
                    attempt_trace=tuple(trace),
                )
            retry_reason = "transport-error"
        else:
            elapsed_ms = round((time.perf_counter() - started) * 1000, 3)
            code = getattr(response, "status_code", None)
            if attempt > policy.retries or code not in retry_statuses:
                trace.append(
                    AttemptRecord(
                        attempt=attempt,
                        response=response,
                        error=None,
                        elapsed_ms=elapsed_ms,
                        retry_reason=None,
                        backoff_ms=None,
                    )
                )
                return SendOutcome(
                    response=response,
                    error=None,
                    attempts=attempt,
                    attempt_trace=tuple(trace),
                )
            retry_reason = "configured-status"

        backoff = min(policy.backoff_cap_s, policy.backoff_base_s * (2 ** (attempt - 1)))
        trace.append(
            AttemptRecord(
                attempt=attempt,
                response=response,
                error=attempt_error,
                elapsed_ms=elapsed_ms,
                retry_reason=retry_reason,
                backoff_ms=round(backoff * 1000, 3),
            )
        )
        time.sleep(backoff)
