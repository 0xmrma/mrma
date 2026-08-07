from __future__ import annotations

import hashlib
import json
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, field
from types import TracebackType
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from mrma.evidence.journal import EvidenceContext, EvidenceJournal

BUDGET_MODEL_VERSION = "budget-ledger/1.2"
ATTEMPT_KINDS = frozenset({"control", "mutation", "retry", "redirect", "setup", "reset", "exploratory"})
MUTATION_RISK_LEVELS = frozenset(
    {"safe", "idempotent-destructive", "non-idempotent", "unknown-extension"}
)


class BudgetError(RuntimeError):
    mrma_fatal_policy_error = True

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


@dataclass(frozen=True)
class BudgetLimits:
    total_network_attempts: int
    controls: int
    mutations: int
    retries: int
    redirects: int
    setup_reset_attempts: int
    attempts_per_origin: int
    requests_per_target: int
    bytes_sent: int
    bytes_received: int
    maximum_response_bytes: int
    maximum_request_body_bytes: int
    total_duration_ms: int
    per_attempt_timeout_ms: int
    concurrency: int
    redirect_depth: int
    mutation_risk_level: str

    @property
    def policy_digest(self) -> str:
        payload = json.dumps(
            asdict(self),
            sort_keys=True,
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("ascii")
        return "sha256:" + hashlib.sha256(payload).hexdigest()

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> BudgetLimits:
        required = {field.name for field in cls.__dataclass_fields__.values()}
        extras = set(value) - required
        missing = required - set(value)
        if extras:
            raise BudgetError("UNKNOWN_BUDGET_FIELD", f"unknown budget field {sorted(extras)[0]!r}")
        if missing:
            raise BudgetError("MISSING_BUDGET_FIELD", f"missing budget field {sorted(missing)[0]!r}")
        numeric = required - {"mutation_risk_level"}
        for name in numeric:
            field_value = value[name]
            if not isinstance(field_value, int) or isinstance(field_value, bool) or field_value < 0:
                raise BudgetError("INVALID_BUDGET_LIMIT", f"{name} must be a non-negative integer")
        positive = (
            "concurrency",
            "per_attempt_timeout_ms",
            "maximum_response_bytes",
            "total_duration_ms",
        )
        if any(cast(int, value[name]) < 1 for name in positive):
            raise BudgetError(
                "INVALID_BUDGET_LIMIT",
                "concurrency, timeout, maximum response, and total duration must be positive",
            )
        if value["mutation_risk_level"] not in MUTATION_RISK_LEVELS:
            raise BudgetError("INVALID_BUDGET_LIMIT", "unknown mutation_risk_level")
        numeric_values = {name: cast(int, value[name]) for name in numeric}
        return cls(
            total_network_attempts=numeric_values["total_network_attempts"],
            controls=numeric_values["controls"],
            mutations=numeric_values["mutations"],
            retries=numeric_values["retries"],
            redirects=numeric_values["redirects"],
            setup_reset_attempts=numeric_values["setup_reset_attempts"],
            attempts_per_origin=numeric_values["attempts_per_origin"],
            requests_per_target=numeric_values["requests_per_target"],
            bytes_sent=numeric_values["bytes_sent"],
            bytes_received=numeric_values["bytes_received"],
            maximum_response_bytes=numeric_values["maximum_response_bytes"],
            maximum_request_body_bytes=numeric_values["maximum_request_body_bytes"],
            total_duration_ms=numeric_values["total_duration_ms"],
            per_attempt_timeout_ms=numeric_values["per_attempt_timeout_ms"],
            concurrency=numeric_values["concurrency"],
            redirect_depth=numeric_values["redirect_depth"],
            mutation_risk_level=value["mutation_risk_level"],
        )


@dataclass(frozen=True)
class AttemptCost:
    kind: str
    origin_fingerprint: str
    target_fingerprint: str
    request_body_bytes: int
    request_bytes: int
    response_bytes: int
    timeout_ms: int
    redirect_depth: int = 0
    mutation_risk_level: str = "safe"

    def __post_init__(self) -> None:
        if self.kind not in ATTEMPT_KINDS:
            raise BudgetError("INVALID_ATTEMPT_KIND", f"unknown attempt kind {self.kind!r}")
        for name in (
            "request_body_bytes",
            "request_bytes",
            "response_bytes",
            "timeout_ms",
            "redirect_depth",
        ):
            if getattr(self, name) < 0:
                raise BudgetError("NEGATIVE_ATTEMPT_COST", f"{name} cannot be negative")
        if self.request_bytes < self.request_body_bytes:
            raise BudgetError(
                "INVALID_REQUEST_COST",
                "request bytes cannot be smaller than the request body",
            )
        if self.mutation_risk_level not in MUTATION_RISK_LEVELS:
            raise BudgetError("INVALID_ATTEMPT_RISK", "unknown attempt mutation_risk_level")


@dataclass(frozen=True)
class BudgetSnapshot:
    total_network_attempts: int = 0
    controls: int = 0
    mutations: int = 0
    retries: int = 0
    redirects: int = 0
    setup_reset_attempts: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    duration_ms: int = 0
    active_leases: int = 0
    attempts_by_origin: tuple[tuple[str, int], ...] = ()
    requests_by_target: tuple[tuple[str, int], ...] = ()

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass
class _MutableTotals:
    total_network_attempts: int = 0
    controls: int = 0
    mutations: int = 0
    retries: int = 0
    redirects: int = 0
    setup_reset_attempts: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    duration_ms: int = 0
    attempts_by_origin: dict[str, int] = field(default_factory=dict)
    requests_by_target: dict[str, int] = field(default_factory=dict)

    def add(self, cost: AttemptCost) -> None:
        self.total_network_attempts += 1
        if cost.kind == "control":
            self.controls += 1
        elif cost.kind == "mutation":
            self.mutations += 1
        elif cost.kind == "retry":
            self.retries += 1
        elif cost.kind == "redirect":
            self.redirects += 1
        elif cost.kind in {"setup", "reset"}:
            self.setup_reset_attempts += 1
        self.bytes_sent += cost.request_bytes
        self.bytes_received += cost.response_bytes
        self.duration_ms += cost.timeout_ms
        self.attempts_by_origin[cost.origin_fingerprint] = self.attempts_by_origin.get(cost.origin_fingerprint, 0) + 1
        self.requests_by_target[cost.target_fingerprint] = self.requests_by_target.get(cost.target_fingerprint, 0) + 1

    def subtract(self, cost: AttemptCost) -> None:
        self.total_network_attempts -= 1
        if cost.kind == "control":
            self.controls -= 1
        elif cost.kind == "mutation":
            self.mutations -= 1
        elif cost.kind == "retry":
            self.retries -= 1
        elif cost.kind == "redirect":
            self.redirects -= 1
        elif cost.kind in {"setup", "reset"}:
            self.setup_reset_attempts -= 1
        self.bytes_sent -= cost.request_bytes
        self.bytes_received -= cost.response_bytes
        self.duration_ms -= cost.timeout_ms
        self.attempts_by_origin[cost.origin_fingerprint] -= 1
        self.requests_by_target[cost.target_fingerprint] -= 1
        if min(
            self.total_network_attempts,
            self.controls,
            self.mutations,
            self.retries,
            self.redirects,
            self.setup_reset_attempts,
            self.bytes_sent,
            self.bytes_received,
            self.duration_ms,
            self.attempts_by_origin[cost.origin_fingerprint],
            self.requests_by_target[cost.target_fingerprint],
        ) < 0:
            raise AssertionError("budget reservation accounting became negative")


class BudgetLease:
    def __init__(
        self,
        ledger: BudgetLedger,
        lease_id: str,
        proposed: AttemptCost,
        evidence: EvidenceContext,
    ) -> None:
        self._ledger = ledger
        self.id = lease_id
        self.proposed = proposed
        self.evidence = evidence
        self._active = True
        self._started = time.monotonic()

    @property
    def active(self) -> bool:
        return self._active

    @property
    def response_allowance(self) -> int:
        return self.proposed.response_bytes

    @property
    def policy_digest(self) -> str:
        return self._ledger.policy_digest

    def commit(
        self,
        *,
        bytes_sent: int,
        bytes_received: int,
        duration_ms: int | None = None,
    ) -> BudgetSnapshot:
        if duration_ms is None:
            duration_ms = int((time.monotonic() - self._started) * 1000)
        return self._ledger._commit(
            self,
            bytes_sent=bytes_sent,
            bytes_received=bytes_received,
            duration_ms=duration_ms,
        )

    def release(self, reason: str = "cancelled") -> BudgetSnapshot:
        return self._ledger._release(self, reason=reason)

    def __enter__(self) -> BudgetLease:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if self.active:
            self.release("exception" if exc_type is not None else "unused")


class BudgetLedger:
    """Concurrency-safe reserve/commit ledger with no unleased network cost."""

    def __init__(
        self,
        limits: BudgetLimits,
        journal: EvidenceJournal,
        *,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.limits = limits
        self._journal = journal
        self._monotonic = monotonic
        self._started = monotonic()
        self._lock = threading.RLock()
        self._committed = _MutableTotals()
        self._reserved = _MutableTotals()
        self._leases: dict[str, BudgetLease] = {}

    @property
    def journal(self) -> EvidenceJournal:
        return self._journal

    @property
    def policy_digest(self) -> str:
        return self.limits.policy_digest

    def _combined(self) -> _MutableTotals:
        result = _MutableTotals()
        for source in (self._committed, self._reserved):
            result.total_network_attempts += source.total_network_attempts
            result.controls += source.controls
            result.mutations += source.mutations
            result.retries += source.retries
            result.redirects += source.redirects
            result.setup_reset_attempts += source.setup_reset_attempts
            result.bytes_sent += source.bytes_sent
            result.bytes_received += source.bytes_received
            result.duration_ms += source.duration_ms
            for key, count in source.attempts_by_origin.items():
                result.attempts_by_origin[key] = result.attempts_by_origin.get(key, 0) + count
            for key, count in source.requests_by_target.items():
                result.requests_by_target[key] = result.requests_by_target.get(key, 0) + count
        return result

    def _check(self, proposed: AttemptCost) -> None:
        if proposed.request_body_bytes > self.limits.maximum_request_body_bytes:
            raise BudgetError("REQUEST_BODY_LIMIT", "request body exceeds per-attempt limit")
        if proposed.response_bytes > self.limits.maximum_response_bytes:
            raise BudgetError("RESPONSE_LIMIT", "response reservation exceeds per-attempt limit")
        if proposed.timeout_ms > self.limits.per_attempt_timeout_ms:
            raise BudgetError("ATTEMPT_TIMEOUT_LIMIT", "attempt timeout exceeds policy")
        wall_elapsed_ms = max(0, int((self._monotonic() - self._started) * 1000))
        if wall_elapsed_ms + proposed.timeout_ms > self.limits.total_duration_ms:
            raise BudgetError(
                "BUDGET_EXHAUSTED",
                "total_duration_ms has insufficient wall-clock time for the attempt reservation",
            )
        if proposed.redirect_depth > self.limits.redirect_depth:
            raise BudgetError("REDIRECT_DEPTH_LIMIT", "redirect depth exceeds policy")
        risk_rank = {
            "safe": 0,
            "idempotent-destructive": 1,
            "non-idempotent": 2,
            "unknown-extension": 3,
        }
        if risk_rank[proposed.mutation_risk_level] > risk_rank[self.limits.mutation_risk_level]:
            raise BudgetError("MUTATION_RISK_LIMIT", "attempt risk exceeds policy")
        combined = self._combined()
        checks = (
            ("total_network_attempts", combined.total_network_attempts + 1, self.limits.total_network_attempts),
            ("controls", combined.controls + (proposed.kind == "control"), self.limits.controls),
            ("mutations", combined.mutations + (proposed.kind == "mutation"), self.limits.mutations),
            ("retries", combined.retries + (proposed.kind == "retry"), self.limits.retries),
            ("redirects", combined.redirects + (proposed.kind == "redirect"), self.limits.redirects),
            (
                "setup_reset_attempts",
                combined.setup_reset_attempts + (proposed.kind in {"setup", "reset"}),
                self.limits.setup_reset_attempts,
            ),
            ("bytes_sent", combined.bytes_sent + proposed.request_bytes, self.limits.bytes_sent),
            ("bytes_received", combined.bytes_received + proposed.response_bytes, self.limits.bytes_received),
            ("total_duration_ms", combined.duration_ms + proposed.timeout_ms, self.limits.total_duration_ms),
            (
                "attempts_per_origin",
                combined.attempts_by_origin.get(proposed.origin_fingerprint, 0) + 1,
                self.limits.attempts_per_origin,
            ),
            (
                "requests_per_target",
                combined.requests_by_target.get(proposed.target_fingerprint, 0) + 1,
                self.limits.requests_per_target,
            ),
        )
        for name, observed, limit in checks:
            if observed > limit:
                raise BudgetError("BUDGET_EXHAUSTED", f"{name} would exceed its limit")
        if len(self._leases) >= self.limits.concurrency:
            raise BudgetError("CONCURRENCY_LIMIT", "active lease concurrency is exhausted")

    def reserve(self, proposed: AttemptCost, *, evidence: EvidenceContext) -> BudgetLease:
        with self._lock:
            self._check(proposed)
            lease_id = uuid.uuid4().hex
            lease = BudgetLease(self, lease_id, proposed, evidence)
            self._leases[lease_id] = lease
            self._reserved.add(proposed)
            self._journal.record(
                "BUDGET_RESERVED",
                {
                    "attempt_id": evidence.attempt_id,
                    "lease_fingerprint": f"sha256:{hashlib.sha256(lease_id.encode()).hexdigest()}",
                    "kind": proposed.kind,
                    "request_body_bytes": proposed.request_body_bytes,
                    "request_bytes_reserved": proposed.request_bytes,
                    "response_bytes": proposed.response_bytes,
                    "timeout_ms": proposed.timeout_ms,
                    "redirect_depth": proposed.redirect_depth,
                    "mutation_risk_level": proposed.mutation_risk_level,
                },
            )
            return lease

    def _assert_active(self, lease: BudgetLease) -> None:
        if not lease._active or self._leases.get(lease.id) is not lease:
            raise BudgetError("INACTIVE_LEASE", "lease is not active")

    def _commit(
        self,
        lease: BudgetLease,
        *,
        bytes_sent: int,
        bytes_received: int,
        duration_ms: int,
    ) -> BudgetSnapshot:
        with self._lock:
            self._assert_active(lease)
            if any(value < 0 for value in (bytes_sent, bytes_received, duration_ms)):
                raise BudgetError("NEGATIVE_ACTUAL_COST", "actual attempt cost cannot be negative")
            proposed = lease.proposed
            if bytes_sent > proposed.request_bytes:
                raise BudgetError("LEASE_SEND_OVERRUN", "actual sent bytes exceed reservation")
            if bytes_received > proposed.response_bytes:
                raise BudgetError("LEASE_RECEIVE_OVERRUN", "actual received bytes exceed reservation")
            charged_duration = min(duration_ms, proposed.timeout_ms)
            actual = AttemptCost(
                kind=proposed.kind,
                origin_fingerprint=proposed.origin_fingerprint,
                target_fingerprint=proposed.target_fingerprint,
                request_body_bytes=proposed.request_body_bytes,
                request_bytes=bytes_sent,
                response_bytes=bytes_received,
                timeout_ms=charged_duration,
                redirect_depth=proposed.redirect_depth,
                mutation_risk_level=proposed.mutation_risk_level,
            )
            self._reserved.subtract(proposed)
            self._committed.add(actual)
            lease._active = False
            del self._leases[lease.id]
            snapshot = self._snapshot_unlocked()
            self._journal.record(
                "BUDGET_UPDATED",
                {
                    "attempt_id": lease.evidence.attempt_id,
                    "outcome": "committed",
                    "bytes_sent": bytes_sent,
                    "bytes_received": bytes_received,
                    "duration_ms": duration_ms,
                    "duration_charged_ms": charged_duration,
                    "totals": snapshot.to_dict(),
                },
            )
            return snapshot

    def _release(self, lease: BudgetLease, *, reason: str) -> BudgetSnapshot:
        with self._lock:
            self._assert_active(lease)
            self._reserved.subtract(lease.proposed)
            lease._active = False
            del self._leases[lease.id]
            snapshot = self._snapshot_unlocked()
            self._journal.record(
                "BUDGET_UPDATED",
                {
                    "attempt_id": lease.evidence.attempt_id,
                    "outcome": "released",
                    "reason": reason,
                    "totals": snapshot.to_dict(),
                },
            )
            return snapshot

    def _snapshot_unlocked(self) -> BudgetSnapshot:
        return BudgetSnapshot(
            total_network_attempts=self._committed.total_network_attempts,
            controls=self._committed.controls,
            mutations=self._committed.mutations,
            retries=self._committed.retries,
            redirects=self._committed.redirects,
            setup_reset_attempts=self._committed.setup_reset_attempts,
            bytes_sent=self._committed.bytes_sent,
            bytes_received=self._committed.bytes_received,
            duration_ms=self._committed.duration_ms,
            active_leases=len(self._leases),
            attempts_by_origin=tuple(sorted(self._committed.attempts_by_origin.items())),
            requests_by_target=tuple(sorted(self._committed.requests_by_target.items())),
        )

    def snapshot(self) -> BudgetSnapshot:
        with self._lock:
            return self._snapshot_unlocked()

    def assert_settled(self) -> None:
        with self._lock:
            if self._leases:
                raise BudgetError("ACTIVE_LEASES_REMAIN", "budget ledger has unreleased leases")
