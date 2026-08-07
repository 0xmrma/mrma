from __future__ import annotations

import hashlib
import inspect
import math
import random
import re
import secrets
import socket
import ssl
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from statistics import median

import httpx

from .compare import (
    EffectiveEquivalencePolicy,
    EquivalenceConfig,
    NormalizationOutcome,
    equivalent_response,
    resolve_equivalence_policy,
)
from .http_client import CapturedResponse, RedirectHop
from .http_semantics import (
    SEMANTIC_REGISTRY_VERSION,
    canonical_header_values,
    canonical_uri,
    header_semantic_ambiguities,
    resolve_charset,
)
from .privacy import EvidenceRedactor
from .raw_request import RawRequest
from .sender import AttemptRecord, SendOutcome

HTTP_RESPONSE = "HTTP_RESPONSE"
TIMEOUT = "TIMEOUT"
CONNECTION_RESET = "CONNECTION_RESET"
TLS_ERROR = "TLS_ERROR"
DNS_ERROR = "DNS_ERROR"
PROTOCOL_ERROR = "PROTOCOL_ERROR"
TRANSPORT_ERROR = "TRANSPORT_ERROR"
POLICY_ABORT = "POLICY_ABORT"

PAIR_CHANGED = "CHANGED"
PAIR_UNCHANGED = "UNCHANGED"
PAIR_INDETERMINATE = "INDETERMINATE"

EVIDENCE_RESPONSE_HEADERS = (
    "location",
    "content-location",
    "content-type",
    "content-encoding",
    "cache-control",
    "vary",
    "server",
    "via",
    "set-cookie",
    "date",
    "etag",
    "x-cache",
    "x-cache-status",
    "cf-cache-status",
    "x-served-by",
    "x-vercel-id",
    "x-matched-path",
    "x-powered-by",
    "x-nextjs-cache",
    "x-nextjs-page",
    "x-nextjs-router-state-tree",
    "x-nextjs-data",
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "access-control-allow-headers",
    "access-control-allow-methods",
    "access-control-expose-headers",
    "allow",
)
BODY_SAFETY_HEADERS = ("content-type", "content-encoding")
RESPONSE_HEADER_SCOPES = ("known", "explicit", "all-stable")
_HEADER_NAME = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
CONTENT_TYPE_AMBIGUITY_REASONS = frozenset(
    {
        "multiple-values",
        "malformed-quoted-string",
        "malformed-media-type",
        "missing-parameter-value",
        "invalid-parameter-name",
        "invalid-parameter-value",
        "conflicting-duplicate-parameter",
        "unsupported-charset",
    }
)


@dataclass(frozen=True)
class ExperimentConfig:
    min_rounds: int = 6
    max_rounds: int = 20
    rounds: int | None = None
    min_reproducibility: float = 0.8
    no_influence_threshold: float = 0.2
    max_control_change_rate: float = 0.2
    equivalence: EquivalenceConfig = field(default_factory=EquivalenceConfig)
    seed: int | None = None
    schedule_mode: str = "bracketed"
    state_mode: str = "isolated"
    connection_mode: str = "reuse"
    max_response_bytes: int = 1024 * 1024
    body_storage: str = "sample"
    response_header_scope: str = "known"
    include_response_headers: tuple[str, ...] = ()
    include_response_header_patterns: tuple[str, ...] = ()
    exclude_response_headers: tuple[str, ...] = ()
    response_header_profile: str | None = None
    stable_header_control_observations: int = 3
    assume_text_without_content_type: bool = False
    trust_environment: bool = False
    tls_verification: str = "system"
    proxy_mode: str = "none"
    assurance_preset: str = "custom"
    redactor: EvidenceRedactor = field(default_factory=EvidenceRedactor, repr=False)

    def round_limits(self) -> tuple[int, int]:
        if self.rounds is not None:
            return self.rounds, self.rounds
        return self.min_rounds, self.max_rounds


@dataclass(frozen=True)
class AttemptEvidence:
    attempt: int
    outcome: str
    status: int | None
    elapsed_ms: float
    retry_reason: str | None
    backoff_ms: float | None
    error_type: str | None = None

    def signature(self) -> tuple[object, ...]:
        return (self.outcome, self.status, self.retry_reason, self.error_type)

    def to_dict(self, redactor: EvidenceRedactor) -> dict[str, object]:
        return {
            "attempt": self.attempt,
            "outcome": self.outcome,
            "status": self.status,
            "elapsed": redactor.elapsed_ms(self.elapsed_ms),
            "retry_reason": self.retry_reason,
            "backoff": (
                redactor.elapsed_ms(self.backoff_ms)
                if self.backoff_ms is not None
                else None
            ),
            "error_type": self.error_type,
        }


@dataclass(frozen=True)
class BodyComparatorEligibility:
    eligible: bool
    charset: str | None
    reasons: tuple[str, ...] = ()
    declared_media_type: str | None = None
    declared_charset: str | None = None
    resolution_source: str = "none"
    registry_version: str = SEMANTIC_REGISTRY_VERSION


@dataclass
class Observation:
    arm: str
    round_index: int
    sequence: int
    outcome: str
    status: int | None
    length: int
    body_sha256: str
    body_digest_complete: bool
    body_retained_complete: bool
    elapsed_ms: float
    attempts: int
    headers: dict[str, tuple[str, ...]]
    body: bytes = field(repr=False)
    body_comparator_eligible: bool = False
    body_comparator_charset: str | None = None
    body_comparator_reasons: tuple[str, ...] = ()
    body_comparator_media_type: str | None = None
    body_comparator_declared_charset: str | None = None
    body_comparator_resolution_source: str = "none"
    semantic_registry_version: str = SEMANTIC_REGISTRY_VERSION
    attempt_trace: tuple[AttemptEvidence, ...] = ()
    error_type: str | None = None
    redirect_chain: tuple[RedirectHop, ...] = ()
    final_origin: str | None = None
    http_version: str | None = None
    final_url: str | None = field(default=None, repr=False)

    def to_dict(self, redactor: EvidenceRedactor) -> dict[str, object]:
        header_fingerprints: dict[str, list[dict[str, object]]] = {}
        for name, values in self.headers.items():
            public_name = redactor.header_name(name)
            header_fingerprints[public_name] = [
                {
                    "length": redactor.size(len(value)),
                    "fingerprint": redactor.fingerprint(
                        f"{name}\0{value}", label="response-header"
                    ),
                }
                for value in values
            ]
        payload: dict[str, object] = {
            "arm": self.arm,
            "round": self.round_index,
            "sequence": self.sequence,
            "outcome": self.outcome,
            "status": self.status,
            "body_length_observed": redactor.size(self.length),
            "body_length_complete": self.body_digest_complete,
            "body_fingerprint": redactor.fingerprint(
                self.body_sha256, label="response-body-digest"
            ),
            "body_digest_complete": self.body_digest_complete,
            "body_retained_complete": self.body_retained_complete,
            "body_comparator_eligible": self.body_comparator_eligible,
            "body_comparator_charset": self.body_comparator_charset,
            "body_comparator_reasons": list(self.body_comparator_reasons),
            "elapsed": redactor.elapsed_ms(self.elapsed_ms),
            "attempts": self.attempts,
            "attempt_trace": [
                attempt.to_dict(redactor) for attempt in self.attempt_trace
            ],
            "evidence_header_fingerprints": header_fingerprints,
        }
        if self.error_type:
            payload["error_type"] = self.error_type
        if self.final_origin:
            payload["final_origin"] = redactor.origin(self.final_origin)
        if self.redirect_chain:
            payload["redirect_chain"] = [
                {
                    "status": hop.status,
                    "method": hop.method,
                    "origin": redactor.origin(hop.origin),
                    "target_origin": redactor.origin(hop.target_origin),
                    "raw_location_fingerprint": (
                        redactor.fingerprint(hop.location, label="redirect-location")
                        if hop.location is not None
                        else None
                    ),
                    "normalized_resolved_target": _public_redirect_target(hop, redactor),
                    "cross_origin": hop.cross_origin,
                    "method_changed": hop.method_changed,
                    "credential_forwarding": hop.credential_forwarding,
                }
                for hop in self.redirect_chain
            ]
        if self.http_version:
            payload["http_version"] = self.http_version
        return payload


@dataclass(frozen=True)
class PairEvidence:
    round_index: int
    classification: str
    status_changed: bool
    body_changed: bool | None
    outcome_changed: bool
    redirect_changed: bool
    retry_changed: bool
    similarity: float | None
    length_delta_ratio: float | None
    header_diffs: tuple[str, ...]
    redirect_diffs: tuple[str, ...]
    attempt_diffs: tuple[str, ...]
    comparator: str
    attempt_elapsed_delta_ms: float | None = None
    backoff_delta_ms: float | None = None
    comparator_resource_limit: str | None = None
    normalization_outcomes: tuple[NormalizationOutcome, ...] = ()

    @property
    def changed(self) -> bool:
        return self.classification == PAIR_CHANGED

    @property
    def indeterminate(self) -> bool:
        return self.classification == PAIR_INDETERMINATE

    def to_dict(self, redactor: EvidenceRedactor) -> dict[str, object]:
        return {
            "round": self.round_index,
            "classification": self.classification,
            "status_changed": self.status_changed,
            "body_changed": self.body_changed,
            "outcome_changed": self.outcome_changed,
            "redirect_changed": self.redirect_changed,
            "retry_changed": self.retry_changed,
            "similarity": self.similarity,
            "length_delta_ratio": self.length_delta_ratio,
            "header_diffs": [redactor.header_name(name) for name in self.header_diffs],
            "redirect_diffs": list(self.redirect_diffs),
            "attempt_diffs": list(self.attempt_diffs),
            "comparator": self.comparator,
            "attempt_elapsed_delta": _public_timing_delta(
                self.attempt_elapsed_delta_ms, redactor
            ),
            "backoff_delta": _public_timing_delta(self.backoff_delta_ms, redactor),
        }


@dataclass
class ExperimentResult:
    verdict: str
    stop_reason: str
    rounds: int
    schedule_seed: int | None
    schedule: list[tuple[str, ...]]
    mutation_changes: int
    mutation_indeterminate: int
    mutation_change_rate: float
    mutation_change_interval_95: tuple[float, float]
    control_changes: int
    control_indeterminate: int
    control_comparisons: int
    control_change_rate: float
    control_change_interval_95: tuple[float, float]
    control_similarity_median: float | None
    mutation_similarity_median: float | None
    similarity_contrast: float | None
    status_shift_rounds: int
    outcome_shift_rounds: int
    redirect_shift_rounds: int
    retry_shift_rounds: int
    header_shift_counts: dict[str, int]
    outcome_counts: dict[str, int]
    reasons: list[str]
    pairs: list[PairEvidence]
    observations: list[Observation]
    effective_policy: EffectiveEquivalencePolicy
    config: ExperimentConfig = field(repr=False)

    def to_dict(self) -> dict[str, object]:
        redactor = self.config.redactor
        _, planned_rounds = self.config.round_limits()
        planned_control_comparisons = (
            planned_rounds
            if self.config.schedule_mode == "bracketed"
            else max(planned_rounds - 1, 0)
        )
        public_policy = self.effective_policy.to_dict()
        public_policy["ignore_headers"] = [
            redactor.header_name(name) for name in self.effective_policy.ignore_headers
        ]
        public_policy["ignore_body_regex"] = (
            list(self.effective_policy.ignore_body_regex)
            if redactor.policy == "forensic"
            else [
                redactor.fingerprint(pattern, label="ignore-body-regex")
                for pattern in self.effective_policy.ignore_body_regex
            ]
        )
        decision_headers = _decision_response_headers(self.config, self.effective_policy)
        return {
            "verdict": self.verdict,
            "stop_reason": self.stop_reason,
            "design": {
                "planned_rounds": planned_rounds,
                "completed_rounds": self.rounds,
                "schedule": (
                    "locally bracketed C-before/M/C-after"
                    if self.config.schedule_mode == "bracketed"
                    else "seeded randomized balanced AB/BA blocks"
                ),
                "schedule_seed": self.schedule_seed,
                "arm_order": [list(order) for order in self.schedule],
                "mutation_observations": self.rounds,
                "control_observations": sum(
                    item.arm.startswith("control") for item in self.observations
                ),
                "control_comparisons": self.control_comparisons,
                "state_mode": self.config.state_mode,
                "connection_mode": self.config.connection_mode,
                "assurance_preset": self.config.assurance_preset,
                "body_storage": self.config.body_storage,
                "max_response_bytes": self.config.max_response_bytes,
                "missing_content_type_policy": (
                    "assume-text"
                    if self.config.assume_text_without_content_type
                    else "digest-only"
                ),
                "response_header_policy": {
                    "scope": self.config.response_header_scope,
                    "decision_headers": [
                        redactor.header_name(name) for name in decision_headers
                    ],
                    "omitted_headers_possible": True,
                },
                "operating_characteristics": operating_characteristics(
                    planned_rounds,
                    self.config.min_reproducibility,
                    self.config.no_influence_threshold,
                    self.config.max_control_change_rate,
                    planned_control_comparisons,
                ),
            },
            "effective_equivalence_policy": public_policy,
            "reproducibility": {
                "changed_rounds": self.mutation_changes,
                "indeterminate_rounds": self.mutation_indeterminate,
                "rate": self.mutation_change_rate,
                "wilson_interval_95": list(self.mutation_change_interval_95),
            },
            "control_stability": {
                "changed_comparisons": self.control_changes,
                "indeterminate_comparisons": self.control_indeterminate,
                "rate": self.control_change_rate,
                "wilson_interval_95": list(self.control_change_interval_95),
                "median_similarity": self.control_similarity_median,
            },
            "effect": {
                "mutation_median_similarity": self.mutation_similarity_median,
                "control_minus_mutation_similarity": self.similarity_contrast,
                "status_shift_rounds": self.status_shift_rounds,
                "outcome_shift_rounds": self.outcome_shift_rounds,
                "redirect_shift_rounds": self.redirect_shift_rounds,
                "retry_shift_rounds": self.retry_shift_rounds,
                "response_header_shift_counts": {
                    redactor.header_name(name): count
                    for name, count in self.header_shift_counts.items()
                },
                "outcome_counts": self.outcome_counts,
                "retry_timing": {
                    "attempt_elapsed": _timing_summary(
                        self.pairs, "attempt_elapsed_delta_ms", redactor
                    ),
                    "configured_backoff": _timing_summary(
                        self.pairs, "backoff_delta_ms", redactor
                    ),
                },
            },
            "assurance_profile": _assurance_profile(self),
            "limitations": _limitations(self),
            "reasons": self.reasons,
            "round_evidence": [pair.to_dict(redactor) for pair in self.pairs],
            "observations": [item.to_dict(redactor) for item in self.observations],
        }


def wilson_interval(successes: int, total: int, z: float = 1.96) -> tuple[float, float]:
    if total <= 0:
        return (0.0, 1.0)
    proportion = successes / total
    denominator = 1 + (z**2 / total)
    centre = proportion + (z**2 / (2 * total))
    margin = z * math.sqrt(
        (proportion * (1 - proportion) / total) + (z**2 / (4 * total**2))
    )
    lower = 0.0 if successes == 0 else max(0.0, (centre - margin) / denominator)
    upper = 1.0 if successes == total else min(1.0, (centre + margin) / denominator)
    return (lower, upper)


def operating_characteristics(
    rounds: int,
    influence_threshold: float,
    no_influence_threshold: float,
    control_threshold: float,
    control_comparisons: int | None = None,
) -> dict[str, int | float | None]:
    """Return the predeclared fixed-sample counts capable of decisive bounds."""
    positive = next(
        (
            changed
            for changed in range(rounds + 1)
            if wilson_interval(changed, rounds)[0] >= influence_threshold
        ),
        None,
    )
    negative_values = [
        changed
        for changed in range(rounds + 1)
        if wilson_interval(changed, rounds)[1] <= no_influence_threshold
    ]
    control_total = rounds if control_comparisons is None else control_comparisons
    stable_control_values = [
        changed
        for changed in range(control_total + 1)
        if wilson_interval(changed, control_total)[1] <= control_threshold
    ]
    return {
        "rounds": rounds,
        "control_comparisons": control_total,
        "confidence": 0.95,
        "positive_min_changed": positive,
        "negative_max_changed": max(negative_values) if negative_values else None,
        "control_max_changed": max(stable_control_values) if stable_control_values else None,
    }


def _header_items(headers: object) -> Iterable[tuple[str, str]]:
    if hasattr(headers, "multi_items"):
        return ((str(name), str(value)) for name, value in headers.multi_items())
    if isinstance(headers, Mapping):
        return ((str(name), str(value)) for name, value in headers.items())
    if isinstance(headers, Iterable):
        return ((str(name), str(value)) for name, value in headers)
    return ()


def _normalized_headers(
    headers: object,
    ignored: set[str],
    evidence_names: set[str],
) -> dict[str, tuple[str, ...]]:
    selected: dict[str, list[str]] = {}
    for raw_name, value in _header_items(headers):
        name = raw_name.lower()
        if name in evidence_names and name not in ignored:
            selected.setdefault(name, []).append(value)
    return {name: tuple(values) for name, values in selected.items()}


def _decision_response_headers(
    cfg: ExperimentConfig,
    policy: EffectiveEquivalencePolicy,
) -> tuple[str, ...]:
    selected = (
        set(EVIDENCE_RESPONSE_HEADERS)
        if cfg.response_header_scope == "known"
        else set(BODY_SAFETY_HEADERS)
    )
    selected.update(name.strip().lower() for name in cfg.include_response_headers)
    selected.difference_update(name.lower() for name in policy.ignore_headers)
    return tuple(sorted(selected))


def _exception_chain(exc: BaseException) -> Iterable[BaseException]:
    current: BaseException | None = exc
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        yield current
        current = current.__cause__ or current.__context__


def classify_transport_error(exc: BaseException) -> str:
    chain = tuple(_exception_chain(exc))
    if any(isinstance(item, httpx.TimeoutException) for item in chain):
        return TIMEOUT
    if any(isinstance(item, ssl.SSLError) for item in chain):
        return TLS_ERROR
    if any(isinstance(item, socket.gaierror) for item in chain):
        return DNS_ERROR
    if any(isinstance(item, (ConnectionResetError, BrokenPipeError)) for item in chain):
        return CONNECTION_RESET
    if any(isinstance(item, httpx.ProtocolError) for item in chain):
        return PROTOCOL_ERROR
    return TRANSPORT_ERROR


def _attempt_from_record(record: AttemptRecord) -> AttemptEvidence:
    response = record.response
    error = record.error
    if error is not None or response is None:
        outcome = classify_transport_error(error or RuntimeError("missing response"))
        status = None
    else:
        captured = response if isinstance(response, CapturedResponse) else None
        outcome = POLICY_ABORT if captured and captured.response_limit_exceeded else HTTP_RESPONSE
        status = int(getattr(response, "status_code"))
    return AttemptEvidence(
        attempt=record.attempt,
        outcome=outcome,
        status=status,
        elapsed_ms=record.elapsed_ms,
        retry_reason=record.retry_reason,
        backoff_ms=record.backoff_ms,
        error_type=type(error).__name__ if error is not None else None,
    )


def _sender_supports_context(sender: Callable[..., object]) -> bool:
    try:
        parameters = inspect.signature(sender).parameters.values()
    except (TypeError, ValueError):
        return False
    return any(parameter.kind == inspect.Parameter.VAR_KEYWORD for parameter in parameters) or {
        "round_index",
        "sequence",
    }.issubset(parameter.name for parameter in parameters)


def _observe(
    arm: str,
    round_index: int,
    sequence: int,
    req: RawRequest,
    sender: Callable[..., object],
    policy: EffectiveEquivalencePolicy,
    sender_supports_context: bool,
    evidence_names: set[str],
    assume_text_without_content_type: bool,
) -> Observation:
    started = time.perf_counter()
    attempts = 1
    response: object | None = None
    error: BaseException | None = None
    attempt_trace: tuple[AttemptEvidence, ...] = ()
    try:
        sent = (
            sender(arm, req, round_index=round_index, sequence=sequence)
            if sender_supports_context
            else sender(arm, req)
        )
        if isinstance(sent, SendOutcome):
            attempts = sent.attempts
            response = sent.response
            error = sent.error
            attempt_trace = tuple(_attempt_from_record(item) for item in sent.attempt_trace)
        else:
            response = sent
    except Exception as exc:
        if getattr(exc, "mrma_fatal_policy_error", False):
            raise
        error = exc
    elapsed_ms = (time.perf_counter() - started) * 1000

    if not attempt_trace:
        synthetic = AttemptRecord(
            attempt=attempts,
            response=response,
            error=error if isinstance(error, Exception) else None,
            elapsed_ms=round(elapsed_ms, 3),
            retry_reason=None,
            backoff_ms=None,
        )
        attempt_trace = (_attempt_from_record(synthetic),)

    if error is not None or response is None:
        outcome = classify_transport_error(error or RuntimeError("missing response"))
        return Observation(
            arm=arm,
            round_index=round_index,
            sequence=sequence,
            outcome=outcome,
            status=None,
            length=0,
            body_sha256="",
            body_digest_complete=False,
            body_retained_complete=False,
            elapsed_ms=round(elapsed_ms, 3),
            attempts=attempts,
            headers={},
            body=b"",
            body_comparator_eligible=False,
            body_comparator_reasons=("non-http-outcome",),
            attempt_trace=attempt_trace,
            error_type=type(error).__name__ if error is not None else "MissingResponse",
        )

    body = getattr(response, "content", b"") or b""
    captured = response if isinstance(response, CapturedResponse) else None
    length = captured.body_length if captured else len(body)
    digest = captured.body_sha256 if captured else hashlib.sha256(body).hexdigest()
    digest_complete = captured.body_digest_complete if captured else True
    retained_complete = captured.body_retained_complete if captured else True
    outcome = POLICY_ABORT if captured and captured.response_limit_exceeded else HTTP_RESPONSE
    headers = _normalized_headers(
        getattr(response, "headers", ()),
        set(policy.ignore_headers),
        evidence_names,
    )
    body_eligibility = _body_comparator_eligibility(
        headers,
        body,
        retained_complete,
        assume_text_without_content_type,
    )
    return Observation(
        arm=arm,
        round_index=round_index,
        sequence=sequence,
        outcome=outcome,
        status=int(getattr(response, "status_code")),
        length=length,
        body_sha256=digest,
        body_digest_complete=digest_complete,
        body_retained_complete=retained_complete,
        elapsed_ms=round(elapsed_ms, 3),
        attempts=attempts,
        headers=headers,
        body=body,
        body_comparator_eligible=body_eligibility.eligible,
        body_comparator_charset=body_eligibility.charset,
        body_comparator_reasons=body_eligibility.reasons,
        body_comparator_media_type=body_eligibility.declared_media_type,
        body_comparator_declared_charset=body_eligibility.declared_charset,
        body_comparator_resolution_source=body_eligibility.resolution_source,
        semantic_registry_version=body_eligibility.registry_version,
        attempt_trace=attempt_trace,
        error_type="ResponseLimitExceeded" if outcome == POLICY_ABORT else None,
        redirect_chain=captured.redirect_chain if captured else (),
        final_origin=captured.final_origin if captured else None,
        http_version=captured.http_version if captured else None,
        final_url=captured.final_url if captured else None,
    )


def _header_diffs(a: Observation, b: Observation) -> tuple[str, ...]:
    names = set(a.headers) | set(b.headers)
    return tuple(
        sorted(
            name
            for name in names
            if canonical_header_values(
                name, a.headers.get(name, ()), base_url=a.final_url
            )
            != canonical_header_values(
                name, b.headers.get(name, ()), base_url=b.final_url
            )
        )
    )


def _resolved_redirect_target(hop: RedirectHop) -> str | None:
    if hop.resolved_target:
        return canonical_uri(hop.resolved_target)
    return None


def _public_redirect_target(
    hop: RedirectHop,
    redactor: EvidenceRedactor,
) -> dict[str, object] | None:
    target = _resolved_redirect_target(hop)
    return redactor.url(target) if target is not None else None


def _redirect_diffs(a: Observation, b: Observation) -> tuple[str, ...]:
    fields: tuple[tuple[str, object, object], ...] = (
        ("hop-count", len(a.redirect_chain), len(b.redirect_chain)),
        (
            "status-sequence",
            tuple(hop.status for hop in a.redirect_chain),
            tuple(hop.status for hop in b.redirect_chain),
        ),
        (
            "method-sequence",
            tuple(hop.method for hop in a.redirect_chain),
            tuple(hop.method for hop in b.redirect_chain),
        ),
        (
            "origin-sequence",
            tuple(hop.origin for hop in a.redirect_chain),
            tuple(hop.origin for hop in b.redirect_chain),
        ),
        (
            "target-origin-sequence",
            tuple(hop.target_origin for hop in a.redirect_chain),
            tuple(hop.target_origin for hop in b.redirect_chain),
        ),
        (
            "resolved-target-sequence",
            tuple(_resolved_redirect_target(hop) for hop in a.redirect_chain),
            tuple(_resolved_redirect_target(hop) for hop in b.redirect_chain),
        ),
        (
            "cross-origin-transitions",
            tuple(hop.cross_origin for hop in a.redirect_chain),
            tuple(hop.cross_origin for hop in b.redirect_chain),
        ),
        (
            "method-transformations",
            tuple(hop.method_changed for hop in a.redirect_chain),
            tuple(hop.method_changed for hop in b.redirect_chain),
        ),
        (
            "credential-forwarding",
            tuple(hop.credential_forwarding for hop in a.redirect_chain),
            tuple(hop.credential_forwarding for hop in b.redirect_chain),
        ),
        ("final-origin", a.final_origin, b.final_origin),
    )
    return tuple(name for name, left, right in fields if left != right)


def _attempt_diffs(a: Observation, b: Observation) -> tuple[str, ...]:
    intermediate_a = a.attempt_trace[:-1]
    intermediate_b = b.attempt_trace[:-1]
    fields: tuple[tuple[str, object, object], ...] = (
        ("attempt-count", a.attempts, b.attempts),
        (
            "outcome-sequence",
            tuple(item.outcome for item in intermediate_a),
            tuple(item.outcome for item in intermediate_b),
        ),
        (
            "status-sequence",
            tuple(item.status for item in intermediate_a),
            tuple(item.status for item in intermediate_b),
        ),
        (
            "retry-reason-sequence",
            tuple(item.retry_reason for item in intermediate_a),
            tuple(item.retry_reason for item in intermediate_b),
        ),
        (
            "error-type-sequence",
            tuple(item.error_type for item in a.attempt_trace),
            tuple(item.error_type for item in b.attempt_trace),
        ),
    )
    return tuple(name for name, left, right in fields if left != right)


def _attempt_timing_delta(
    a: Observation,
    b: Observation,
    attribute: str,
) -> float:
    left = sum(float(getattr(item, attribute) or 0.0) for item in a.attempt_trace)
    right = sum(float(getattr(item, attribute) or 0.0) for item in b.attempt_trace)
    return round(right - left, 3)


def _public_timing_delta(
    value: float | None,
    redactor: EvidenceRedactor,
) -> dict[str, object] | None:
    if value is None:
        return None
    direction = "equal" if value == 0 else "mutation-higher" if value > 0 else "mutation-lower"
    return {
        "direction": direction,
        "magnitude": redactor.elapsed_ms(abs(value)),
    }


def _timing_summary(
    pairs: list[PairEvidence],
    attribute: str,
    redactor: EvidenceRedactor,
) -> dict[str, object]:
    values = [
        float(value)
        for pair in pairs
        if (value := getattr(pair, attribute)) is not None
    ]
    if not values:
        return {
            "samples": 0,
            "median_delta": None,
            "median_absolute_deviation": None,
            "direction_consistency": None,
            "decision_role": "contextual",
        }
    center = float(median(values))
    deviation = float(median(abs(value - center) for value in values))
    positive = sum(value > 0 for value in values)
    negative = sum(value < 0 for value in values)
    equal = len(values) - positive - negative
    return {
        "samples": len(values),
        "median_delta": _public_timing_delta(center, redactor),
        "median_absolute_deviation": redactor.elapsed_ms(deviation),
        "direction_consistency": round(max(positive, negative, equal) / len(values), 6),
        "decision_role": "contextual",
    }


def _body_comparator_eligibility(
    headers: Mapping[str, tuple[str, ...]],
    body: bytes,
    body_retained_complete: bool,
    assume_text_without_content_type: bool,
) -> BodyComparatorEligibility:
    reasons: list[str] = []
    if not body_retained_complete:
        reasons.append("body-not-retained")
    encodings = headers.get("content-encoding", ())
    if any(value.strip().lower() not in {"", "identity"} for value in encodings):
        reasons.append("unsupported-content-encoding")

    resolution = resolve_charset(
        headers.get("content-type", ()),
        body,
        assume_text_without_content_type=assume_text_without_content_type,
    )
    reasons.extend(resolution.reasons)
    unique_reasons = tuple(dict.fromkeys(reasons))
    return BodyComparatorEligibility(
        not unique_reasons and resolution.eligible,
        resolution.resolved_charset if not unique_reasons else None,
        unique_reasons,
        resolution.declared_media_type,
        resolution.declared_charset,
        resolution.resolution_source,
        resolution.registry_version,
    )


def _comparison_body(item: Observation) -> bytes:
    charset = item.body_comparator_charset
    if charset is None:
        raise ValueError("comparison body has no resolved charset")
    decoder = {
        "us-ascii": "ascii",
        "iso-8859-1": "iso-8859-1",
        "utf-16le": "utf-16-le",
        "utf-16be": "utf-16-be",
    }.get(charset, charset)
    text = item.body.decode(decoder, errors="strict")
    if text.startswith("\ufeff"):
        text = text[1:]
    return text.encode("utf-8")


def _compare(
    a: Observation,
    b: Observation,
    policy: EffectiveEquivalencePolicy,
) -> PairEvidence:
    header_diffs = _header_diffs(a, b)
    redirect_diffs = _redirect_diffs(a, b)
    attempt_diffs = _attempt_diffs(a, b)
    attempt_elapsed_delta_ms = _attempt_timing_delta(a, b, "elapsed_ms")
    backoff_delta_ms = _attempt_timing_delta(a, b, "backoff_ms")
    status_changed = a.status != b.status
    outcome_changed = a.outcome != b.outcome
    redirect_changed = bool(redirect_diffs)
    retry_changed = bool(attempt_diffs)
    decisive_change = outcome_changed or (status_changed and policy.require_same_status) or bool(
        header_diffs
    ) or redirect_changed or retry_changed

    if a.outcome != HTTP_RESPONSE or b.outcome != HTTP_RESPONSE:
        return PairEvidence(
            round_index=b.round_index,
            classification=PAIR_CHANGED if decisive_change else PAIR_UNCHANGED,
            status_changed=status_changed,
            body_changed=None,
            outcome_changed=outcome_changed,
            redirect_changed=redirect_changed,
            retry_changed=retry_changed,
            similarity=None,
            length_delta_ratio=None,
            header_diffs=header_diffs,
            redirect_diffs=redirect_diffs,
            attempt_diffs=attempt_diffs,
            comparator="outcome",
            attempt_elapsed_delta_ms=attempt_elapsed_delta_ms,
            backoff_delta_ms=backoff_delta_ms,
        )

    if a.body_comparator_eligible and b.body_comparator_eligible:
        comparison = equivalent_response(
            a.status or 0,
            _comparison_body(a),
            b.status or 0,
            _comparison_body(b),
            policy,
        )
        length_delta_ratio = abs(comparison.len_b - comparison.len_a) / max(comparison.len_a, 1)
        if not comparison.completed:
            return PairEvidence(
                round_index=b.round_index,
                classification=PAIR_CHANGED if decisive_change else PAIR_INDETERMINATE,
                status_changed=status_changed,
                body_changed=None,
                outcome_changed=outcome_changed,
                redirect_changed=redirect_changed,
                retry_changed=retry_changed,
                similarity=None,
                length_delta_ratio=round(length_delta_ratio, 6),
                header_diffs=header_diffs,
                redirect_diffs=redirect_diffs,
                attempt_diffs=attempt_diffs,
                comparator=comparison.comparator,
                attempt_elapsed_delta_ms=attempt_elapsed_delta_ms,
                backoff_delta_ms=backoff_delta_ms,
                comparator_resource_limit=comparison.resource_limit,
                normalization_outcomes=comparison.normalization_outcomes,
            )
        raw_complete_difference = (
            a.body_digest_complete
            and b.body_digest_complete
            and (a.length != b.length or a.body_sha256 != b.body_sha256)
        )
        body_changed: bool | None = comparison.sim < policy.min_similarity or (
            length_delta_ratio > policy.max_len_delta_ratio
        )
        if decisive_change or not comparison.equivalent:
            classification = PAIR_CHANGED
        elif raw_complete_difference:
            classification = PAIR_INDETERMINATE
            body_changed = None
        else:
            classification = PAIR_UNCHANGED
        return PairEvidence(
            round_index=b.round_index,
            classification=classification,
            status_changed=status_changed,
            body_changed=body_changed,
            outcome_changed=outcome_changed,
            redirect_changed=redirect_changed,
            retry_changed=retry_changed,
            similarity=round(comparison.sim, 6),
            length_delta_ratio=round(length_delta_ratio, 6),
            header_diffs=header_diffs,
            redirect_diffs=redirect_diffs,
            attempt_diffs=attempt_diffs,
            comparator=comparison.comparator,
            attempt_elapsed_delta_ms=attempt_elapsed_delta_ms,
            backoff_delta_ms=backoff_delta_ms,
            normalization_outcomes=comparison.normalization_outcomes,
        )

    exact_digest_match = (
        a.body_digest_complete
        and b.body_digest_complete
        and a.length == b.length
        and a.body_sha256 == b.body_sha256
    )
    if decisive_change:
        classification = PAIR_CHANGED
    elif exact_digest_match:
        classification = PAIR_UNCHANGED
    else:
        classification = PAIR_INDETERMINATE
    return PairEvidence(
        round_index=b.round_index,
        classification=classification,
        status_changed=status_changed,
        body_changed=False if exact_digest_match else None,
        outcome_changed=outcome_changed,
        redirect_changed=redirect_changed,
        retry_changed=retry_changed,
        similarity=1.0 if exact_digest_match else None,
        length_delta_ratio=(
            round(abs(b.length - a.length) / max(a.length, 1), 6)
            if a.body_digest_complete and b.body_digest_complete
            else None
        ),
        header_diffs=header_diffs,
        redirect_diffs=redirect_diffs,
        attempt_diffs=attempt_diffs,
        comparator="exact-digest" if exact_digest_match else "bounded-incomplete",
        attempt_elapsed_delta_ms=attempt_elapsed_delta_ms,
        backoff_delta_ms=backoff_delta_ms,
    )


def _combine_bracket(
    round_index: int,
    control_pair: PairEvidence,
    before_mutation: PairEvidence,
    after_mutation: PairEvidence,
) -> PairEvidence:
    mutation_diffs = set(before_mutation.header_diffs) & set(after_mutation.header_diffs)
    redirect_diffs = set(before_mutation.redirect_diffs) & set(after_mutation.redirect_diffs)
    attempt_diffs = set(before_mutation.attempt_diffs) & set(after_mutation.attempt_diffs)
    if control_pair.classification != PAIR_UNCHANGED:
        classification = PAIR_INDETERMINATE
    elif before_mutation.changed and after_mutation.changed:
        classification = PAIR_CHANGED
    elif (
        before_mutation.classification == PAIR_UNCHANGED
        and after_mutation.classification == PAIR_UNCHANGED
    ):
        classification = PAIR_UNCHANGED
    else:
        classification = PAIR_INDETERMINATE

    similarities = [
        value
        for value in (before_mutation.similarity, after_mutation.similarity)
        if value is not None
    ]
    length_deltas = [
        value
        for value in (before_mutation.length_delta_ratio, after_mutation.length_delta_ratio)
        if value is not None
    ]

    def bracket_delta(first: float | None, second: float | None) -> float | None:
        if first is None or second is None:
            return None
        if first and second and (first > 0) != (second > 0):
            return None
        return round(float(median((first, second))), 3)

    return PairEvidence(
        round_index=round_index,
        classification=classification,
        status_changed=before_mutation.status_changed and after_mutation.status_changed,
        body_changed=(
            True
            if before_mutation.body_changed is True and after_mutation.body_changed is True
            else False
            if before_mutation.body_changed is False and after_mutation.body_changed is False
            else None
        ),
        outcome_changed=before_mutation.outcome_changed and after_mutation.outcome_changed,
        redirect_changed=before_mutation.redirect_changed and after_mutation.redirect_changed,
        retry_changed=before_mutation.retry_changed and after_mutation.retry_changed,
        similarity=max(similarities) if similarities else None,
        length_delta_ratio=min(length_deltas) if length_deltas else None,
        header_diffs=tuple(sorted(mutation_diffs)),
        redirect_diffs=tuple(sorted(redirect_diffs)),
        attempt_diffs=tuple(sorted(attempt_diffs)),
        comparator=f"bracketed:{before_mutation.comparator}/{after_mutation.comparator}",
        attempt_elapsed_delta_ms=bracket_delta(
            before_mutation.attempt_elapsed_delta_ms,
            after_mutation.attempt_elapsed_delta_ms,
        ),
        backoff_delta_ms=bracket_delta(
            before_mutation.backoff_delta_ms,
            after_mutation.backoff_delta_ms,
        ),
    )


def _median_similarity(pairs: list[PairEvidence]) -> float | None:
    values = [pair.similarity for pair in pairs if pair.similarity is not None]
    return round(median(values), 6) if values else None


def _effect_types(result: ExperimentResult) -> list[str]:
    effects: list[str] = []
    if result.status_shift_rounds:
        effects.append("status")
    if any(pair.body_changed is True for pair in result.pairs):
        effects.append("body")
    if result.header_shift_counts:
        effects.append("response-header")
    if result.outcome_shift_rounds:
        effects.append("transport-outcome")
    if result.redirect_shift_rounds:
        effects.append("redirect-trace")
    if result.retry_shift_rounds:
        effects.append("retry-trace")
    return effects


def _normalization_risk(result: ExperimentResult) -> str:
    return (
        "elevated"
        if result.effective_policy.ignore_headers
        or result.effective_policy.ignore_body_regex
        or result.effective_policy.preset != "default"
        else "low"
    )


def _assurance_profile(result: ExperimentResult) -> dict[str, object]:
    has_transport_outcome = any(item.outcome != HTTP_RESPONSE for item in result.observations)
    controls_complete = all(
        item.outcome == HTTP_RESPONSE
        for item in result.observations
        if item.arm.startswith("control")
    )
    has_incomplete_body = any(
        not item.body_digest_complete or not item.body_retained_complete
        for item in result.observations
    )
    connection_independence = {
        "fresh-observation": "strong",
        "per-round": "moderate",
        "per-arm": "limited",
        "reuse": "limited",
    }[result.config.connection_mode]
    state_isolation = {
        "isolated": "strong",
        "per-arm": "moderate",
        "shared-session": "limited",
    }[result.config.state_mode]
    return {
        "statistical_decisiveness": (
            "strong" if result.verdict != "INCONCLUSIVE" else "limited"
        ),
        "control_stability": (
            "strong"
            if controls_complete
            and result.control_change_interval_95[1]
            <= result.config.max_control_change_rate
            and result.control_indeterminate == 0
            else "limited"
        ),
        "connection_independence": connection_independence,
        "state_isolation": state_isolation,
        "body_completeness": "bounded" if has_incomplete_body else "complete",
        "normalization_risk": _normalization_risk(result),
        "transport_reproducibility": (
            "moderate"
            if has_transport_outcome or result.config.trust_environment
            else "strong"
        ),
        "transport_integrity": (
            "limited"
            if result.config.tls_verification == "disabled"
            else "moderate"
            if result.config.trust_environment
            else "strong"
        ),
        "response_header_coverage": "limited",
        "effect_types": _effect_types(result),
        "reproduction_completeness": (
            "strong"
            if result.mutation_indeterminate == 0
            else "limited"
        ),
    }


def _limitation(
    code: str,
    severity: str,
    scope: str,
    message: str,
    remediation: str,
) -> dict[str, str]:
    return {
        "code": code,
        "severity": severity,
        "scope": scope,
        "message": message,
        "remediation": remediation,
    }


def _limitations(result: ExperimentResult) -> list[dict[str, str]]:
    limitations: list[dict[str, str]] = []
    if result.config.tls_verification == "disabled":
        limitations.append(
            _limitation(
                "TLS_VERIFICATION_DISABLED",
                "high",
                "transport_integrity",
                "TLS peer verification was disabled for this experiment.",
                "Repeat with system verification or an explicit approved CA bundle.",
            )
        )
    if result.config.trust_environment:
        limitations.append(
            _limitation(
                "ENVIRONMENT_TRANSPORT_CONFIGURATION",
                "moderate",
                "transport_reproducibility",
                "HTTPX was allowed to consume proxy or CA configuration from the process environment.",
                "Repeat with trust_environment=false and explicit transport inputs.",
            )
        )
    if result.config.connection_mode != "fresh-observation":
        limitations.append(
            _limitation(
                "CONNECTION_REUSE",
                "low" if result.config.connection_mode == "per-round" else "moderate",
                "statistical_independence",
                f"Connection mode {result.config.connection_mode} can share transport state.",
                "Repeat with connection_mode=fresh-observation.",
            )
        )
    if result.config.state_mode != "isolated":
        limitations.append(
            _limitation(
                "RESPONSE_STATE_REUSE",
                "moderate",
                "state_isolation",
                f"State mode {result.config.state_mode} carries response-derived cookie state.",
                "Repeat with state_mode=isolated.",
            )
        )
    if _normalization_risk(result) == "elevated":
        limitations.append(
            _limitation(
                "ELEVATED_NORMALIZATION",
                "moderate",
                "semantic_comparison",
                "Configured normalization or ignored evidence can suppress real differences.",
                "Confirm the result with the default equivalence policy.",
            )
        )
    if any(
        not item.body_digest_complete or not item.body_retained_complete
        for item in result.observations
    ):
        limitations.append(
            _limitation(
                "BOUNDED_BODY_EVIDENCE",
                "moderate",
                "body_completeness",
                "At least one response body was truncated or not retained completely.",
                "Increase max_response_bytes or use body_storage=full within an approved budget.",
            )
        )
    if any(item.outcome != HTTP_RESPONSE for item in result.observations):
        limitations.append(
            _limitation(
                "TYPED_TRANSPORT_FAILURE",
                "moderate",
                "transport_reproducibility",
                "At least one observation ended as a typed transport or policy outcome.",
                "Repeat from an independent transport environment and compare outcome subtypes.",
            )
        )
    if any(
        hop.resolved_target is None
        for item in result.observations
        for hop in item.redirect_chain
    ):
        limitations.append(
            _limitation(
                "INFERRED_REDIRECT_TARGET",
                "low",
                "redirect_semantics",
                "At least one redirect target was inferred without the actual followed request URL.",
                "Capture redirects through the semantic transport to record resolved targets.",
            )
        )
    if any(
        header_semantic_ambiguities(
            "cache-control", item.headers.get("cache-control", ())
        )
        for item in result.observations
    ):
        limitations.append(
            _limitation(
                "AMBIGUOUS_CACHE_CONTROL",
                "moderate",
                "response_header_equivalence",
                "Duplicate directives or malformed Cache-Control syntax prevented "
                "order-insensitive canonicalization.",
                "Review the ordered response-header evidence and intermediary behavior.",
            )
        )
    content_type_reasons = sorted(
        {
            reason
            for item in result.observations
            for reason in item.body_comparator_reasons
            if reason in CONTENT_TYPE_AMBIGUITY_REASONS
        }
    )
    if content_type_reasons:
        limitations.append(
            _limitation(
                "AMBIGUOUS_CONTENT_TYPE",
                "moderate",
                "body_comparison",
                "Content-Type could not safely enable semantic body comparison: "
                + ", ".join(content_type_reasons)
                + ".",
                "Resolve the origin or intermediary ambiguity before interpreting body semantics.",
            )
        )
    if any(
        "invalid-body-encoding" in item.body_comparator_reasons
        for item in result.observations
    ):
        limitations.append(
            _limitation(
                "INVALID_DECLARED_BODY_ENCODING",
                "moderate",
                "body_comparison",
                "At least one retained body was not valid under its declared text charset.",
                "Correct the declared charset or compare the complete response digest only.",
            )
        )
    comparator_limits = sorted(
        {
            pair.comparator_resource_limit
            for pair in result.pairs
            if pair.comparator_resource_limit is not None
        }
    )
    if comparator_limits:
        limitations.append(
            _limitation(
                "COMPARATOR_RESOURCE_LIMIT",
                "high",
                "semantic_comparison",
                "At least one required comparison exceeded a bounded resource policy: "
                + ", ".join(comparator_limits)
                + ".",
                "Reduce retained input or replace the normalization rule, then repeat independently.",
            )
        )
    if result.config.assume_text_without_content_type:
        limitations.append(
            _limitation(
                "UNDECLARED_CONTENT_TYPE_TEXT_ASSUMPTION",
                "moderate",
                "body_comparison",
                "Responses without Content-Type were explicitly allowed into text comparison.",
                "Repeat with the default digest-only missing Content-Type policy.",
            )
        )
    decision_headers = _decision_response_headers(result.config, result.effective_policy)
    public_headers = ", ".join(
        result.config.redactor.header_name(name) for name in decision_headers
    )
    limitations.append(
        _limitation(
            "SELECTIVE_RESPONSE_HEADER_SCOPE",
            "moderate",
            "response_header_coverage",
            f"Decision-bearing response headers were limited to: {public_headers}.",
            "Add target-specific fields with --include-response-header or repeat under a future stable-header discovery policy.",
        )
    )
    limitations.append(
        _limitation(
            "SEMANTIC_HTTP_TRANSPORT",
            "low",
            "protocol_fidelity",
            "The HTTP client may normalize request syntax and does not preserve wire-exact bytes.",
            "Use a future wire-exact backend when syntax-level behavior is the research target.",
        )
    )
    return limitations


def analyze_experiment(
    observations: list[Observation],
    cfg: ExperimentConfig,
    *,
    schedule_seed: int | None = None,
    schedule: list[tuple[str, ...]] | None = None,
    stop_reason: str = "analysis",
) -> ExperimentResult:
    policy = resolve_equivalence_policy(cfg.equivalence)
    mutations = {item.round_index: item for item in observations if item.arm == "mutation"}
    if cfg.schedule_mode == "bracketed":
        controls_before = {
            item.round_index: item for item in observations if item.arm == "control_before"
        }
        controls_after = {
            item.round_index: item for item in observations if item.arm == "control_after"
        }
        round_ids = sorted(set(controls_before) & set(controls_after) & set(mutations))
        control_pairs = [
            _compare(controls_before[index], controls_after[index], policy)
            for index in round_ids
        ]
        pairs = [
            _combine_bracket(
                index,
                control_pair,
                _compare(controls_before[index], mutations[index], policy),
                _compare(controls_after[index], mutations[index], policy),
            )
            for index, control_pair in zip(round_ids, control_pairs)
        ]
        control_observations = list(controls_before.values()) + list(controls_after.values())
        missing_pairs = not (
            len(controls_before) == len(controls_after) == len(mutations) == len(round_ids)
        )
    else:
        controls = {item.round_index: item for item in observations if item.arm == "control"}
        round_ids = sorted(set(controls) & set(mutations))
        pairs = [_compare(controls[index], mutations[index], policy) for index in round_ids]
        ordered_controls = sorted(controls.values(), key=lambda item: item.sequence)
        control_pairs = [
            _compare(previous, current, policy)
            for previous, current in zip(ordered_controls, ordered_controls[1:])
        ]
        control_observations = list(controls.values())
        missing_pairs = len(controls) != len(mutations) or len(round_ids) != len(controls)

    mutation_changes = sum(pair.changed for pair in pairs)
    mutation_indeterminate = sum(pair.indeterminate for pair in pairs)
    mutation_rate = mutation_changes / len(pairs) if pairs else 0.0
    mutation_interval = wilson_interval(mutation_changes, len(pairs))
    control_changes = sum(pair.changed for pair in control_pairs)
    control_indeterminate = sum(pair.indeterminate for pair in control_pairs)
    control_rate = control_changes / len(control_pairs) if control_pairs else 0.0
    control_interval = wilson_interval(control_changes, len(control_pairs))

    mutation_median = _median_similarity(pairs)
    control_median = _median_similarity(control_pairs)
    similarity_contrast = (
        round(control_median - mutation_median, 6)
        if control_median is not None and mutation_median is not None
        else None
    )

    invalid_controls = any(item.outcome != HTTP_RESPONSE for item in control_observations)
    control_confidently_stable = (
        bool(control_pairs)
        and not invalid_controls
        and control_indeterminate == 0
        and control_interval[1] <= cfg.max_control_change_rate
    )
    control_confidently_unstable = (
        bool(control_pairs) and control_interval[0] > cfg.max_control_change_rate
    )

    if missing_pairs or invalid_controls or control_confidently_unstable:
        verdict = "INCONCLUSIVE"
    elif control_confidently_stable and mutation_interval[0] >= cfg.min_reproducibility:
        verdict = "INFLUENCE_DETECTED"
    elif (
        control_confidently_stable
        and mutation_indeterminate == 0
        and mutation_interval[1] <= cfg.no_influence_threshold
    ):
        verdict = "NO_INFLUENCE_OBSERVED"
    else:
        verdict = "INCONCLUSIVE"

    header_shift_counts: dict[str, int] = {}
    for pair in pairs:
        for name in pair.header_diffs:
            header_shift_counts[name] = header_shift_counts.get(name, 0) + 1

    outcome_counts: dict[str, int] = {}
    for item in observations:
        outcome_counts[item.outcome] = outcome_counts.get(item.outcome, 0) + 1
    status_shift_rounds = sum(pair.status_changed for pair in pairs)
    outcome_shift_rounds = sum(pair.outcome_changed for pair in pairs)
    redirect_shift_rounds = sum(pair.redirect_changed for pair in pairs)
    retry_shift_rounds = sum(pair.retry_changed for pair in pairs)
    reasons = [
        f"{mutation_changes}/{len(pairs)} mutation pairs were classified as changed",
        f"mutation 95% interval is {mutation_interval[0]:.1%}-{mutation_interval[1]:.1%}",
        f"{control_changes}/{len(control_pairs)} repeated-control comparisons changed",
        f"control 95% interval is {control_interval[0]:.1%}-{control_interval[1]:.1%}",
    ]
    if mutation_indeterminate:
        reasons.append(f"{mutation_indeterminate} mutation pairs had incomplete body evidence")
    if invalid_controls:
        reasons.append("At least one control did not produce a complete HTTP response")
    if control_confidently_unstable:
        reasons.append("Control instability confidence bound exceeded the rejection threshold")
    if not control_confidently_stable and not invalid_controls and not control_confidently_unstable:
        reasons.append("Control stability did not reach the required confidence bound")
    if missing_pairs:
        reasons.append("One or more rounds were missing a control or mutation observation")

    return ExperimentResult(
        verdict=verdict,
        stop_reason=stop_reason,
        rounds=len(pairs),
        schedule_seed=schedule_seed,
        schedule=list(schedule or []),
        mutation_changes=mutation_changes,
        mutation_indeterminate=mutation_indeterminate,
        mutation_change_rate=round(mutation_rate, 6),
        mutation_change_interval_95=(
            round(mutation_interval[0], 6),
            round(mutation_interval[1], 6),
        ),
        control_changes=control_changes,
        control_indeterminate=control_indeterminate,
        control_comparisons=len(control_pairs),
        control_change_rate=round(control_rate, 6),
        control_change_interval_95=(
            round(control_interval[0], 6),
            round(control_interval[1], 6),
        ),
        control_similarity_median=control_median,
        mutation_similarity_median=mutation_median,
        similarity_contrast=similarity_contrast,
        status_shift_rounds=status_shift_rounds,
        outcome_shift_rounds=outcome_shift_rounds,
        redirect_shift_rounds=redirect_shift_rounds,
        retry_shift_rounds=retry_shift_rounds,
        header_shift_counts=header_shift_counts,
        outcome_counts=outcome_counts,
        reasons=reasons,
        pairs=pairs,
        observations=observations,
        effective_policy=policy,
        config=cfg,
    )


def _validate_config(cfg: ExperimentConfig) -> tuple[int, int]:
    min_rounds, max_rounds = cfg.round_limits()
    if min_rounds < 6 or max_rounds > 50 or min_rounds > max_rounds:
        raise ValueError("experiments require 6-50 rounds with min_rounds <= max_rounds")
    if not 0.5 < cfg.min_reproducibility <= 1.0:
        raise ValueError("min_reproducibility must be greater than 0.5 and at most 1.0")
    if not 0.0 <= cfg.no_influence_threshold < 0.5:
        raise ValueError("no_influence_threshold must be at least 0 and less than 0.5")
    if cfg.no_influence_threshold >= cfg.min_reproducibility:
        raise ValueError("no_influence_threshold must be below min_reproducibility")
    if not 0.0 <= cfg.max_control_change_rate < 0.5:
        raise ValueError("max_control_change_rate must be at least 0 and less than 0.5")
    if cfg.max_response_bytes <= 0:
        raise ValueError("max_response_bytes must be positive")
    if cfg.body_storage not in {"none", "sample", "full"}:
        raise ValueError("body_storage must be none, sample, or full")
    if cfg.response_header_scope not in RESPONSE_HEADER_SCOPES:
        raise ValueError("response_header_scope must be known, explicit, or all-stable")
    invalid_headers = [
        name
        for name in (*cfg.include_response_headers, *cfg.exclude_response_headers)
        if _HEADER_NAME.fullmatch(name.strip()) is None
    ]
    if invalid_headers:
        raise ValueError(f"invalid response evidence header name: {invalid_headers[0]!r}")
    if len(cfg.include_response_header_patterns) > 32 or any(
        not pattern
        or len(pattern) > 128
        or any(character not in "!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ?*" for character in pattern)
        for pattern in cfg.include_response_header_patterns
    ):
        raise ValueError("response header patterns must be bounded token globs")
    if cfg.response_header_profile not in {None, "routing", "security", "cache"}:
        raise ValueError("response_header_profile must be routing, security, or cache")
    if not 3 <= cfg.stable_header_control_observations <= 10:
        raise ValueError("stable_header_control_observations must be 3-10")
    if cfg.tls_verification not in {"system", "custom-ca", "environment", "disabled"}:
        raise ValueError("tls_verification must be system, custom-ca, environment, or disabled")
    if cfg.proxy_mode not in {"none", "explicit", "environment"}:
        raise ValueError("proxy_mode must be none, explicit, or environment")
    if not cfg.trust_environment and (
        cfg.tls_verification == "environment" or cfg.proxy_mode == "environment"
    ):
        raise ValueError("environment transport modes require trust_environment")
    if cfg.schedule_mode not in {"bracketed", "balanced"}:
        raise ValueError("schedule_mode must be bracketed or balanced")
    if cfg.schedule_mode == "balanced" and (min_rounds % 2 or max_rounds % 2):
        raise ValueError("balanced schedules require even min_rounds and max_rounds")
    if cfg.state_mode not in {"isolated", "per-arm", "shared-session"}:
        raise ValueError("state_mode must be isolated, per-arm, or shared-session")
    if cfg.connection_mode not in {"reuse", "per-arm", "per-round", "fresh-observation"}:
        raise ValueError(
            "connection_mode must be reuse, per-arm, per-round, or fresh-observation"
        )
    if cfg.assurance_preset not in {"custom", "exploratory", "research", "forensic"}:
        raise ValueError("assurance_preset must be custom, exploratory, research, or forensic")
    return min_rounds, max_rounds


def _schedule_blocks(max_rounds: int, seed: int) -> list[tuple[str, ...]]:
    rng = random.Random(seed)
    schedule: list[tuple[str, ...]] = []
    for _ in range(max_rounds // 2):
        block = [("control", "mutation"), ("mutation", "control")]
        rng.shuffle(block)
        schedule.extend(block)
    return schedule


def run_experiment(
    baseline_req: RawRequest,
    mutated_req: RawRequest,
    sender: Callable[..., object],
    cfg: ExperimentConfig,
    on_progress: Callable[[int, int, str], None] | None = None,
    on_observation: Callable[[Observation], None] | None = None,
    should_cancel: Callable[[], bool] | None = None,
) -> ExperimentResult:
    min_rounds, max_rounds = _validate_config(cfg)
    seed = cfg.seed if cfg.seed is not None else secrets.randbits(64)
    full_schedule: list[tuple[str, ...]]
    if cfg.schedule_mode == "bracketed":
        full_schedule = [("control_before", "mutation", "control_after")] * max_rounds
    else:
        full_schedule = _schedule_blocks(max_rounds, seed)
    public_seed = None if cfg.schedule_mode == "bracketed" else seed
    policy = resolve_equivalence_policy(cfg.equivalence)
    evidence_names = set(_decision_response_headers(cfg, policy))
    observations: list[Observation] = []
    sequence = 0
    result: ExperimentResult | None = None
    sender_supports_context = _sender_supports_context(sender)

    for round_index, order in enumerate(full_schedule, start=1):
        for arm in order:
            if should_cancel is not None and should_cancel():
                cancelled = analyze_experiment(
                    observations,
                    cfg,
                    schedule_seed=public_seed,
                    schedule=full_schedule[: round_index - 1],
                    stop_reason="cancelled",
                )
                cancelled.verdict = "INCONCLUSIVE"
                return cancelled
            sequence += 1
            request = mutated_req if arm == "mutation" else baseline_req
            observation = _observe(
                arm,
                round_index,
                sequence,
                request,
                sender,
                policy,
                sender_supports_context,
                evidence_names,
                cfg.assume_text_without_content_type,
            )
            observations.append(observation)
            if on_observation is not None:
                on_observation(observation)
            if on_progress is not None:
                on_progress(sequence, max_rounds * len(order), arm)

        completed_rounds = round_index
        result = analyze_experiment(
            observations,
            cfg,
            schedule_seed=public_seed,
            schedule=full_schedule[:completed_rounds],
            stop_reason="interim",
        )
        if completed_rounds < min_rounds:
            continue
        if any(
            item.arm.startswith("control") and item.outcome != HTTP_RESPONSE
            for item in observations
        ):
            result.stop_reason = "control_failure"
            return result
        control_low = result.control_change_interval_95[0]
        if control_low > cfg.max_control_change_rate:
            result.stop_reason = "control_instability"
            return result

    assert result is not None
    result.stop_reason = (
        "fixed_sample_complete"
        if result.verdict != "INCONCLUSIVE"
        else "maximum_rounds_reached"
    )
    return result
