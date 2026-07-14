from __future__ import annotations

import hashlib
import math
import random
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
    equivalent_response,
    resolve_equivalence_policy,
)
from .http_client import CapturedResponse, RedirectHop
from .privacy import EvidenceRedactor
from .raw_request import RawRequest
from .sender import SendOutcome

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
    max_response_bytes: int = 1024 * 1024
    body_storage: str = "sample"
    redactor: EvidenceRedactor = field(default_factory=EvidenceRedactor, repr=False)

    def round_limits(self) -> tuple[int, int]:
        if self.rounds is not None:
            return self.rounds, self.rounds
        return self.min_rounds, self.max_rounds


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
    error_type: str | None = None
    redirect_chain: tuple[RedirectHop, ...] = ()
    final_origin: str | None = None

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
            "body_comparator_eligible": _body_comparator_eligible(self),
            "elapsed": redactor.elapsed_ms(self.elapsed_ms),
            "attempts": self.attempts,
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
                    "location_fingerprint": (
                        redactor.fingerprint(hop.location, label="redirect-location")
                        if hop.location is not None
                        else None
                    ),
                    "cross_origin": hop.cross_origin,
                    "method_changed": hop.method_changed,
                }
                for hop in self.redirect_chain
            ]
        return payload


@dataclass(frozen=True)
class PairEvidence:
    round_index: int
    classification: str
    status_changed: bool
    body_changed: bool | None
    outcome_changed: bool
    similarity: float | None
    length_delta_ratio: float | None
    header_diffs: tuple[str, ...]
    comparator: str

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
            "similarity": self.similarity,
            "length_delta_ratio": self.length_delta_ratio,
            "header_diffs": [redactor.header_name(name) for name in self.header_diffs],
            "comparator": self.comparator,
        }


@dataclass
class ExperimentResult:
    verdict: str
    evidence_grade: str
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
    header_shift_counts: dict[str, int]
    outcome_counts: dict[str, int]
    reasons: list[str]
    pairs: list[PairEvidence]
    observations: list[Observation]
    effective_policy: EffectiveEquivalencePolicy
    config: ExperimentConfig = field(repr=False)

    def to_dict(self) -> dict[str, object]:
        redactor = self.config.redactor
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
        return {
            "verdict": self.verdict,
            "evidence_grade": self.evidence_grade,
            "stop_reason": self.stop_reason,
            "design": {
                "rounds": self.rounds,
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
                "body_storage": self.config.body_storage,
                "max_response_bytes": self.config.max_response_bytes,
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
                "response_header_shift_counts": {
                    redactor.header_name(name): count
                    for name, count in self.header_shift_counts.items()
                },
                "outcome_counts": self.outcome_counts,
            },
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
) -> dict[str, tuple[str, ...]]:
    selected: dict[str, list[str]] = {}
    evidence_names = set(EVIDENCE_RESPONSE_HEADERS)
    for raw_name, value in _header_items(headers):
        name = raw_name.lower()
        if name in evidence_names and name not in ignored:
            selected.setdefault(name, []).append(value)
    return {name: tuple(values) for name, values in selected.items()}


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


def _observe(
    arm: str,
    round_index: int,
    sequence: int,
    req: RawRequest,
    sender: Callable[[str, RawRequest], object],
    policy: EffectiveEquivalencePolicy,
) -> Observation:
    started = time.perf_counter()
    attempts = 1
    response: object | None = None
    error: BaseException | None = None
    try:
        sent = sender(arm, req)
        if isinstance(sent, SendOutcome):
            attempts = sent.attempts
            response = sent.response
            error = sent.error
        else:
            response = sent
    except Exception as exc:
        error = exc
    elapsed_ms = (time.perf_counter() - started) * 1000

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
            error_type=type(error).__name__ if error is not None else "MissingResponse",
        )

    body = getattr(response, "content", b"") or b""
    captured = response if isinstance(response, CapturedResponse) else None
    length = captured.body_length if captured else len(body)
    digest = captured.body_sha256 if captured else hashlib.sha256(body).hexdigest()
    digest_complete = captured.body_digest_complete if captured else True
    retained_complete = captured.body_retained_complete if captured else True
    outcome = POLICY_ABORT if captured and captured.response_limit_exceeded else HTTP_RESPONSE
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
        headers=_normalized_headers(getattr(response, "headers", ()), set(policy.ignore_headers)),
        body=body,
        error_type="ResponseLimitExceeded" if outcome == POLICY_ABORT else None,
        redirect_chain=captured.redirect_chain if captured else (),
        final_origin=captured.final_origin if captured else None,
    )


def _header_diffs(a: Observation, b: Observation) -> tuple[str, ...]:
    names = set(a.headers) | set(b.headers)
    return tuple(sorted(name for name in names if a.headers.get(name) != b.headers.get(name)))


def _body_comparator_eligible(observation: Observation) -> bool:
    if not observation.body_retained_complete:
        return False
    encodings = observation.headers.get("content-encoding", ())
    if any(value.strip().lower() not in {"", "identity"} for value in encodings):
        return False
    content_types = observation.headers.get("content-type", ())
    if not content_types:
        return True
    media_type = content_types[-1].split(";", 1)[0].strip().lower()
    return (
        media_type.startswith("text/")
        or media_type.endswith(("+json", "+xml"))
        or media_type
        in {
            "application/json",
            "application/xml",
            "application/javascript",
            "application/x-javascript",
            "application/x-www-form-urlencoded",
        }
    )


def _compare(
    a: Observation,
    b: Observation,
    policy: EffectiveEquivalencePolicy,
) -> PairEvidence:
    header_diffs = _header_diffs(a, b)
    status_changed = a.status != b.status
    outcome_changed = a.outcome != b.outcome
    decisive_change = outcome_changed or (status_changed and policy.require_same_status) or bool(
        header_diffs
    )

    if a.outcome != HTTP_RESPONSE or b.outcome != HTTP_RESPONSE:
        return PairEvidence(
            round_index=b.round_index,
            classification=PAIR_CHANGED if decisive_change else PAIR_UNCHANGED,
            status_changed=status_changed,
            body_changed=None,
            outcome_changed=outcome_changed,
            similarity=None,
            length_delta_ratio=None,
            header_diffs=header_diffs,
            comparator="outcome",
        )

    if _body_comparator_eligible(a) and _body_comparator_eligible(b):
        comparison = equivalent_response(a.status or 0, a.body, b.status or 0, b.body, policy)
        length_delta_ratio = abs(comparison.len_b - comparison.len_a) / max(comparison.len_a, 1)
        body_changed = comparison.sim < policy.min_similarity or (
            length_delta_ratio > policy.max_len_delta_ratio
        )
        classification = PAIR_CHANGED if decisive_change or not comparison.equivalent else PAIR_UNCHANGED
        return PairEvidence(
            round_index=b.round_index,
            classification=classification,
            status_changed=status_changed,
            body_changed=body_changed,
            outcome_changed=outcome_changed,
            similarity=round(comparison.sim, 6),
            length_delta_ratio=round(length_delta_ratio, 6),
            header_diffs=header_diffs,
            comparator=comparison.comparator,
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
        similarity=1.0 if exact_digest_match else None,
        length_delta_ratio=(
            round(abs(b.length - a.length) / max(a.length, 1), 6)
            if a.body_digest_complete and b.body_digest_complete
            else None
        ),
        header_diffs=header_diffs,
        comparator="exact-digest" if exact_digest_match else "bounded-incomplete",
    )


def _combine_bracket(
    round_index: int,
    control_pair: PairEvidence,
    before_mutation: PairEvidence,
    after_mutation: PairEvidence,
) -> PairEvidence:
    mutation_diffs = set(before_mutation.header_diffs) & set(after_mutation.header_diffs)
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
        similarity=max(similarities) if similarities else None,
        length_delta_ratio=min(length_deltas) if length_deltas else None,
        header_diffs=tuple(sorted(mutation_diffs)),
        comparator=f"bracketed:{before_mutation.comparator}/{after_mutation.comparator}",
    )


def _median_similarity(pairs: list[PairEvidence]) -> float | None:
    values = [pair.similarity for pair in pairs if pair.similarity is not None]
    return round(median(values), 6) if values else None


def _evidence_grade(verdict: str, observations: list[Observation]) -> str:
    if verdict == "INCONCLUSIVE":
        return "limited"
    if any(item.outcome != HTTP_RESPONSE for item in observations):
        return "moderate"
    return "strong"


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
        evidence_grade=_evidence_grade(verdict, observations),
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
    if cfg.schedule_mode not in {"bracketed", "balanced"}:
        raise ValueError("schedule_mode must be bracketed or balanced")
    if cfg.schedule_mode == "balanced" and (min_rounds % 2 or max_rounds % 2):
        raise ValueError("balanced schedules require even min_rounds and max_rounds")
    if cfg.state_mode not in {"isolated", "per-arm", "shared-session"}:
        raise ValueError("state_mode must be isolated, per-arm, or shared-session")
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
    sender: Callable[[str, RawRequest], object],
    cfg: ExperimentConfig,
    on_progress: Callable[[int, int, str], None] | None = None,
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
    observations: list[Observation] = []
    sequence = 0
    result: ExperimentResult | None = None

    for round_index, order in enumerate(full_schedule, start=1):
        for arm in order:
            sequence += 1
            request = mutated_req if arm == "mutation" else baseline_req
            observations.append(
                _observe(arm, round_index, sequence, request, sender, policy)
            )
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
