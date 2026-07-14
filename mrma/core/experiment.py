from __future__ import annotations

import hashlib
import math
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from statistics import median

from .compare import EquivalenceConfig, equivalent_response
from .raw_request import RawRequest

EVIDENCE_RESPONSE_HEADERS = (
    "location",
    "content-location",
    "content-type",
    "cache-control",
    "vary",
    "server",
    "via",
    "x-cache",
    "x-cache-status",
    "cf-cache-status",
    "x-served-by",
    "access-control-allow-origin",
    "access-control-allow-credentials",
)


@dataclass(frozen=True)
class ExperimentConfig:
    rounds: int = 5
    min_reproducibility: float = 0.8
    max_control_change_rate: float = 0.2
    equivalence: EquivalenceConfig = field(default_factory=EquivalenceConfig)


@dataclass
class Observation:
    arm: str
    round_index: int
    sequence: int
    status: int
    length: int
    sha256: str
    elapsed_ms: float
    headers: dict[str, str]
    body: bytes = field(repr=False)

    def to_dict(self) -> dict[str, object]:
        header_fingerprints = {
            name: {
                "length": len(value),
                "sha256": hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest(),
            }
            for name, value in self.headers.items()
        }
        return {
            "arm": self.arm,
            "round": self.round_index,
            "sequence": self.sequence,
            "status": self.status,
            "length": self.length,
            "sha256": self.sha256,
            "elapsed_ms": self.elapsed_ms,
            "evidence_header_fingerprints": header_fingerprints,
        }


@dataclass(frozen=True)
class PairEvidence:
    round_index: int
    changed: bool
    status_changed: bool
    body_changed: bool
    similarity: float
    length_delta_ratio: float
    header_diffs: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "round": self.round_index,
            "changed": self.changed,
            "status_changed": self.status_changed,
            "body_changed": self.body_changed,
            "similarity": self.similarity,
            "length_delta_ratio": self.length_delta_ratio,
            "header_diffs": list(self.header_diffs),
        }


@dataclass
class ExperimentResult:
    verdict: str
    evidence_grade: str
    rounds: int
    mutation_changes: int
    mutation_change_rate: float
    mutation_change_interval_95: tuple[float, float]
    control_changes: int
    control_comparisons: int
    control_change_rate: float
    control_similarity_median: float
    mutation_similarity_median: float
    similarity_contrast: float
    status_shift_rounds: int
    header_shift_counts: dict[str, int]
    reasons: list[str]
    pairs: list[PairEvidence]
    observations: list[Observation]

    def to_dict(self) -> dict[str, object]:
        return {
            "verdict": self.verdict,
            "evidence_grade": self.evidence_grade,
            "design": {
                "rounds": self.rounds,
                "schedule": "counterbalanced AB/BA",
                "mutation_observations": self.rounds,
                "control_observations": self.rounds,
                "control_comparisons": self.control_comparisons,
            },
            "reproducibility": {
                "changed_rounds": self.mutation_changes,
                "rate": self.mutation_change_rate,
                "wilson_interval_95": list(self.mutation_change_interval_95),
            },
            "control_stability": {
                "changed_comparisons": self.control_changes,
                "rate": self.control_change_rate,
                "median_similarity": self.control_similarity_median,
            },
            "effect": {
                "mutation_median_similarity": self.mutation_similarity_median,
                "control_minus_mutation_similarity": self.similarity_contrast,
                "status_shift_rounds": self.status_shift_rounds,
                "response_header_shift_counts": self.header_shift_counts,
            },
            "reasons": self.reasons,
            "round_evidence": [pair.to_dict() for pair in self.pairs],
            "observations": [observation.to_dict() for observation in self.observations],
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
    return (
        max(0.0, (centre - margin) / denominator),
        min(1.0, (centre + margin) / denominator),
    )


def _normalized_headers(headers: Mapping[str, str], ignored: set[str]) -> dict[str, str]:
    lowered = {str(name).lower(): str(value) for name, value in headers.items()}
    return {
        name: lowered[name]
        for name in EVIDENCE_RESPONSE_HEADERS
        if name not in ignored and name in lowered
    }


def _observe(
    arm: str,
    round_index: int,
    sequence: int,
    req: RawRequest,
    sender: Callable[[RawRequest], object],
    ignored_headers: set[str],
) -> Observation:
    started = time.perf_counter()
    response = sender(req)
    elapsed_ms = (time.perf_counter() - started) * 1000
    body = getattr(response, "content", b"") or b""
    headers = getattr(response, "headers", {}) or {}
    return Observation(
        arm=arm,
        round_index=round_index,
        sequence=sequence,
        status=int(getattr(response, "status_code")),
        length=len(body),
        sha256=hashlib.sha256(body).hexdigest(),
        elapsed_ms=round(elapsed_ms, 3),
        headers=_normalized_headers(headers, ignored_headers),
        body=body,
    )


def _header_diffs(a: Observation, b: Observation) -> tuple[str, ...]:
    names = set(a.headers) | set(b.headers)
    return tuple(sorted(name for name in names if a.headers.get(name) != b.headers.get(name)))


def _compare(a: Observation, b: Observation, cfg: EquivalenceConfig) -> PairEvidence:
    comparison = equivalent_response(a.status, a.body, b.status, b.body, cfg)
    length_delta_ratio = abs(comparison.len_b - comparison.len_a) / max(comparison.len_a, 1)
    status_changed = a.status != b.status
    body_changed = comparison.sim < cfg.min_similarity or (
        length_delta_ratio > cfg.max_len_delta_ratio
    )
    header_diffs = _header_diffs(a, b)
    return PairEvidence(
        round_index=b.round_index,
        changed=(not comparison.equivalent) or bool(header_diffs),
        status_changed=status_changed,
        body_changed=body_changed,
        similarity=comparison.sim,
        length_delta_ratio=length_delta_ratio,
        header_diffs=header_diffs,
    )


def _evidence_grade(verdict: str, rounds: int, mutation_rate: float, control_rate: float) -> str:
    if (
        verdict == "INFLUENCE_DETECTED"
        and rounds >= 5
        and mutation_rate == 1.0
        and control_rate == 0.0
    ):
        return "strong"
    if verdict == "INFLUENCE_DETECTED" and rounds >= 3 and control_rate <= 0.2:
        return "moderate"
    if verdict == "NO_INFLUENCE_OBSERVED" and rounds >= 5 and control_rate == 0.0:
        return "moderate"
    return "limited"


def analyze_experiment(
    observations: list[Observation],
    cfg: ExperimentConfig,
) -> ExperimentResult:
    controls = {item.round_index: item for item in observations if item.arm == "control"}
    mutations = {item.round_index: item for item in observations if item.arm == "mutation"}
    round_ids = sorted(set(controls) & set(mutations))
    pairs = [_compare(controls[index], mutations[index], cfg.equivalence) for index in round_ids]

    ordered_controls = [controls[index] for index in sorted(controls)]
    control_pairs = [
        _compare(previous, current, cfg.equivalence)
        for previous, current in zip(ordered_controls, ordered_controls[1:])
    ]

    mutation_changes = sum(pair.changed for pair in pairs)
    mutation_rate = mutation_changes / len(pairs) if pairs else 0.0
    control_changes = sum(pair.changed for pair in control_pairs)
    control_rate = control_changes / len(control_pairs) if control_pairs else 0.0

    mutation_sims = [pair.similarity for pair in pairs] or [1.0]
    control_sims = [pair.similarity for pair in control_pairs] or [1.0]
    mutation_median = median(mutation_sims)
    control_median = median(control_sims)

    if control_rate > cfg.max_control_change_rate:
        verdict = "INCONCLUSIVE"
    elif mutation_rate >= cfg.min_reproducibility:
        verdict = "INFLUENCE_DETECTED"
    elif mutation_rate <= (1 - cfg.min_reproducibility):
        verdict = "NO_INFLUENCE_OBSERVED"
    else:
        verdict = "INCONCLUSIVE"

    header_shift_counts: dict[str, int] = {}
    for pair in pairs:
        for name in pair.header_diffs:
            header_shift_counts[name] = header_shift_counts.get(name, 0) + 1

    status_shift_rounds = sum(pair.status_changed for pair in pairs)
    reasons = [
        f"{mutation_changes}/{len(pairs)} mutation rounds crossed the change threshold",
        f"{control_changes}/{len(control_pairs)} repeated-control comparisons changed",
    ]
    if status_shift_rounds:
        reasons.append(f"HTTP status shifted in {status_shift_rounds}/{len(pairs)} rounds")
    if header_shift_counts:
        strongest = max(header_shift_counts.items(), key=lambda item: item[1])
        reasons.append(
            f"Response header {strongest[0]!r} shifted in {strongest[1]}/{len(pairs)} rounds"
        )
    if verdict == "INCONCLUSIVE" and control_rate > cfg.max_control_change_rate:
        reasons.append("Control instability exceeded the configured rejection threshold")

    interval = wilson_interval(mutation_changes, len(pairs))
    return ExperimentResult(
        verdict=verdict,
        evidence_grade=_evidence_grade(verdict, len(pairs), mutation_rate, control_rate),
        rounds=len(pairs),
        mutation_changes=mutation_changes,
        mutation_change_rate=round(mutation_rate, 6),
        mutation_change_interval_95=(round(interval[0], 6), round(interval[1], 6)),
        control_changes=control_changes,
        control_comparisons=len(control_pairs),
        control_change_rate=round(control_rate, 6),
        control_similarity_median=round(control_median, 6),
        mutation_similarity_median=round(mutation_median, 6),
        similarity_contrast=round(control_median - mutation_median, 6),
        status_shift_rounds=status_shift_rounds,
        header_shift_counts=header_shift_counts,
        reasons=reasons,
        pairs=pairs,
        observations=observations,
    )


def run_experiment(
    baseline_req: RawRequest,
    mutated_req: RawRequest,
    sender: Callable[[RawRequest], object],
    cfg: ExperimentConfig,
    on_progress: Callable[[int, int, str], None] | None = None,
) -> ExperimentResult:
    if cfg.rounds < 3:
        raise ValueError("experiments require at least 3 rounds")
    if not 0.5 < cfg.min_reproducibility <= 1.0:
        raise ValueError("min_reproducibility must be greater than 0.5 and at most 1.0")
    if not 0.0 <= cfg.max_control_change_rate < 0.5:
        raise ValueError("max_control_change_rate must be at least 0 and less than 0.5")

    ignored_headers = {name.lower() for name in cfg.equivalence.ignore_headers}
    observations: list[Observation] = []
    total = cfg.rounds * 2
    sequence = 0

    for round_index in range(1, cfg.rounds + 1):
        order = ("control", "mutation") if round_index % 2 else ("mutation", "control")
        for arm in order:
            sequence += 1
            request = baseline_req if arm == "control" else mutated_req
            observations.append(
                _observe(
                    arm,
                    round_index,
                    sequence,
                    request,
                    sender,
                    ignored_headers,
                )
            )
            if on_progress is not None:
                on_progress(sequence, total, arm)

    return analyze_experiment(observations, cfg)
