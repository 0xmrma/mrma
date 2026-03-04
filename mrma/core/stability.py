from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from difflib import SequenceMatcher

from .compare import normalize_text


@dataclass
class RunSample:
    status: int
    length: int
    body_text: str


@dataclass
class StabilityReport:
    repeats: int
    status_counts: dict[int, int]
    min_len: int
    max_len: int
    sim_min: float
    sim_avg: float


def _sim(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()


def measure_stability(
    fetch_once: Callable[[], tuple[int, bytes]],
    repeats: int,
    preset: str = "default",
) -> StabilityReport:
    samples: list[RunSample] = []

    for _ in range(repeats):
        status, body = fetch_once()
        text = normalize_text(body) if preset == "dynamic" else body.decode("utf-8", errors="replace")
        samples.append(RunSample(status=status, length=len(body), body_text=text))

    status_counts: dict[int, int] = {}
    for s in samples:
        status_counts[s.status] = status_counts.get(s.status, 0) + 1

    lengths = [s.length for s in samples]
    min_len = min(lengths) if lengths else 0
    max_len = max(lengths) if lengths else 0

    # similarity vs first
    if not samples:
        return StabilityReport(repeats=repeats, status_counts={}, min_len=0, max_len=0, sim_min=1.0, sim_avg=1.0)

    base = samples[0].body_text
    sims = [_sim(base, s.body_text) for s in samples[1:]] or [1.0]
    sim_min = min(sims)
    sim_avg = sum(sims) / len(sims)

    return StabilityReport(
        repeats=repeats,
        status_counts=status_counts,
        min_len=min_len,
        max_len=max_len,
        sim_min=sim_min,
        sim_avg=sim_avg,
    )
