from dataclasses import replace

import pytest

from mrma.core.compare import EquivalenceConfig
from mrma.core.experiment import ExperimentConfig, run_experiment, wilson_interval
from mrma.core.raw_request import RawRequest


class FakeResponse:
    def __init__(self, body: bytes, headers: dict[str, str] | None = None, status: int = 200):
        self.content = body
        self.headers = headers or {"content-type": "text/plain"}
        self.status_code = status


def request(headers: list[tuple[str, str]] | None = None) -> RawRequest:
    return RawRequest("GET", "/", "HTTP/1.1", headers or [("Host", "example.test")], b"")


def has_probe(req: RawRequest) -> bool:
    return any(name.lower() == "x-probe" for name, _ in req.headers)


def test_experiment_detects_reproducible_influence_and_counterbalances_order():
    baseline = request()
    mutated = replace(baseline, headers=baseline.headers + [("X-Probe", "1")])
    observed_arms: list[str] = []

    def sender(req: RawRequest) -> FakeResponse:
        changed = has_probe(req)
        observed_arms.append("mutation" if changed else "control")
        return FakeResponse(b"mutated response" if changed else b"control response")

    result = run_experiment(baseline, mutated, sender, ExperimentConfig(rounds=5))

    assert result.verdict == "INFLUENCE_DETECTED"
    assert result.evidence_grade == "strong"
    assert result.mutation_change_rate == 1.0
    assert result.control_change_rate == 0.0
    assert observed_arms == [
        "control",
        "mutation",
        "mutation",
        "control",
        "control",
        "mutation",
        "mutation",
        "control",
        "control",
        "mutation",
    ]


def test_experiment_detects_header_only_influence():
    baseline = request()
    mutated = replace(baseline, headers=baseline.headers + [("X-Probe", "1")])

    def sender(req: RawRequest) -> FakeResponse:
        location = "/mutated" if has_probe(req) else "/control"
        return FakeResponse(b"same body", {"content-type": "text/plain", "location": location})

    result = run_experiment(baseline, mutated, sender, ExperimentConfig(rounds=5))

    assert result.verdict == "INFLUENCE_DETECTED"
    assert result.header_shift_counts == {"location": 5}
    assert "/mutated" not in str(result.to_dict())
    assert "evidence_header_fingerprints" in str(result.to_dict())


def test_experiment_rejects_unstable_controls():
    baseline = request()
    mutated = replace(baseline, headers=baseline.headers + [("X-Probe", "1")])
    control_count = 0

    def sender(req: RawRequest) -> FakeResponse:
        nonlocal control_count
        if has_probe(req):
            return FakeResponse(b"mutation")
        control_count += 1
        return FakeResponse(f"control variant {control_count}".encode())

    cfg = ExperimentConfig(
        rounds=5,
        equivalence=EquivalenceConfig(min_similarity=0.999, max_len_delta_ratio=0.0),
    )
    result = run_experiment(baseline, mutated, sender, cfg)

    assert result.verdict == "INCONCLUSIVE"
    assert result.control_change_rate == 1.0
    assert any("Control instability" in reason for reason in result.reasons)


def test_experiment_requires_three_rounds():
    with pytest.raises(ValueError, match="at least 3 rounds"):
        run_experiment(request(), request(), lambda _: FakeResponse(b"same"), ExperimentConfig(rounds=2))


def test_wilson_interval_contains_observed_rate():
    low, high = wilson_interval(4, 5)
    assert 0.0 < low < 0.8 < high < 1.0
