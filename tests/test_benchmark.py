import json
from importlib.resources import files

from mrma.benchmark import run_benchmark
from mrma.evidence import validate_benchmark_document


def test_loopback_benchmark_corpus_passes_without_false_results():
    result = run_benchmark()

    assert result["passed"] is True
    assert result["case_count"] == 22
    assert result["false_positive_count"] == 0
    assert result["false_negative_count"] == 0
    assert result["request_cost"] > 0


def test_packaged_release_benchmark_is_schema_valid_and_passed():
    baseline = json.loads(
        files("mrma")
        .joinpath("benchmarks", "release-baseline.json")
        .read_text(encoding="utf-8")
    )
    verified = validate_benchmark_document(baseline)

    assert verified["passed"] is True
    assert verified["mrma_version"] == "0.4.5"
    assert verified["case_count"] == 22
    assert all(item["passed"] for item in baseline["cases"])
