import json
import tempfile
from pathlib import Path
from types import SimpleNamespace

from mrma.cli import _emit_json_if_requested, _experiment_exit_code, _redacted_target_metadata
from mrma.core.privacy import EvidenceRedactor
from mrma.core.raw_request import RawRequest


def test_experiment_target_metadata_uses_run_keyed_redaction():
    request = RawRequest(
        method="GET",
        path="/account/private?token=secret",
        http_version="HTTP/1.1",
        headers=[("Host", "example.test")],
        body=b"",
    )
    first = _redacted_target_metadata(
        "https://user:password@example.test:8443",
        request,
        EvidenceRedactor(policy="standard", _key=b"a" * 32),
    )
    second = _redacted_target_metadata(
        "https://user:password@example.test:8443",
        request,
        EvidenceRedactor(policy="standard", _key=b"b" * 32),
    )

    assert "example.test" not in first["origin"]
    assert "account" not in first["path"]
    assert "private" not in first["path"]
    assert "secret" not in str(first)
    assert first["query_fingerprint"].startswith("hmac-sha256:")
    assert first["query_fingerprint"] != second["query_fingerprint"]


def test_forensic_metadata_is_explicitly_less_redacted():
    request = RawRequest("GET", "/account", "HTTP/1.1", [], b"")
    metadata = _redacted_target_metadata(
        "https://example.test",
        request,
        EvidenceRedactor(policy="forensic", _key=b"a" * 32),
    )
    assert metadata["origin"] == "https://example.test"
    assert metadata["path"] == "/account"


def test_run_metadata_precision_follows_privacy_policy():
    timestamp = "2026-07-14T15:38:47.123456+00:00"

    standard = EvidenceRedactor(policy="standard", _key=b"a" * 32)
    strict = EvidenceRedactor(policy="strict", _key=b"a" * 32)
    forensic = EvidenceRedactor(policy="forensic", _key=b"a" * 32)

    assert standard.run_timestamp(timestamp) == "2026-07-14T15:38:00+00:00"
    assert standard.run_duration_ms(12_345) == "5-15 s"
    assert strict.run_timestamp(timestamp) == "2026-07-14"
    assert strict.run_duration_ms(12_345) == "<1 min"
    assert forensic.run_timestamp(timestamp) == timestamp
    assert forensic.run_duration_ms(12_345.6789) == 12_345.679


def test_experiment_exit_codes_are_stable_and_opt_in():
    assert _experiment_exit_code("INFLUENCE_DETECTED", "none") == 0
    assert _experiment_exit_code("INFLUENCE_DETECTED", "influence") == 10
    assert _experiment_exit_code("INCONCLUSIVE", "inconclusive") == 11
    assert _experiment_exit_code("INCONCLUSIVE", "any-signal") == 11
    assert _experiment_exit_code("NO_INFLUENCE_OBSERVED", "any-signal") == 0


def test_json_evidence_file_is_replaced_without_leaving_partial_files():
    with tempfile.TemporaryDirectory(prefix="mrma-test-") as directory:
        root = Path(directory)
        destination = root / "evidence.json"
        destination.write_text("old", encoding="utf-8")

        emitted = _emit_json_if_requested(
            SimpleNamespace(json=True, out_json=str(destination)),
            {"schema_version": "test", "complete": True},
        )

        assert emitted is True
        assert json.loads(destination.read_text(encoding="utf-8"))["complete"] is True
        assert list(root.glob("*.tmp")) == []
