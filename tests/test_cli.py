from mrma.cli import _experiment_exit_code, _redacted_target_metadata
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


def test_experiment_exit_codes_are_stable_and_opt_in():
    assert _experiment_exit_code("INFLUENCE_DETECTED", "none") == 0
    assert _experiment_exit_code("INFLUENCE_DETECTED", "influence") == 10
    assert _experiment_exit_code("INCONCLUSIVE", "inconclusive") == 11
    assert _experiment_exit_code("INCONCLUSIVE", "any-signal") == 11
    assert _experiment_exit_code("NO_INFLUENCE_OBSERVED", "any-signal") == 0
