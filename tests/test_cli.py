import hashlib
import json
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from mrma.cli import (
    _apply_assurance_preset,
    _emit_json_if_requested,
    _experiment_exit_code,
    _redacted_target_metadata,
    _transport_configuration,
    _write_json_atomic,
)
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


def test_research_assurance_preset_selects_independent_bounded_policies():
    args = SimpleNamespace(
        assurance="research",
        connection_mode="reuse",
        state_mode="shared-session",
        retries=3,
        redaction_policy="forensic",
        body_storage="sample",
        schedule="balanced",
        rounds=None,
        trust_environment=True,
    )

    assert _apply_assurance_preset(args) == "research"
    assert args.connection_mode == "fresh-observation"
    assert args.state_mode == "isolated"
    assert args.retries == 0
    assert args.redaction_policy == "standard"
    assert args.body_storage == "full"
    assert args.schedule == "bracketed"
    assert args.rounds == 20
    assert args.trust_environment is False


def test_transport_provenance_fingerprints_sensitive_inputs(monkeypatch):
    for name in (
        "ALL_PROXY",
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "NO_PROXY",
        "all_proxy",
        "https_proxy",
        "http_proxy",
        "no_proxy",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "ssl_cert_file",
        "ssl_cert_dir",
    ):
        monkeypatch.delenv(name, raising=False)
    with tempfile.TemporaryDirectory(prefix="mrma-transport-test-") as directory:
        ca_bundle = Path(directory) / "approved.pem"
        ca_bundle.write_bytes(b"approved-ca")
        args = SimpleNamespace(
            trust_environment=False,
            insecure=False,
            ca_bundle=str(ca_bundle),
            proxy="http://user:secret@proxy.test:8080",
        )
        prepared: list[bytes] = []
        marker = object()
        monkeypatch.setattr(
            "mrma.cli.ssl_context_from_ca_bytes",
            lambda value: prepared.append(value) or marker,
        )

        tls_mode, proxy_mode, evidence, ssl_context, snapshot = (
            _transport_configuration(args, EvidenceRedactor(_key=b"a" * 32))
        )

        assert tls_mode == "custom-ca"
        assert proxy_mode == "explicit"
        assert evidence["tls"]["ca_fingerprint"] == (
            "sha256:" + hashlib.sha256(b"approved-ca").hexdigest()
        )
        assert evidence["proxy"]["endpoint_fingerprint"].startswith("hmac-sha256:")
        assert "secret" not in str(evidence)
        assert str(ca_bundle) not in str(evidence)
        assert prepared == [b"approved-ca"]
        assert ssl_context is marker
        assert snapshot is None


def test_environment_transport_is_opt_in_and_fingerprinted(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://user:secret@proxy.test")
    monkeypatch.setenv("SSL_CERT_FILE", "C:/private/company.pem")
    args = SimpleNamespace(
        trust_environment=True,
        insecure=False,
        ca_bundle=None,
        proxy=None,
    )

    tls_mode, proxy_mode, evidence, ssl_context, snapshot = _transport_configuration(
        args, EvidenceRedactor(_key=b"a" * 32)
    )

    assert (tls_mode, proxy_mode) == ("environment", "environment")
    assert "secret" not in str(evidence)
    assert "company.pem" not in str(evidence)
    assert ssl_context is None
    assert snapshot is not None
    assert dict(snapshot)["HTTPS_PROXY"] == "http://user:secret@proxy.test"
    assert "HTTP_PROXY" in dict(snapshot)


def test_durable_writer_syncs_file_before_replacement(monkeypatch):
    with tempfile.TemporaryDirectory(prefix="mrma-durable-test-") as directory:
        destination = Path(directory) / "evidence.json"
        sync_calls: list[int] = []
        monkeypatch.setattr("mrma.cli.os.fsync", lambda descriptor: sync_calls.append(descriptor))

        _write_json_atomic(destination, {"complete": True}, durable=True)

        assert json.loads(destination.read_text(encoding="utf-8"))["complete"] is True
        assert sync_calls


def test_atomic_writer_preserves_old_document_when_replace_fails(monkeypatch):
    with tempfile.TemporaryDirectory(prefix="mrma-atomic-test-") as directory:
        root = Path(directory)
        destination = root / "evidence.json"
        destination.write_text("old", encoding="utf-8")

        def fail_replace(_source, _destination):
            raise OSError("simulated interruption")

        monkeypatch.setattr("mrma.cli.os.replace", fail_replace)

        with pytest.raises(OSError, match="simulated interruption"):
            _write_json_atomic(destination, {"complete": True}, durable=False)

        assert destination.read_text(encoding="utf-8") == "old"
        assert list(root.glob("*.tmp")) == []
