import hashlib
import json
import subprocess
import sys
import threading
import zipfile
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from mrma.evidence import (
    EvidenceIntegrityError,
    create_evidence_bundle,
    verify_evidence,
    verify_evidence_bundle,
    verify_journal,
)
from mrma.evidence import bundle as bundle_module


def _rewrite_bundle(source: Path, destination: Path, mutate) -> None:
    with zipfile.ZipFile(source, "r") as archive:
        entries = {info.filename: archive.read(info) for info in archive.infolist()}
    mutate(entries)
    with zipfile.ZipFile(destination, "w") as archive:
        for name, data in entries.items():
            archive.writestr(name, data)


def _sync_manifest_entry(entries: dict[str, bytes], name: str) -> None:
    manifest = json.loads(entries["manifest.json"])
    for item in manifest["files"]:
        if item["path"] == name:
            item["size"] = len(entries[name])
            item["sha256"] = "sha256:" + hashlib.sha256(entries[name]).hexdigest()
            break
    entries["manifest.json"] = (
        json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    )


class ExperimentHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"mutation" if self.headers.get("X-Probe") == "1" else b"control"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *args):
        return


def test_cli_emits_schema_valid_evidence_and_stable_influence_exit_code(
    tmp_path: Path,
    authorization_payload: dict[str, object],
    monkeypatch,
):
    server = ThreadingHTTPServer(("127.0.0.1", 0), ExperimentHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    authorization_payload["rules"][0]["ports"] = [server.server_port]
    authorization_path = tmp_path / "authorization.json"
    authorization_path.write_text(json.dumps(authorization_payload), encoding="utf-8")
    journal_path = tmp_path / "experiment.journal.jsonl"
    bundle_path = tmp_path / "experiment.zip"
    try:
        url = f"http://127.0.0.1:{server.server_port}/private/path?token=secret"
        process = subprocess.run(
            [
                sys.executable,
                "-c",
                "from mrma.cli import main; main()",
                "experiment",
                "--url",
                url,
                "--set-header",
                "X-Probe: 1",
                "--assurance",
                "research",
                "--ignore-header",
                "date",
                "--authorization",
                str(authorization_path),
                "--journal",
                str(journal_path),
                "--bundle",
                str(bundle_path),
                "--json",
                "--fail-on",
                "influence",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert process.returncode == 10, process.stderr
    payload = json.loads(process.stdout)
    schema = json.loads(
        files("mrma.schemas").joinpath("experiment-v7.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    validator.validate(payload)
    assert payload["schema_version"] == "mrma.experiment/v7"
    assert payload["run"]["verdict"] == "INFLUENCE_DETECTED"
    assert payload["analysis"]["verdict"] == "INFLUENCE_DETECTED"
    assert len(payload["analysis"]["observations"]) == 60
    assert payload["run"]["started_at"].endswith(":00+00:00")
    assert payload["run"]["timestamp_precision"] == "minute"
    assert isinstance(payload["run"]["duration"], str)
    assert payload["transport"]["trust_environment"] is False
    assert payload["transport"]["tls"] == {
        "verification": "system",
        "ca_fingerprint": None,
    }
    assert payload["transport"]["proxy"] == {
        "mode": "none",
        "source": "none",
        "endpoint_fingerprint": None,
    }
    assert payload["authorization"]["validated"] is True
    assert payload["authorization"]["bypass"] is False
    assert payload["budget"]["settled"] is True
    assert payload["journal"]["event_count"] > 0
    assert payload["journal"]["head_digest"] == verify_journal(journal_path)["head_digest"]
    assert payload["experiment_role"]["assurance_preset"] == "research"
    assert payload["transport"]["connection_mode"] == "fresh-observation"
    assert payload["transport"]["wire_exact"] is False
    assert payload["assurance"]["connection_independence"] == "strong"
    assert payload["assurance"]["transport_integrity"] == "strong"
    assert all(
        item["charset_resolution"]["resolved_charset"] == "us-ascii"
        and item["charset_resolution"]["reasons"] == []
        for item in payload["analysis"]["observations"]
    )
    assert all(
        item["code"] != "CONNECTION_REUSE" for item in payload["limitations"]
    )
    assert payload["comparison"]["regex_bounded"] is True
    assert "secret" not in str(payload)
    assert str(tmp_path) not in str(payload)

    verified_bundle = verify_evidence_bundle(bundle_path)
    assert verified_bundle["verified"] is True
    assert verified_bundle["benchmark"]["passed"] is True
    assert verified_bundle["benchmark"]["case_count"] == 22
    second_bundle = tmp_path / "experiment-copy.zip"
    create_evidence_bundle(second_bundle, result=payload, journal_path=journal_path)
    assert bundle_path.read_bytes() == second_bundle.read_bytes()
    assert verify_evidence(second_bundle)["verified"] is True
    assert verify_evidence(journal_path)["verified"] is True
    result_path = tmp_path / "result.json"
    result_path.write_text(json.dumps(payload), encoding="utf-8")
    assert verify_evidence(result_path)["schema_valid"] is True

    digest_tamper = tmp_path / "digest-tamper.zip"
    _rewrite_bundle(
        second_bundle,
        digest_tamper,
        lambda entries: entries.__setitem__("plan.json", b"{}\n"),
    )
    with pytest.raises(EvidenceIntegrityError, match="BUNDLE_DIGEST_MISMATCH"):
        verify_evidence_bundle(digest_tamper)

    schema_tamper = tmp_path / "schema-tamper.zip"

    def tamper_schema(entries: dict[str, bytes]) -> None:
        entries["schema.json"] = entries["schema.json"] + b"\n"
        _sync_manifest_entry(entries, "schema.json")

    _rewrite_bundle(second_bundle, schema_tamper, tamper_schema)
    with pytest.raises(EvidenceIntegrityError, match="INCOMPATIBLE_BUNDLED_SCHEMA"):
        verify_evidence_bundle(schema_tamper)

    plan_tamper = tmp_path / "plan-tamper.zip"

    def tamper_plan(entries: dict[str, bytes]) -> None:
        plan_document = json.loads(entries["plan.json"])
        plan_document["target_count"] += 1
        entries["plan.json"] = json.dumps(plan_document).encode() + b"\n"
        _sync_manifest_entry(entries, "plan.json")

    _rewrite_bundle(second_bundle, plan_tamper, tamper_plan)
    with pytest.raises(EvidenceIntegrityError, match="PLAN_RESULT_MISMATCH"):
        verify_evidence_bundle(plan_tamper)

    authorization_tamper = tmp_path / "authorization-tamper.zip"

    def tamper_authorization(entries: dict[str, bytes]) -> None:
        document = json.loads(entries["authorization.json"])
        document["rule_count"] += 1
        entries["authorization.json"] = json.dumps(document).encode() + b"\n"
        _sync_manifest_entry(entries, "authorization.json")

    _rewrite_bundle(second_bundle, authorization_tamper, tamper_authorization)
    with pytest.raises(EvidenceIntegrityError, match="AUTHORIZATION_RESULT_MISMATCH"):
        verify_evidence_bundle(authorization_tamper)

    invalid_benchmark = tmp_path / "invalid-benchmark.zip"

    def tamper_benchmark(entries: dict[str, bytes]) -> None:
        document = json.loads(entries["benchmark.json"])
        document["case_count"] = "twenty-two"
        entries["benchmark.json"] = json.dumps(document).encode() + b"\n"
        _sync_manifest_entry(entries, "benchmark.json")

    _rewrite_bundle(second_bundle, invalid_benchmark, tamper_benchmark)
    with pytest.raises(EvidenceIntegrityError, match="BENCHMARK_SCHEMA_INVALID"):
        verify_evidence_bundle(invalid_benchmark)

    wrong_manifest = tmp_path / "wrong-manifest.zip"

    def tamper_manifest(entries: dict[str, bytes]) -> None:
        document = json.loads(entries["manifest.json"])
        document["schema_version"] = "mrma.evidence-bundle/v99"
        entries["manifest.json"] = json.dumps(document).encode() + b"\n"

    _rewrite_bundle(second_bundle, wrong_manifest, tamper_manifest)
    with pytest.raises(EvidenceIntegrityError, match="UNSUPPORTED_BUNDLE_SCHEMA"):
        verify_evidence_bundle(wrong_manifest)

    unsafe_path = tmp_path / "unsafe-path.zip"
    _rewrite_bundle(
        second_bundle,
        unsafe_path,
        lambda entries: entries.__setitem__("../escape", b"x"),
    )
    with pytest.raises(EvidenceIntegrityError, match="UNSAFE_BUNDLE_PATH"):
        verify_evidence_bundle(unsafe_path)

    with monkeypatch.context() as scoped:
        scoped.setattr(bundle_module, "_MAX_FILES", 1)
        with pytest.raises(EvidenceIntegrityError, match="BUNDLE_FILE_LIMIT"):
            verify_evidence_bundle(second_bundle)
    with monkeypatch.context() as scoped:
        scoped.setattr(bundle_module, "_MAX_FILE_BYTES", 1)
        with pytest.raises(EvidenceIntegrityError, match="BUNDLE_FILE_LIMIT"):
            verify_evidence_bundle(second_bundle)

    with pytest.raises(FileExistsError):
        create_evidence_bundle(second_bundle, result=payload, journal_path=journal_path)

    for name, raw, code in (
        ("invalid.json", b"{", "INVALID_EVIDENCE_JSON"),
        ("duplicate.json", b'{"schema_version":"a","schema_version":"b"}', "INVALID_EVIDENCE_JSON"),
        ("nonfinite.json", b'{"value":NaN}', "INVALID_EVIDENCE_JSON"),
        ("array.json", b"[]", "INVALID_EVIDENCE_JSON"),
        ("missing-schema.json", b"{}", "MISSING_EVIDENCE_SCHEMA"),
        (
            "unsupported-schema.json",
            b'{"schema_version":"mrma.experiment/v99"}',
            "UNSUPPORTED_EVIDENCE_SCHEMA",
        ),
    ):
        invalid_path = tmp_path / name
        invalid_path.write_bytes(raw)
        with pytest.raises(EvidenceIntegrityError, match=code):
            verify_evidence(invalid_path)

    invalid_result = deepcopy(payload)
    invalid_result["unexpected"] = True
    invalid_result_path = tmp_path / "invalid-result.json"
    invalid_result_path.write_text(json.dumps(invalid_result), encoding="utf-8")
    with pytest.raises(EvidenceIntegrityError, match="EVIDENCE_SCHEMA_INVALID"):
        verify_evidence(invalid_result_path)

    cross_field_result = deepcopy(payload)
    cross_field_result["analysis"]["verdict"] = "NO_INFLUENCE_OBSERVED"
    cross_field_path = tmp_path / "cross-field-result.json"
    cross_field_path.write_text(json.dumps(cross_field_result), encoding="utf-8")
    with pytest.raises(EvidenceIntegrityError, match="EVIDENCE_CROSS_FIELD_INVALID"):
        verify_evidence(cross_field_path)

    wrong_head = deepcopy(payload)
    wrong_head["journal"]["head_digest"] = "sha256:" + "0" * 64
    with pytest.raises(EvidenceIntegrityError, match="JOURNAL_RESULT_MISMATCH"):
        create_evidence_bundle(
            tmp_path / "wrong-head.zip", result=wrong_head, journal_path=journal_path
        )
    wrong_count = deepcopy(payload)
    wrong_count["journal"]["event_count"] += 1
    with pytest.raises(EvidenceIntegrityError, match="JOURNAL_RESULT_MISMATCH"):
        create_evidence_bundle(
            tmp_path / "wrong-count.zip", result=wrong_count, journal_path=journal_path
        )

    missing_file = tmp_path / "missing-file.zip"
    _rewrite_bundle(
        second_bundle,
        missing_file,
        lambda entries: entries.pop("benchmark.json"),
    )
    with pytest.raises(EvidenceIntegrityError, match="BUNDLE_FILE_SET_MISMATCH"):
        verify_evidence_bundle(missing_file)
    with monkeypatch.context() as scoped:
        scoped.setattr(bundle_module, "_MAX_BUNDLE_BYTES", 1)
        with pytest.raises(EvidenceIntegrityError, match="BUNDLE_SIZE_LIMIT"):
            verify_evidence_bundle(second_bundle)

    invalid_file_list = tmp_path / "invalid-file-list.zip"

    def tamper_file_list(entries: dict[str, bytes]) -> None:
        document = json.loads(entries["manifest.json"])
        document["files"] = "invalid"
        entries["manifest.json"] = json.dumps(document).encode() + b"\n"

    _rewrite_bundle(second_bundle, invalid_file_list, tamper_file_list)
    with pytest.raises(EvidenceIntegrityError, match="INVALID_BUNDLE_MANIFEST"):
        verify_evidence_bundle(invalid_file_list)

    invalid_file_entry = tmp_path / "invalid-file-entry.zip"

    def tamper_file_entry(entries: dict[str, bytes]) -> None:
        document = json.loads(entries["manifest.json"])
        document["files"][0] = {}
        entries["manifest.json"] = json.dumps(document).encode() + b"\n"

    _rewrite_bundle(second_bundle, invalid_file_entry, tamper_file_entry)
    with pytest.raises(EvidenceIntegrityError, match="INVALID_BUNDLE_MANIFEST"):
        verify_evidence_bundle(invalid_file_entry)

    missing_manifest_entry = tmp_path / "missing-manifest-entry.zip"

    def drop_manifest_entry(entries: dict[str, bytes]) -> None:
        document = json.loads(entries["manifest.json"])
        document["files"].pop()
        entries["manifest.json"] = json.dumps(document).encode() + b"\n"

    _rewrite_bundle(second_bundle, missing_manifest_entry, drop_manifest_entry)
    with pytest.raises(EvidenceIntegrityError, match="manifest file set mismatch"):
        verify_evidence_bundle(missing_manifest_entry)

    linked_head = tmp_path / "linked-head.zip"

    def tamper_linked_head(entries: dict[str, bytes]) -> None:
        result_document = json.loads(entries["result.json"])
        result_document["journal"]["head_digest"] = "sha256:" + "0" * 64
        entries["result.json"] = json.dumps(result_document).encode() + b"\n"
        _sync_manifest_entry(entries, "result.json")

    _rewrite_bundle(second_bundle, linked_head, tamper_linked_head)
    with pytest.raises(EvidenceIntegrityError, match="JOURNAL_RESULT_MISMATCH"):
        verify_evidence_bundle(linked_head)

    manifest_head = tmp_path / "manifest-head.zip"

    def tamper_manifest_head(entries: dict[str, bytes]) -> None:
        document = json.loads(entries["manifest.json"])
        document["journal_head_digest"] = "sha256:" + "0" * 64
        entries["manifest.json"] = json.dumps(document).encode() + b"\n"

    _rewrite_bundle(second_bundle, manifest_head, tamper_manifest_head)
    with pytest.raises(EvidenceIntegrityError, match="JOURNAL_MANIFEST_MISMATCH"):
        verify_evidence_bundle(manifest_head)

    missing_observation = tmp_path / "missing-observation.zip"

    def add_result_observation(entries: dict[str, bytes]) -> None:
        result_document = json.loads(entries["result.json"])
        result_document["run"]["verdict"] = "INCONCLUSIVE"
        result_document["analysis"]["verdict"] = "INCONCLUSIVE"
        result_document["analysis"]["observations"].append(
            deepcopy(result_document["analysis"]["observations"][0])
        )
        entries["result.json"] = json.dumps(result_document).encode() + b"\n"
        _sync_manifest_entry(entries, "result.json")

    _rewrite_bundle(second_bundle, missing_observation, add_result_observation)
    with pytest.raises(EvidenceIntegrityError, match="MISSING_JOURNAL_OBSERVATIONS"):
        verify_evidence_bundle(missing_observation)

    with pytest.warns(UserWarning, match="Duplicate name"):
        with zipfile.ZipFile(bundle_path, "a") as archive:
            archive.writestr("result.json", b"{}\n")
    with pytest.raises(EvidenceIntegrityError, match="DUPLICATE_BUNDLE_ENTRY"):
        verify_evidence_bundle(bundle_path)

    authorization_bypass = deepcopy(payload)
    authorization_bypass["authorization"]["bypass"] = True
    wire_exact = deepcopy(payload)
    wire_exact["transport"]["wire_exact"] = True
    false_complete_sampling = deepcopy(payload)
    false_complete_sampling["run"]["complete_sampling"] = False
    assert not validator.is_valid(authorization_bypass)
    assert not validator.is_valid(wire_exact)
    assert not validator.is_valid(false_complete_sampling)
