from __future__ import annotations

import hashlib
import json
import os
import tempfile
import zipfile
from importlib.resources import files
from pathlib import Path, PurePosixPath
from typing import cast

from jsonschema import Draft202012Validator

from mrma import __version__

from .journal import EvidenceIntegrityError, verify_journal, verify_journal_bytes

BUNDLE_MANIFEST_VERSION = "mrma.evidence-bundle/v1"
_MAX_FILES = 32
_MAX_FILE_BYTES = 64 * 1024 * 1024
_MAX_BUNDLE_BYTES = 128 * 1024 * 1024
_FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
_REQUIRED_FILES = frozenset(
    {
        "authorization.json",
        "benchmark.json",
        "journal.jsonl",
        "plan.json",
        "REPLAY.md",
        "result.json",
        "runtime.json",
        "schema.json",
    }
)


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number {value!r} is forbidden")


def _object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _load_json(data: bytes, *, label: str) -> dict[str, object]:
    try:
        value = json.loads(
            data,
            object_pairs_hook=_object_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise EvidenceIntegrityError("INVALID_EVIDENCE_JSON", f"{label}: {exc}") from exc
    if not isinstance(value, dict):
        raise EvidenceIntegrityError("INVALID_EVIDENCE_JSON", f"{label} must be an object")
    return value


def _as_object(value: object, *, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise EvidenceIntegrityError("INVALID_EVIDENCE_JSON", f"{label} must be an object")
    return cast(dict[str, object], value)


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            ensure_ascii=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("ascii")
        + b"\n"
    )


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _schema_bytes(schema_version: str) -> bytes:
    if schema_version != "mrma.experiment/v7":
        raise EvidenceIntegrityError("UNSUPPORTED_EVIDENCE_SCHEMA", schema_version)
    return files("mrma.schemas").joinpath("experiment-v7.schema.json").read_bytes()


def _benchmark_schema_bytes() -> bytes:
    return files("mrma.schemas").joinpath("benchmark-v1.schema.json").read_bytes()


def validate_benchmark_document(document: dict[str, object]) -> dict[str, object]:
    schema = _load_json(_benchmark_schema_bytes(), label="installed benchmark schema")
    try:
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(document)
    except Exception as exc:
        raise EvidenceIntegrityError("BENCHMARK_SCHEMA_INVALID", str(exc)) from exc
    return {
        "schema_version": document["schema_version"],
        "corpus_version": document["corpus_version"],
        "mrma_version": document["mrma_version"],
        "passed": document["passed"],
        "case_count": document["case_count"],
    }


def _release_benchmark() -> dict[str, object]:
    data = files("mrma").joinpath("benchmarks", "release-baseline.json").read_bytes()
    return _load_json(data, label="installed release benchmark")


def validate_result_document(document: dict[str, object]) -> dict[str, object]:
    schema_version = document.get("schema_version")
    if not isinstance(schema_version, str):
        raise EvidenceIntegrityError("MISSING_EVIDENCE_SCHEMA", "schema_version is required")
    schema = _load_json(_schema_bytes(schema_version), label="installed schema")
    try:
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(document)
    except Exception as exc:
        raise EvidenceIntegrityError("EVIDENCE_SCHEMA_INVALID", str(exc)) from exc
    run = _as_object(document["run"], label="run")
    analysis = _as_object(document["analysis"], label="analysis")
    assurance = _as_object(document["assurance"], label="assurance")
    budget = _as_object(document["budget"], label="budget")
    consumed = _as_object(budget["consumed"], label="budget.consumed")
    transport = _as_object(document["transport"], label="transport")
    plan = _as_object(document["plan"], label="plan")
    if run["verdict"] != analysis["verdict"] or run["stop_reason"] != analysis["stop_reason"]:
        raise EvidenceIntegrityError(
            "EVIDENCE_CROSS_FIELD_INVALID", "run and analysis conclusions differ"
        )
    if run["complete_sampling"] != assurance["sampling_complete"]:
        raise EvidenceIntegrityError(
            "EVIDENCE_CROSS_FIELD_INVALID", "sampling completeness declarations differ"
        )
    if budget["settled"] and consumed["active_leases"] != 0:
        raise EvidenceIntegrityError(
            "EVIDENCE_CROSS_FIELD_INVALID", "settled budget retains active leases"
        )
    if assurance["authorization_enforcement"] == "strong" and transport[
        "connected_address_fingerprint"
    ] is None:
        raise EvidenceIntegrityError(
            "EVIDENCE_CROSS_FIELD_INVALID",
            "strong authorization assurance requires connection-address evidence",
        )
    decisive = run["verdict"] in {"INFLUENCE_DETECTED", "NO_INFLUENCE_OBSERVED"}
    if decisive and (
        run["completed_rounds"] != run["planned_rounds"]
        or len(cast(list[object], analysis["observations"]))
        != plan["maximum_logical_observations"]
    ):
        raise EvidenceIntegrityError(
            "EVIDENCE_CROSS_FIELD_INVALID",
            "decisive evidence does not contain the complete fixed sample",
        )
    return {
        "schema_version": schema_version,
        "schema_valid": True,
        "run_id": run["id"],
        "verdict": run["verdict"],
    }


def _zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=_FIXED_ZIP_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = 0o100644 << 16
    return info


def create_evidence_bundle(
    destination: str | Path,
    *,
    result: dict[str, object],
    journal_path: str | Path,
    benchmark: dict[str, object] | None = None,
) -> dict[str, object]:
    """Create an atomic deterministic bundle from already-public evidence."""
    validate_result_document(result)
    result_journal = _as_object(result["journal"], label="journal")
    result_tool = _as_object(result["tool"], label="tool")
    journal_bytes = Path(journal_path).read_bytes()
    journal_verification = verify_journal_bytes(journal_bytes)
    if result_journal["head_digest"] != journal_verification["head_digest"]:
        raise EvidenceIntegrityError(
            "JOURNAL_RESULT_MISMATCH", "result and journal head digests differ"
        )
    if result_journal["event_count"] != journal_verification["event_count"]:
        raise EvidenceIntegrityError(
            "JOURNAL_RESULT_MISMATCH", "result and journal event counts differ"
        )

    benchmark_document = benchmark if benchmark is not None else _release_benchmark()
    validate_benchmark_document(benchmark_document)
    schema_bytes = _schema_bytes(str(result["schema_version"]))
    payloads = {
        "authorization.json": _canonical_json(result["authorization"]),
        "benchmark.json": _canonical_json(benchmark_document),
        "journal.jsonl": journal_bytes,
        "plan.json": _canonical_json(result["plan"]),
        "REPLAY.md": (
            b"# MRMA Evidence Replay\n\n"
            b"Run `mrma evidence verify BUNDLE.zip` with the same or a newer compatible MRMA release.\n"
            b"The bundle contains privacy-safe evidence, not credentials or an executable authorization grant.\n"
        ),
        "result.json": _canonical_json(result),
        "runtime.json": _canonical_json(result_tool["runtime"]),
        "schema.json": schema_bytes,
    }
    manifest = {
        "schema_version": BUNDLE_MANIFEST_VERSION,
        "mrma_version": __version__,
        "result_schema_version": result["schema_version"],
        "journal_head_digest": journal_verification["head_digest"],
        "files": [
            {"path": name, "size": len(payloads[name]), "sha256": _digest(payloads[name])}
            for name in sorted(payloads)
        ],
    }
    payloads["manifest.json"] = _canonical_json(manifest)

    target = Path(destination)
    if target.exists():
        raise FileExistsError(f"evidence bundle already exists: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    os.close(fd)
    temporary = Path(temporary_name)
    try:
        with zipfile.ZipFile(temporary, "w") as archive:
            for name in sorted(payloads):
                archive.writestr(_zip_info(name), payloads[name])
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)
    bundle_bytes = target.read_bytes()
    return {
        "schema_version": BUNDLE_MANIFEST_VERSION,
        "path": str(target),
        "size": len(bundle_bytes),
        "sha256": _digest(bundle_bytes),
        "journal_head_digest": journal_verification["head_digest"],
    }


def _safe_members(archive: zipfile.ZipFile) -> dict[str, zipfile.ZipInfo]:
    infos = archive.infolist()
    if len(infos) > _MAX_FILES:
        raise EvidenceIntegrityError("BUNDLE_FILE_LIMIT", "bundle has too many entries")
    members: dict[str, zipfile.ZipInfo] = {}
    total = 0
    for info in infos:
        path = PurePosixPath(info.filename)
        if path.is_absolute() or ".." in path.parts or len(path.parts) != 1:
            raise EvidenceIntegrityError("UNSAFE_BUNDLE_PATH", info.filename)
        if info.filename in members:
            raise EvidenceIntegrityError("DUPLICATE_BUNDLE_ENTRY", info.filename)
        if info.file_size > _MAX_FILE_BYTES:
            raise EvidenceIntegrityError("BUNDLE_FILE_LIMIT", info.filename)
        total += info.file_size
        if total > _MAX_BUNDLE_BYTES:
            raise EvidenceIntegrityError("BUNDLE_SIZE_LIMIT", "expanded bundle is too large")
        members[info.filename] = info
    expected = set(_REQUIRED_FILES) | {"manifest.json"}
    if set(members) != expected:
        raise EvidenceIntegrityError("BUNDLE_FILE_SET_MISMATCH", "missing or unexpected files")
    return members


def _journal_observation_count(data: bytes) -> int:
    return sum(
        1
        for line in data.splitlines()
        if _load_json(line, label="journal event").get("event_type") == "OBSERVATION_COMPLETED"
    )


def verify_evidence_bundle(path: str | Path) -> dict[str, object]:
    with zipfile.ZipFile(path, "r") as archive:
        members = _safe_members(archive)
        manifest = _load_json(archive.read(members["manifest.json"]), label="manifest.json")
        if manifest.get("schema_version") != BUNDLE_MANIFEST_VERSION:
            raise EvidenceIntegrityError("UNSUPPORTED_BUNDLE_SCHEMA", str(manifest.get("schema_version")))
        listed = manifest.get("files")
        if not isinstance(listed, list):
            raise EvidenceIntegrityError("INVALID_BUNDLE_MANIFEST", "files must be an array")
        expected_entries = set(_REQUIRED_FILES)
        seen: set[str] = set()
        for entry in listed:
            if not isinstance(entry, dict) or set(entry) != {"path", "size", "sha256"}:
                raise EvidenceIntegrityError("INVALID_BUNDLE_MANIFEST", "invalid file entry")
            name = entry["path"]
            if not isinstance(name, str) or name not in expected_entries or name in seen:
                raise EvidenceIntegrityError("INVALID_BUNDLE_MANIFEST", "invalid file path")
            data = archive.read(members[name])
            if entry["size"] != len(data) or entry["sha256"] != _digest(data):
                raise EvidenceIntegrityError("BUNDLE_DIGEST_MISMATCH", name)
            seen.add(name)
        if seen != expected_entries:
            raise EvidenceIntegrityError("INVALID_BUNDLE_MANIFEST", "manifest file set mismatch")

        result = _load_json(archive.read(members["result.json"]), label="result.json")
        result_verification = validate_result_document(result)
        result_journal = _as_object(result["journal"], label="journal")
        result_analysis = _as_object(result["analysis"], label="analysis")
        installed_schema = _schema_bytes(str(result["schema_version"]))
        if archive.read(members["schema.json"]) != installed_schema:
            raise EvidenceIntegrityError(
                "INCOMPATIBLE_BUNDLED_SCHEMA", "schema differs from the installed immutable schema"
            )
        journal_data = archive.read(members["journal.jsonl"])
        journal = verify_journal_bytes(journal_data)
        if result_journal["head_digest"] != journal["head_digest"]:
            raise EvidenceIntegrityError("JOURNAL_RESULT_MISMATCH", "head digest differs")
        if result_journal["event_count"] != journal["event_count"]:
            raise EvidenceIntegrityError("JOURNAL_RESULT_MISMATCH", "event count differs")
        if manifest.get("journal_head_digest") != journal["head_digest"]:
            raise EvidenceIntegrityError("JOURNAL_MANIFEST_MISMATCH", "head digest differs")
        if _load_json(archive.read(members["plan.json"]), label="plan.json") != result["plan"]:
            raise EvidenceIntegrityError("PLAN_RESULT_MISMATCH", "plan differs")
        if (
            _load_json(archive.read(members["authorization.json"]), label="authorization.json")
            != result["authorization"]
        ):
            raise EvidenceIntegrityError("AUTHORIZATION_RESULT_MISMATCH", "summary differs")
        observations = cast(list[object], result_analysis["observations"])
        observation_count = len(observations)
        if _journal_observation_count(journal_data) < observation_count:
            raise EvidenceIntegrityError(
                "MISSING_JOURNAL_OBSERVATIONS", "journal has fewer observations than the result"
            )
        benchmark = validate_benchmark_document(
            _load_json(archive.read(members["benchmark.json"]), label="benchmark.json")
        )
    return {
        "schema_version": BUNDLE_MANIFEST_VERSION,
        "verified": True,
        "bundle_sha256": _digest(Path(path).read_bytes()),
        "result": result_verification,
        "journal": journal,
        "benchmark": benchmark,
    }


def verify_evidence(path: str | Path) -> dict[str, object]:
    source = Path(path)
    if zipfile.is_zipfile(source):
        return verify_evidence_bundle(source)
    if source.suffix.lower() in {".jsonl", ".journal"}:
        return verify_journal(source)
    document = _load_json(source.read_bytes(), label=source.name)
    return {"verified": True, **validate_result_document(document)}
