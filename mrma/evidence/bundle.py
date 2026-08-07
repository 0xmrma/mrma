from __future__ import annotations

import hashlib
import json
import os
import tempfile
import zipfile
from collections import Counter
from importlib.resources import files
from pathlib import Path, PurePosixPath
from statistics import median
from typing import cast

from jsonschema import Draft202012Validator

from mrma import __version__
from mrma.core.experiment import HTTP_RESPONSE, wilson_interval
from mrma.engine.plan import effective_plan_digest

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


def _as_array(value: object, *, label: str) -> list[object]:
    if not isinstance(value, list):
        raise EvidenceIntegrityError("INVALID_EVIDENCE_JSON", f"{label} must be an array")
    return cast(list[object], value)


def _as_int(value: object, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise EvidenceIntegrityError("INVALID_EVIDENCE_JSON", f"{label} must be an integer")
    return value


def _as_float(value: object, *, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise EvidenceIntegrityError("INVALID_EVIDENCE_JSON", f"{label} must be a number")
    return float(value)


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
    if schema_version not in {
        "mrma.experiment/v7",
        "mrma.experiment/v8",
        "mrma.experiment/v9",
    }:
        raise EvidenceIntegrityError("UNSUPPORTED_EVIDENCE_SCHEMA", schema_version)
    version = schema_version.rsplit("/v", 1)[1]
    return files("mrma.schemas").joinpath(f"experiment-v{version}.schema.json").read_bytes()


def _benchmark_schema_bytes(schema_version: str) -> bytes:
    if schema_version not in {"mrma.benchmark/v1", "mrma.benchmark/v2"}:
        raise EvidenceIntegrityError("UNSUPPORTED_BENCHMARK_SCHEMA", schema_version)
    version = schema_version.rsplit("/v", 1)[1]
    return files("mrma.schemas").joinpath(f"benchmark-v{version}.schema.json").read_bytes()


def validate_benchmark_document(document: dict[str, object]) -> dict[str, object]:
    schema_version = document.get("schema_version")
    if not isinstance(schema_version, str):
        raise EvidenceIntegrityError("MISSING_BENCHMARK_SCHEMA", "schema_version is required")
    schema = _load_json(
        _benchmark_schema_bytes(schema_version), label="installed benchmark schema"
    )
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


def _derivation_mismatch(label: str) -> EvidenceIntegrityError:
    return EvidenceIntegrityError(
        "STATISTICAL_DERIVATION_MISMATCH",
        f"recorded {label} differs from public evidence derivation",
    )


def _expect_derived(actual: object, expected: object, *, label: str) -> None:
    if actual != expected:
        raise _derivation_mismatch(label)


def _pair_objects(value: object, *, label: str) -> list[dict[str, object]]:
    return [
        _as_object(item, label=f"{label}[{index}]")
        for index, item in enumerate(_as_array(value, label=label))
    ]


def _rounded_interval(changed: int, total: int) -> list[float]:
    low, high = wilson_interval(changed, total)
    return [round(low, 6), round(high, 6)]


def _similarity_median(pairs: list[dict[str, object]]) -> float | None:
    values = [
        _as_float(item["similarity"], label="pair similarity")
        for item in pairs
        if item["similarity"] is not None
    ]
    return round(float(median(values)), 6) if values else None


def _verify_v9_statistical_derivation(
    document: dict[str, object],
) -> dict[str, object]:
    run = _as_object(document["run"], label="run")
    plan = _as_object(document["plan"], label="plan")
    effective_plan = _as_object(plan["effective_plan"], label="plan.effective_plan")
    experiment = _as_object(effective_plan["experiment"], label="effective experiment")
    analysis = _as_object(document["analysis"], label="analysis")
    reproducibility = _as_object(analysis["reproducibility"], label="reproducibility")
    control_stability = _as_object(analysis["control_stability"], label="control_stability")
    effect = _as_object(analysis["effect"], label="effect")
    mutation_pairs = _pair_objects(analysis["round_evidence"], label="round_evidence")
    control_pairs = _pair_objects(analysis["control_evidence"], label="control_evidence")
    observations = _pair_objects(analysis["observations"], label="observations")

    observation_keys: set[tuple[int, str]] = set()
    observations_by_arm: dict[str, dict[int, dict[str, object]]] = {}
    for item in observations:
        arm = str(item["arm"])
        round_index = _as_int(item["round"], label="observation round")
        key = (round_index, arm)
        if key in observation_keys:
            raise _derivation_mismatch("observation arm/round uniqueness")
        observation_keys.add(key)
        observations_by_arm.setdefault(arm, {})[round_index] = item

    mutation_rounds = [
        _as_int(item["round"], label="mutation pair round") for item in mutation_pairs
    ]
    control_rounds = [
        _as_int(item["round"], label="control pair round") for item in control_pairs
    ]
    if len(set(mutation_rounds)) != len(mutation_rounds):
        raise _derivation_mismatch("mutation pair round uniqueness")
    if len(set(control_rounds)) != len(control_rounds):
        raise _derivation_mismatch("control pair round uniqueness")

    schedule_mode = str(experiment["schedule_mode"])
    mutations = observations_by_arm.get("mutation", {})
    if schedule_mode == "bracketed":
        controls_before = observations_by_arm.get("control_before", {})
        controls_after = observations_by_arm.get("control_after", {})
        paired_rounds = set(controls_before) & set(controls_after) & set(mutations)
        expected_control_rounds = paired_rounds
        missing_pairs = not (
            len(controls_before)
            == len(controls_after)
            == len(mutations)
            == len(paired_rounds)
        )
        control_observations = [*controls_before.values(), *controls_after.values()]
        observations_per_round = 3
    else:
        controls = observations_by_arm.get("control", {})
        paired_rounds = set(controls) & set(mutations)
        ordered_controls = sorted(
            controls.values(),
            key=lambda item: _as_int(item["sequence"], label="observation sequence"),
        )
        expected_control_rounds = {
            _as_int(item["round"], label="control round") for item in ordered_controls[1:]
        }
        missing_pairs = len(controls) != len(mutations) or len(paired_rounds) != len(controls)
        control_observations = list(controls.values())
        observations_per_round = 2

    if set(mutation_rounds) != paired_rounds or set(control_rounds) != expected_control_rounds:
        raise _derivation_mismatch("pair topology")

    maximum_rounds = _as_int(experiment["maximum_rounds"], label="maximum rounds")
    _expect_derived(run["planned_rounds"], maximum_rounds, label="planned rounds")
    _expect_derived(plan["maximum_rounds"], maximum_rounds, label="plan maximum rounds")
    _expect_derived(
        plan["observations_per_round"],
        observations_per_round,
        label="observations per round",
    )
    _expect_derived(
        plan["maximum_logical_observations"],
        maximum_rounds * observations_per_round,
        label="maximum logical observations",
    )
    _expect_derived(run["completed_rounds"], len(paired_rounds), label="completed rounds")
    complete_sampling = (
        run["status"] == "completed"
        and len(paired_rounds) == maximum_rounds
        and len(observations) == maximum_rounds * observations_per_round
    )
    _expect_derived(run["complete_sampling"], complete_sampling, label="sampling completeness")

    mutation_changed = sum(item["classification"] == "CHANGED" for item in mutation_pairs)
    mutation_indeterminate = sum(
        item["classification"] == "INDETERMINATE" for item in mutation_pairs
    )
    control_changed = sum(item["classification"] == "CHANGED" for item in control_pairs)
    control_indeterminate = sum(
        item["classification"] == "INDETERMINATE" for item in control_pairs
    )
    mutation_rate = round(mutation_changed / len(mutation_pairs), 6) if mutation_pairs else 0.0
    control_rate = round(control_changed / len(control_pairs), 6) if control_pairs else 0.0
    mutation_interval = _rounded_interval(mutation_changed, len(mutation_pairs))
    control_interval = _rounded_interval(control_changed, len(control_pairs))

    for actual, expected, label in (
        (reproducibility["changed_rounds"], mutation_changed, "mutation changed rounds"),
        (
            reproducibility["indeterminate_rounds"],
            mutation_indeterminate,
            "mutation indeterminate rounds",
        ),
        (reproducibility["rate"], mutation_rate, "mutation rate"),
        (
            reproducibility["wilson_interval_95"],
            mutation_interval,
            "mutation Wilson interval",
        ),
        (control_stability["changed_comparisons"], control_changed, "control changes"),
        (
            control_stability["indeterminate_comparisons"],
            control_indeterminate,
            "control indeterminate comparisons",
        ),
        (control_stability["rate"], control_rate, "control rate"),
        (
            control_stability["wilson_interval_95"],
            control_interval,
            "control Wilson interval",
        ),
    ):
        _expect_derived(actual, expected, label=label)

    mutation_median = _similarity_median(mutation_pairs)
    control_median = _similarity_median(control_pairs)
    similarity_contrast = (
        round(control_median - mutation_median, 6)
        if control_median is not None and mutation_median is not None
        else None
    )
    _expect_derived(
        control_stability["median_similarity"],
        control_median,
        label="control median similarity",
    )
    for field, pair_field in (
        ("status_shift_rounds", "status_changed"),
        ("outcome_shift_rounds", "outcome_changed"),
        ("redirect_shift_rounds", "redirect_changed"),
        ("retry_shift_rounds", "retry_changed"),
    ):
        _expect_derived(
            effect[field],
            sum(bool(item[pair_field]) for item in mutation_pairs),
            label=field,
        )
    _expect_derived(
        effect["mutation_median_similarity"],
        mutation_median,
        label="mutation median similarity",
    )
    _expect_derived(
        effect["control_minus_mutation_similarity"],
        similarity_contrast,
        label="similarity contrast",
    )

    header_counts: Counter[str] = Counter()
    for item in mutation_pairs:
        fields = [str(name) for name in _as_array(
            item["response_header_differences"],
            label="response_header_differences",
        )]
        if len(fields) != len(set(fields)):
            raise _derivation_mismatch("response header difference uniqueness")
        header_counts.update(fields)
    expected_header_shifts = [
        {"name": name, "rounds": count} for name, count in sorted(header_counts.items())
    ]
    _expect_derived(
        effect["response_header_shifts"],
        expected_header_shifts,
        label="response header shift counts",
    )

    outcome_counts = Counter(str(item["outcome"]) for item in observations)
    expected_outcome_counts = [
        {"outcome": outcome, "count": count}
        for outcome, count in sorted(outcome_counts.items())
    ]
    _expect_derived(
        effect["outcome_counts"],
        expected_outcome_counts,
        label="outcome counts",
    )

    invalid_controls = any(item["outcome"] != HTTP_RESPONSE for item in control_observations)
    control_confidently_stable = (
        bool(control_pairs)
        and not invalid_controls
        and control_indeterminate == 0
        and control_interval[1]
        <= _as_float(
            experiment["maximum_control_change_rate"],
            label="maximum control change rate",
        )
    )
    control_confidently_unstable = bool(control_pairs) and control_interval[0] > _as_float(
        experiment["maximum_control_change_rate"],
        label="maximum control change rate",
    )
    if missing_pairs or invalid_controls or control_confidently_unstable:
        derived_verdict = "INCONCLUSIVE"
    elif control_confidently_stable and mutation_interval[0] >= _as_float(
        experiment["minimum_reproducibility"], label="minimum reproducibility"
    ):
        derived_verdict = "INFLUENCE_DETECTED"
    elif (
        control_confidently_stable
        and mutation_indeterminate == 0
        and mutation_interval[1]
        <= _as_float(
            experiment["no_influence_threshold"], label="no influence threshold"
        )
    ):
        derived_verdict = "NO_INFLUENCE_OBSERVED"
    else:
        derived_verdict = "INCONCLUSIVE"
    if run["status"] != "completed":
        derived_verdict = "INCONCLUSIVE"
    if run["verdict"] != derived_verdict or analysis["verdict"] != derived_verdict:
        raise EvidenceIntegrityError(
            "VERDICT_DERIVATION_MISMATCH",
            "recorded verdict differs from the public evidence and effective plan",
        )
    return {
        "statistical_derivation_verified": True,
        "derived_verdict": derived_verdict,
        "mutation_pairs": len(mutation_pairs),
        "control_comparisons": len(control_pairs),
    }


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
    if schema_version in {"mrma.experiment/v8", "mrma.experiment/v9"}:
        effective_plan = _as_object(plan["effective_plan"], label="plan.effective_plan")
        if plan["plan_digest"] != effective_plan_digest(effective_plan):
            raise EvidenceIntegrityError(
                "PLAN_DIGEST_MISMATCH",
                "effective_plan does not match plan_digest",
            )
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
    derivation = (
        _verify_v9_statistical_derivation(document)
        if schema_version == "mrma.experiment/v9"
        else {"statistical_derivation_verified": False}
    )
    return {
        "schema_version": schema_version,
        "schema_valid": True,
        "run_id": run["id"],
        "verdict": run["verdict"],
        **derivation,
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
    result_plan = _as_object(result["plan"], label="plan")
    _verify_journal_plan_digest(journal_bytes, result_plan["plan_digest"])
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


def _verify_journal_plan_digest(data: bytes, expected: object) -> None:
    planned: list[object] = []
    for line in data.splitlines():
        event = _load_json(line, label="journal event")
        if event.get("event_type") != "RUN_PLANNED":
            continue
        event_data = _as_object(event.get("data"), label="journal event data")
        planned.append(event_data.get("plan_digest"))
    if not planned or any(value != expected for value in planned):
        raise EvidenceIntegrityError(
            "JOURNAL_PLAN_MISMATCH",
            "RUN_PLANNED does not match the result plan digest",
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
        result_plan = _as_object(result["plan"], label="plan")
        _verify_journal_plan_digest(journal_data, result_plan["plan_digest"])
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
