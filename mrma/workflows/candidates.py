from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from mrma.core.mutations import Mutation
from mrma.core.raw_request import RawRequest

CANDIDATE_SCHEMA_VERSION = "mrma.candidates/v1"
_TOP_LEVEL_FIELDS = frozenset(
    {
        "schema_version",
        "authorization_digest",
        "baseline_request_digest",
        "selection_role",
        "candidates",
        "digest",
    }
)


class CandidateManifestError(ValueError):
    pass


@dataclass(frozen=True)
class SelectedCandidate:
    manifest_digest: str
    candidate_id: str
    name: str
    remove_header: str | None
    set_header: tuple[str, str] | None
    baseline_request_digest: str
    authorization_digest: str


def _reject_constant(value: str) -> None:
    raise CandidateManifestError(f"non-finite number {value!r} is forbidden")


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise CandidateManifestError(f"duplicate key {key!r}")
        result[key] = value
    return result


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def request_identity(request: RawRequest) -> str:
    if request.original_sha256:
        value = request.original_sha256
        return value if value.startswith("sha256:") else f"sha256:{value}"
    return _digest(
        {
            "method": request.method,
            "path": request.path,
            "http_version": request.http_version,
            "headers": request.headers,
            "body_sha256": hashlib.sha256(request.body).hexdigest(),
        }
    )


def build_candidate_manifest(
    request: RawRequest,
    mutations: list[Mutation],
    *,
    authorization_digest: str,
    rank_by_name: dict[str, int],
) -> dict[str, object]:
    candidates = []
    for index, mutation in enumerate(mutations, start=1):
        if mutation.remove is not None:
            operation = {"kind": "remove-header", "name": mutation.remove, "value": None}
        elif mutation.set_header is not None:
            name, value = mutation.set_header
            operation = {"kind": "set-header", "name": name, "value": value}
        else:
            raise CandidateManifestError(f"mutation {mutation.name!r} has no operation")
        candidates.append(
            {
                "id": f"candidate-{index:04d}",
                "name": mutation.name,
                "exploratory_rank": rank_by_name.get(mutation.name, len(mutations) + 1),
                "mutation_family": "header",
                "operation": operation,
            }
        )
    payload: dict[str, object] = {
        "schema_version": CANDIDATE_SCHEMA_VERSION,
        "authorization_digest": authorization_digest,
        "baseline_request_digest": request_identity(request),
        "selection_role": "exploration",
        "candidates": candidates,
    }
    payload["digest"] = _digest(payload)
    return payload


def write_candidate_manifest(path: str | Path, manifest: dict[str, object]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        raise FileExistsError(f"candidate manifest already exists: {target}")
    target.write_bytes(_canonical(manifest) + b"\n")


def load_candidate(path: str | Path, candidate_id: str) -> SelectedCandidate:
    try:
        payload = json.loads(
            Path(path).read_bytes(),
            object_pairs_hook=_pairs,
            parse_constant=_reject_constant,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CandidateManifestError(f"invalid candidate manifest: {exc}") from exc
    if not isinstance(payload, dict) or set(payload) != _TOP_LEVEL_FIELDS:
        raise CandidateManifestError("candidate manifest has unknown or missing fields")
    if payload["schema_version"] != CANDIDATE_SCHEMA_VERSION:
        raise CandidateManifestError("unsupported candidate manifest schema")
    digest = payload["digest"]
    unsigned = dict(payload)
    unsigned.pop("digest")
    if not isinstance(digest, str) or digest != _digest(unsigned):
        raise CandidateManifestError("candidate manifest digest mismatch")
    candidates = payload["candidates"]
    if not isinstance(candidates, list) or not candidates:
        raise CandidateManifestError("candidate manifest is empty")
    matches = [
        item
        for item in candidates
        if isinstance(item, dict) and item.get("id") == candidate_id
    ]
    if len(matches) != 1:
        raise CandidateManifestError("candidate ID is missing or ambiguous")
    item = matches[0]
    if set(item) != {"id", "name", "exploratory_rank", "mutation_family", "operation"}:
        raise CandidateManifestError("candidate has unknown or missing fields")
    if item["mutation_family"] != "header" or not isinstance(item["operation"], dict):
        raise CandidateManifestError("unsupported candidate mutation family")
    operation = item["operation"]
    if set(operation) != {"kind", "name", "value"} or not isinstance(
        operation["name"], str
    ):
        raise CandidateManifestError("invalid candidate operation")
    remove = None
    set_header = None
    if operation["kind"] == "remove-header" and operation["value"] is None:
        remove = operation["name"]
    elif operation["kind"] == "set-header" and isinstance(operation["value"], str):
        set_header = (operation["name"], operation["value"])
    else:
        raise CandidateManifestError("unsupported candidate operation")
    if not all(
        isinstance(payload[name], str)
        for name in ("baseline_request_digest", "authorization_digest")
    ) or not isinstance(item["name"], str):
        raise CandidateManifestError("candidate identity fields are invalid")
    return SelectedCandidate(
        manifest_digest=digest,
        candidate_id=candidate_id,
        name=item["name"],
        remove_header=remove,
        set_header=set_header,
        baseline_request_digest=payload["baseline_request_digest"],
        authorization_digest=payload["authorization_digest"],
    )
