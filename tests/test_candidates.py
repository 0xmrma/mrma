from __future__ import annotations

import json
from pathlib import Path

import pytest

from mrma.core.mutations import Mutation
from mrma.core.raw_request import RawRequest
from mrma.workflows import (
    CandidateManifestError,
    build_candidate_manifest,
    load_candidate,
    write_candidate_manifest,
)


def test_candidate_manifest_binds_request_authorization_and_exact_operation(
    tmp_path: Path,
):
    request = RawRequest(
        "GET",
        "/test",
        "HTTP/1.1",
        [("Accept", "text/plain")],
        b"",
        original_sha256="a" * 64,
    )
    mutations = [
        Mutation("remove-accept", remove="Accept"),
        Mutation("set-probe", set_header=("X-Probe", "1")),
    ]
    manifest = build_candidate_manifest(
        request,
        mutations,
        authorization_digest="sha256:" + "b" * 64,
        rank_by_name={"set-probe": 1, "remove-accept": 2},
    )
    path = tmp_path / "candidates.json"
    write_candidate_manifest(path, manifest)

    selected = load_candidate(path, "candidate-0002")
    assert selected.name == "set-probe"
    assert selected.set_header == ("X-Probe", "1")
    assert selected.baseline_request_digest == "sha256:" + "a" * 64
    assert selected.authorization_digest == "sha256:" + "b" * 64
    assert selected.manifest_digest == manifest["digest"]


def test_candidate_manifest_rejects_tampering_and_duplicate_keys(tmp_path: Path):
    request = RawRequest("GET", "/", "HTTP/1.1", [], b"")
    manifest = build_candidate_manifest(
        request,
        [Mutation("set-probe", set_header=("X-Probe", "1"))],
        authorization_digest="sha256:" + "b" * 64,
        rank_by_name={"set-probe": 1},
    )
    manifest["candidates"][0]["operation"]["value"] = "2"
    tampered = tmp_path / "tampered.json"
    tampered.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(CandidateManifestError, match="digest mismatch"):
        load_candidate(tampered, "candidate-0001")

    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"schema_version":"x","schema_version":"y"}', encoding="utf-8")
    with pytest.raises(CandidateManifestError, match="duplicate key"):
        load_candidate(duplicate, "candidate-0001")
