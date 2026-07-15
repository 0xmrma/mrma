from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from mrma.evidence.journal import (
    EvidenceIntegrityError,
    EvidenceJournal,
    verify_journal_bytes,
)


def _line(event: dict[str, object]) -> bytes:
    return json.dumps(event, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def _event_bytes() -> bytes:
    journal = EvidenceJournal(run_id="run")
    event = journal.record("RUN_PLANNED", {"plan_digest": "sha256:" + "a" * 64})
    return _line(event.to_dict())


@pytest.mark.parametrize(
    "kwargs",
    [
        {"mode": "invalid"},
        {"mode": "memory", "path": "journal.jsonl"},
        {"mode": "normal"},
    ],
)
def test_journal_mode_and_path_contract_is_strict(kwargs):
    with pytest.raises(ValueError):
        EvidenceJournal(run_id="run", **kwargs)


def test_privacy_timestamp_precision_and_invalid_policy():
    now = datetime(2026, 7, 15, 12, 34, 56, 789000, tzinfo=timezone.utc)
    strict = EvidenceJournal(run_id="strict", privacy="strict").record(
        "RUN_PLANNED", now=now
    )
    standard = EvidenceJournal(run_id="standard", privacy="standard").record(
        "RUN_PLANNED", now=now
    )
    forensic = EvidenceJournal(run_id="forensic", privacy="forensic").record(
        "RUN_PLANNED", now=now
    )
    assert strict.timestamp == "2026-07-15"
    assert standard.timestamp == "2026-07-15T12:34:00+00:00"
    assert forensic.timestamp == "2026-07-15T12:34:56.789+00:00"
    with pytest.raises(ValueError, match="privacy"):
        EvidenceJournal(run_id="bad", privacy="bad").record("RUN_PLANNED", now=now)


def test_journal_refuses_unknown_closed_and_unsafe_events():
    journal = EvidenceJournal(run_id="run")
    with pytest.raises(EvidenceIntegrityError, match="UNKNOWN_EVENT_TYPE"):
        journal.record("UNKNOWN")
    with pytest.raises(EvidenceIntegrityError, match="NON_STRING_EVIDENCE_KEY"):
        journal.record("RUN_PLANNED", {1: "value"})  # type: ignore[dict-item]
    with pytest.raises(EvidenceIntegrityError, match="UNSAFE_EVIDENCE_VALUE"):
        journal.record("RUN_PLANNED", {"value": object()})
    with pytest.raises(EvidenceIntegrityError, match="UNSERIALIZABLE_EVIDENCE"):
        journal.record("RUN_PLANNED", {"value": float("nan")})
    journal.close()
    journal.close()
    with pytest.raises(EvidenceIntegrityError, match="JOURNAL_CLOSED"):
        journal.record("RUN_FAILED")


@pytest.mark.parametrize(
    ("payload", "code"),
    [
        (b"{\n", "INVALID_JOURNAL_JSON"),
        (b"{}\n", "INVALID_JOURNAL_EVENT"),
        (_event_bytes().rstrip(b"\n"), "TRUNCATED_JOURNAL_RECORD"),
        (
            b'{"schema_version":"mrma.journal/v1","schema_version":"x"}\n',
            "DUPLICATE_JOURNAL_KEY",
        ),
        (b'{"value":NaN}\n', "NONFINITE_JOURNAL_NUMBER"),
    ],
)
def test_journal_verifier_rejects_malformed_jsonl(payload: bytes, code: str):
    with pytest.raises(EvidenceIntegrityError, match=code):
        verify_journal_bytes(payload)


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("schema_version", "mrma.journal/v99", "UNSUPPORTED_JOURNAL_SCHEMA"),
        ("sequence", 2, "JOURNAL_SEQUENCE_MISMATCH"),
        ("previous_digest", "sha256:" + "b" * 64, "JOURNAL_CHAIN_MISMATCH"),
        ("digest", "sha256:" + "b" * 64, "JOURNAL_DIGEST_MISMATCH"),
        ("event_type", "UNKNOWN", "UNKNOWN_EVENT_TYPE"),
        ("sequence", True, "INVALID_JOURNAL_EVENT"),
        ("digest", "bad", "INVALID_JOURNAL_EVENT"),
    ],
)
def test_journal_verifier_rejects_tampered_fields(field: str, value: object, code: str):
    payload = json.loads(_event_bytes())
    payload[field] = value
    with pytest.raises(EvidenceIntegrityError, match=code):
        verify_journal_bytes(_line(payload))


def test_normal_and_durable_file_journals_record_sync_state(tmp_path: Path):
    normal_path = tmp_path / "normal" / "journal.jsonl"
    with EvidenceJournal(run_id="normal", path=normal_path, mode="normal") as normal:
        normal.record("RUN_PLANNED")
    assert normal.file_sync is False
    assert normal.directory_sync == "not-requested"

    durable_path = tmp_path / "durable" / "journal.jsonl"
    with EvidenceJournal(run_id="durable", path=durable_path, mode="durable") as durable:
        durable.record("RUN_PLANNED")
        assert durable.file_sync is True
    assert durable.directory_sync in {"performed", "unsupported"}


def test_journal_write_failure_does_not_advance_chain(monkeypatch, tmp_path: Path):
    path = tmp_path / "journal.jsonl"
    journal = EvidenceJournal(run_id="run", path=path, mode="normal")
    original_head = journal.head_digest
    monkeypatch.setattr(journal._stream, "write", lambda _data: 0)
    with pytest.raises(OSError, match="made no progress"):
        journal.record("RUN_PLANNED")
    assert journal.events == ()
    assert journal.head_digest == original_head
    journal.close()
