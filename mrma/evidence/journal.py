from __future__ import annotations

import hashlib
import json
import os
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from types import TracebackType
from typing import BinaryIO

JOURNAL_SCHEMA_VERSION = "mrma.journal/v1"
JOURNAL_HASH_ALGORITHM = "sha256"
JOURNAL_MODES = frozenset({"memory", "normal", "durable"})
EVENT_TYPES = frozenset(
    {
        "RUN_PLANNED",
        "AUTHORIZATION_ACCEPTED",
        "AUTHORIZATION_REJECTED",
        "BUDGET_RESERVED",
        "ROUND_STARTED",
        "ATTEMPT_STARTED",
        "ATTEMPT_COMPLETED",
        "REDIRECT_PROPOSED",
        "REDIRECT_AUTHORIZED",
        "REDIRECT_REJECTED",
        "OBSERVATION_COMPLETED",
        "ROUND_COMPLETED",
        "BUDGET_UPDATED",
        "RUN_CANCELLED",
        "RUN_FAILED",
        "RUN_COMPLETED",
        "COMPARATOR_RESOURCE_LIMIT",
        "POLICY_ABORT",
    }
)
_SENSITIVE_KEYS = (
    "authorization",
    "cookie",
    "password",
    "secret",
    "token",
    "credential",
    "proxy_url",
    "raw_url",
    "filesystem_path",
    "environment",
)


class EvidenceIntegrityError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


@dataclass(frozen=True)
class EvidenceContext:
    run_id: str
    attempt_id: str
    role: str
    round_index: int | None = None


@dataclass(frozen=True)
class JournalEvent:
    schema_version: str
    sequence: int
    event_type: str
    timestamp: str
    previous_digest: str
    digest: str
    data: Mapping[str, object]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "sequence": self.sequence,
            "event_type": self.event_type,
            "timestamp": self.timestamp,
            "previous_digest": self.previous_digest,
            "digest": self.digest,
            "data": dict(self.data),
        }


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            ensure_ascii=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise EvidenceIntegrityError("UNSERIALIZABLE_EVIDENCE", str(exc)) from exc


def _validate_safe(value: object, *, path: str = "data") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str):
                raise EvidenceIntegrityError("NON_STRING_EVIDENCE_KEY", path)
            lowered = key.lower().replace("-", "_")
            if any(marker in lowered for marker in _SENSITIVE_KEYS):
                raise EvidenceIntegrityError(
                    "SENSITIVE_EVIDENCE_FIELD",
                    f"{path}.{key} is not permitted in the public journal",
                )
            _validate_safe(child, path=f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            _validate_safe(child, path=f"{path}[{index}]")
    elif value is not None and not isinstance(value, (str, int, float, bool)):
        raise EvidenceIntegrityError("UNSAFE_EVIDENCE_VALUE", f"unsupported value at {path}")


def _timestamp(privacy: str, now: datetime) -> str:
    current = now.astimezone(timezone.utc)
    if privacy == "strict":
        return current.date().isoformat()
    if privacy == "standard":
        return current.replace(second=0, microsecond=0).isoformat()
    if privacy == "forensic":
        return current.isoformat(timespec="milliseconds")
    raise ValueError("privacy must be strict, standard, or forensic")


class EvidenceJournal:
    """Append-only, hash-chained journal with optional per-record durability."""

    def __init__(
        self,
        *,
        run_id: str,
        privacy: str = "standard",
        path: str | Path | None = None,
        mode: str = "memory",
    ) -> None:
        if mode not in JOURNAL_MODES:
            raise ValueError("mode must be memory, normal, or durable")
        if mode == "memory" and path is not None:
            raise ValueError("memory journals cannot have a path")
        if mode != "memory" and path is None:
            raise ValueError("file journals require a path")
        self.run_id = run_id
        self.privacy = privacy
        self.mode = mode
        self._path = Path(path) if path is not None else None
        self._lock = threading.RLock()
        self._events: list[JournalEvent] = []
        self._previous_digest = "sha256:" + "0" * 64
        self._stream: BinaryIO | None = None
        self._closed = False
        self.file_sync = False
        self.directory_sync = "not-requested"
        if self._path is not None:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._stream = self._path.open("xb", buffering=0)

    def __enter__(self) -> EvidenceJournal:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    @property
    def events(self) -> tuple[JournalEvent, ...]:
        with self._lock:
            return tuple(self._events)

    @property
    def head_digest(self) -> str:
        with self._lock:
            return self._previous_digest

    def record(
        self,
        event_type: str,
        data: Mapping[str, object] | None = None,
        *,
        now: datetime | None = None,
    ) -> JournalEvent:
        if event_type not in EVENT_TYPES:
            raise EvidenceIntegrityError("UNKNOWN_EVENT_TYPE", event_type)
        clean_data = dict(data or {})
        _validate_safe(clean_data)
        with self._lock:
            if self._closed:
                raise EvidenceIntegrityError("JOURNAL_CLOSED", "cannot append after close")
            sequence = len(self._events) + 1
            timestamp = _timestamp(self.privacy, now or datetime.now(timezone.utc))
            core: dict[str, object] = {
                "schema_version": JOURNAL_SCHEMA_VERSION,
                "sequence": sequence,
                "event_type": event_type,
                "timestamp": timestamp,
                "previous_digest": self._previous_digest,
                "data": clean_data,
            }
            digest = "sha256:" + hashlib.sha256(_canonical(core)).hexdigest()
            event = JournalEvent(
                schema_version=JOURNAL_SCHEMA_VERSION,
                sequence=sequence,
                event_type=event_type,
                timestamp=timestamp,
                previous_digest=self._previous_digest,
                digest=digest,
                data=clean_data,
            )
            encoded = _canonical(event.to_dict()) + b"\n"
            if self._stream is not None:
                self._write_all(encoded)
                if self.mode == "durable":
                    self._stream.flush()
                    os.fsync(self._stream.fileno())
                    self.file_sync = True
            self._events.append(event)
            self._previous_digest = digest
            return event

    def _write_all(self, data: bytes) -> None:
        assert self._stream is not None
        view = memoryview(data)
        while view:
            written = self._stream.write(view)
            if written is None or written <= 0:
                raise OSError("journal append made no progress")
            view = view[written:]

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            if self._stream is not None:
                if self.mode == "durable":
                    self._stream.flush()
                    os.fsync(self._stream.fileno())
                    self.file_sync = True
                self._stream.close()
                if self.mode == "durable" and self._path is not None and hasattr(os, "O_DIRECTORY"):
                    directory_fd = os.open(self._path.parent, os.O_RDONLY | os.O_DIRECTORY)
                    try:
                        os.fsync(directory_fd)
                    finally:
                        os.close(directory_fd)
                    self.directory_sync = "performed"
                elif self.mode == "durable":
                    self.directory_sync = "unsupported"
            self._closed = True


def _parse_event(line: bytes, line_number: int) -> JournalEvent:
    def strict_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise EvidenceIntegrityError(
                    "DUPLICATE_JOURNAL_KEY", f"line {line_number}: {key}"
                )
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise EvidenceIntegrityError(
            "NONFINITE_JOURNAL_NUMBER", f"line {line_number}: {value}"
        )

    try:
        payload = json.loads(
            line,
            object_pairs_hook=strict_pairs,
            parse_constant=reject_constant,
        )
    except json.JSONDecodeError as exc:
        raise EvidenceIntegrityError("INVALID_JOURNAL_JSON", f"line {line_number}") from exc
    required = {
        "schema_version",
        "sequence",
        "event_type",
        "timestamp",
        "previous_digest",
        "digest",
        "data",
    }
    if not isinstance(payload, dict) or set(payload) != required or not isinstance(payload["data"], dict):
        raise EvidenceIntegrityError("INVALID_JOURNAL_EVENT", f"line {line_number}")
    if (
        payload["schema_version"] != JOURNAL_SCHEMA_VERSION
        and not isinstance(payload["schema_version"], str)
    ):
        raise EvidenceIntegrityError("INVALID_JOURNAL_EVENT", f"line {line_number}")
    if not isinstance(payload["sequence"], int) or isinstance(payload["sequence"], bool):
        raise EvidenceIntegrityError("INVALID_JOURNAL_EVENT", f"line {line_number}")
    if not isinstance(payload["event_type"], str) or payload["event_type"] not in EVENT_TYPES:
        raise EvidenceIntegrityError("UNKNOWN_EVENT_TYPE", f"line {line_number}")
    if not isinstance(payload["timestamp"], str):
        raise EvidenceIntegrityError("INVALID_JOURNAL_EVENT", f"line {line_number}")
    for field_name in ("previous_digest", "digest"):
        value = payload[field_name]
        if (
            not isinstance(value, str)
            or not value.startswith("sha256:")
            or len(value) != 71
            or any(character not in "0123456789abcdef" for character in value[7:])
        ):
            raise EvidenceIntegrityError("INVALID_JOURNAL_EVENT", f"line {line_number}")
    return JournalEvent(**payload)


def _verify_journal_stream(source: BinaryIO) -> dict[str, object]:
    previous = "sha256:" + "0" * 64
    count = 0
    for line_number, line in enumerate(source, start=1):
        if not line.endswith(b"\n"):
            raise EvidenceIntegrityError("TRUNCATED_JOURNAL_RECORD", f"line {line_number}")
        event = _parse_event(line, line_number)
        if event.schema_version != JOURNAL_SCHEMA_VERSION:
            raise EvidenceIntegrityError("UNSUPPORTED_JOURNAL_SCHEMA", event.schema_version)
        if event.sequence != line_number:
            raise EvidenceIntegrityError("JOURNAL_SEQUENCE_MISMATCH", f"line {line_number}")
        if event.previous_digest != previous:
            raise EvidenceIntegrityError("JOURNAL_CHAIN_MISMATCH", f"line {line_number}")
        core = event.to_dict()
        core.pop("digest")
        expected = "sha256:" + hashlib.sha256(_canonical(core)).hexdigest()
        if event.digest != expected:
            raise EvidenceIntegrityError("JOURNAL_DIGEST_MISMATCH", f"line {line_number}")
        _validate_safe(event.data)
        previous = event.digest
        count += 1
    return {
        "schema_version": JOURNAL_SCHEMA_VERSION,
        "verified": True,
        "event_count": count,
        "head_digest": previous,
    }


def verify_journal(path: str | Path) -> dict[str, object]:
    with Path(path).open("rb") as source:
        return _verify_journal_stream(source)


def verify_journal_bytes(data: bytes) -> dict[str, object]:
    return _verify_journal_stream(BytesIO(data))
