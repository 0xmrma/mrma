from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

_TOKEN = re.compile(rb"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_AUTHORITY = re.compile(r"^(?:\[[0-9A-Fa-f:.]+\]|[^:/\s]+):[0-9]{1,5}$")


class RawRequestParseError(ValueError):
    """A stable, machine-readable rejection for malformed raw HTTP input."""

    def __init__(self, code: str, message: str, *, line: int | None = None) -> None:
        self.code = code
        self.line = line
        location = f" at line {line}" if line is not None else ""
        super().__init__(f"{code}{location}: {message}")


@dataclass
class RawRequest:
    method: str
    path: str
    http_version: str
    headers: list[tuple[str, str]]
    body: bytes
    target_form: str = "origin"
    original_sha256: str | None = None
    source_line_ending: str = "unknown"
    semantic_replay_eligible: bool = True
    semantic_replay_limitations: tuple[str, ...] = ()

    def header_dict_last_wins(self) -> dict[str, str]:
        result: dict[str, str] = {}
        for name, value in self.headers:
            result[name] = value
        return result


def _reject_controls(value: bytes, *, line: int, header_value: bool = False) -> None:
    for octet in value:
        if octet == 0:
            raise RawRequestParseError("NUL_OCTET", "NUL is not valid in request metadata", line=line)
        if octet < 0x20 and not (header_value and octet == 0x09):
            raise RawRequestParseError(
                "CONTROL_OCTET",
                "bare control octet is not valid in request metadata",
                line=line,
            )
        if octet == 0x7F:
            raise RawRequestParseError(
                "CONTROL_OCTET",
                "DEL is not valid in request metadata",
                line=line,
            )


def _split_head_body(data: bytes) -> tuple[bytes, bytes, bytes, str]:
    crlf_boundary = data.find(b"\r\n\r\n")
    lf_boundary = data.find(b"\n\n")
    if crlf_boundary >= 0 and (lf_boundary < 0 or crlf_boundary <= lf_boundary):
        head = data[:crlf_boundary]
        return head, data[crlf_boundary + 4 :], b"\r\n", "crlf"
    if lf_boundary >= 0:
        head = data[:lf_boundary]
        if b"\r" in head:
            raise RawRequestParseError(
                "MIXED_LINE_ENDINGS",
                "request metadata contains mixed or bare CR line endings",
            )
        return head, data[lf_boundary + 2 :], b"\n", "lf"
    if b"\r" in data:
        if b"\r\n" not in data or data.replace(b"\r\n", b"").find(b"\r") >= 0:
            raise RawRequestParseError("BARE_CR", "bare CR is not a valid line ending")
        return data, b"", b"\r\n", "crlf"
    return data, b"", b"\n", "lf"


def _target_form(method: str, target: str) -> str:
    if target == "*":
        return "asterisk"
    if target.startswith("/"):
        return "origin"
    parsed = urlsplit(target)
    if parsed.scheme and parsed.netloc:
        if parsed.scheme.lower() not in {"http", "https"}:
            raise RawRequestParseError(
                "UNSUPPORTED_ABSOLUTE_SCHEME",
                "absolute-form targets must use http or https",
                line=1,
            )
        return "absolute"
    if method == "CONNECT" and _AUTHORITY.fullmatch(target):
        port_text = target.rsplit(":", 1)[1]
        if not 1 <= int(port_text) <= 65535:
            raise RawRequestParseError("INVALID_AUTHORITY_PORT", "port is out of range", line=1)
        return "authority"
    raise RawRequestParseError("INVALID_REQUEST_TARGET", "unsupported request-target form", line=1)


def _validate_framing(headers: list[tuple[str, str]], body: bytes) -> tuple[bool, tuple[str, ...]]:
    content_lengths = [value.strip() for name, value in headers if name.lower() == "content-length"]
    transfer_encodings = [value.strip() for name, value in headers if name.lower() == "transfer-encoding"]
    if content_lengths and transfer_encodings:
        raise RawRequestParseError(
            "CONTENT_LENGTH_TRANSFER_ENCODING_CONFLICT",
            "Content-Length and Transfer-Encoding cannot be replayed together",
        )
    if content_lengths:
        parsed_lengths: list[int] = []
        for value in content_lengths:
            if not value.isascii() or not value.isdigit():
                raise RawRequestParseError("INVALID_CONTENT_LENGTH", "Content-Length must be decimal")
            parsed_lengths.append(int(value))
        if len(set(parsed_lengths)) != 1:
            raise RawRequestParseError(
                "CONFLICTING_CONTENT_LENGTH",
                "duplicate Content-Length values disagree",
            )
        if parsed_lengths[0] != len(body):
            raise RawRequestParseError(
                "CONTENT_LENGTH_MISMATCH",
                "Content-Length does not match retained body bytes",
            )
    if transfer_encodings:
        return False, ("transfer-coding-not-wire-preserved",)
    return True, ()


def parse_raw_http_request_bytes(data: bytes) -> RawRequest:
    """Parse strict raw HTTP/1 request bytes while retaining the body exactly."""
    if not data:
        raise RawRequestParseError("EMPTY_REQUEST", "request input is empty")
    head, body, separator, line_ending = _split_head_body(data)
    lines = head.split(separator)
    if not lines or not lines[0]:
        raise RawRequestParseError("EMPTY_REQUEST_LINE", "request line is missing", line=1)

    request_line = lines[0]
    _reject_controls(request_line, line=1)
    parts = request_line.split(b" ")
    if len(parts) != 3 or any(not part for part in parts):
        raise RawRequestParseError(
            "MALFORMED_REQUEST_LINE",
            "request line must contain METHOD SP TARGET SP HTTP/VERSION",
            line=1,
        )
    method_bytes, target_bytes, version_bytes = parts
    if _TOKEN.fullmatch(method_bytes) is None:
        raise RawRequestParseError("INVALID_METHOD", "method is not an HTTP token", line=1)
    if version_bytes not in {b"HTTP/1.0", b"HTTP/1.1"}:
        raise RawRequestParseError(
            "UNSUPPORTED_HTTP_VERSION",
            "only declared HTTP/1.0 and HTTP/1.1 input is accepted",
            line=1,
        )
    try:
        method = method_bytes.decode("ascii")
        target = target_bytes.decode("ascii")
        version = version_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise RawRequestParseError(
            "NON_ASCII_REQUEST_LINE",
            "request line must be ASCII",
            line=1,
        ) from exc
    target_form = _target_form(method, target)

    headers: list[tuple[str, str]] = []
    for line_number, line in enumerate(lines[1:], start=2):
        if not line:
            raise RawRequestParseError(
                "UNEXPECTED_EMPTY_HEADER_LINE",
                "empty metadata line appeared before the header boundary",
                line=line_number,
            )
        if line[:1] in {b" ", b"\t"}:
            raise RawRequestParseError(
                "OBSOLETE_LINE_FOLDING",
                "folded header fields are rejected",
                line=line_number,
            )
        if b":" not in line:
            raise RawRequestParseError(
                "MISSING_HEADER_COLON",
                "header field is missing ':'",
                line=line_number,
            )
        raw_name, raw_value = line.split(b":", 1)
        if not raw_name or raw_name[-1:] in {b" ", b"\t"} or _TOKEN.fullmatch(raw_name) is None:
            raise RawRequestParseError(
                "INVALID_HEADER_NAME",
                "header field name is not a strict HTTP token",
                line=line_number,
            )
        _reject_controls(raw_name, line=line_number)
        _reject_controls(raw_value, line=line_number, header_value=True)
        name = raw_name.decode("ascii")
        value = raw_value.strip(b" \t").decode("latin-1")
        headers.append((name, value))

    eligible, limitations = _validate_framing(headers, body)
    if target_form in {"authority", "asterisk"}:
        eligible = False
        limitations += (f"{target_form}-form-not-supported-by-semantic-http",)

    return RawRequest(
        method=method,
        path=target,
        http_version=version,
        headers=headers,
        body=body,
        target_form=target_form,
        original_sha256=hashlib.sha256(data).hexdigest(),
        source_line_ending=line_ending,
        semantic_replay_eligible=eligible,
        semantic_replay_limitations=limitations,
    )


def parse_raw_http_request(text: str) -> RawRequest:
    """Compatibility wrapper; text input cannot preserve non-UTF-8 source bytes."""
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    return parse_raw_http_request_bytes(normalized.encode("utf-8"))
