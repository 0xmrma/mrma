from __future__ import annotations

import hashlib

import pytest

from mrma.core.raw_request import RawRequestParseError, parse_raw_http_request_bytes


def test_binary_body_header_order_duplicates_and_digest_are_preserved():
    raw = (
        b"POST /upload HTTP/1.1\r\n"
        b"Host: example.test\r\n"
        b"X-Value: first\r\n"
        b"X-Value: second\r\n"
        b"Content-Length: 5\r\n\r\n"
        b"\x00\xff\x01\x02\x03"
    )
    request = parse_raw_http_request_bytes(raw)

    assert request.body == b"\x00\xff\x01\x02\x03"
    assert request.headers[1:3] == [("X-Value", "first"), ("X-Value", "second")]
    assert request.source_line_ending == "crlf"
    assert request.original_sha256 == hashlib.sha256(raw).hexdigest()


def test_request_method_case_is_preserved():
    request = parse_raw_http_request_bytes(
        b"get / HTTP/1.1\r\nHost: example.test\r\n\r\n"
    )
    assert request.method == "get"


@pytest.mark.parametrize(
    ("line", "target_form", "eligible"),
    [
        (b"GET /path HTTP/1.0", "origin", True),
        (b"GET http://example.test/path HTTP/1.1", "absolute", True),
        (b"CONNECT example.test:443 HTTP/1.1", "authority", False),
        (b"OPTIONS * HTTP/1.1", "asterisk", False),
    ],
)
def test_request_target_forms_and_declared_version(line, target_form, eligible):
    request = parse_raw_http_request_bytes(line + b"\r\nHost: example.test\r\n\r\n")
    assert request.target_form == target_form
    assert request.semantic_replay_eligible is eligible
    assert request.http_version in {"HTTP/1.0", "HTTP/1.1"}


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        (b"GET / HTTP/1.1\r\nBad Name: x\r\n\r\n", "INVALID_HEADER_NAME"),
        (b"GET / HTTP/1.1\r\n Folded: x\r\n\r\n", "OBSOLETE_LINE_FOLDING"),
        (b"GET / HTTP/1.1\r\nX-Test: a\x00b\r\n\r\n", "NUL_OCTET"),
        (
            b"POST / HTTP/1.1\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\nx",
            "CONTENT_LENGTH_TRANSFER_ENCODING_CONFLICT",
        ),
        (b"POST / HTTP/1.1\r\nContent-Length: 2\r\n\r\nx", "CONTENT_LENGTH_MISMATCH"),
    ],
)
def test_invalid_or_ambiguous_framing_has_typed_errors(raw, code):
    with pytest.raises(RawRequestParseError) as captured:
        parse_raw_http_request_bytes(raw)
    assert captured.value.code == code
