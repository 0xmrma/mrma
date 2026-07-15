from __future__ import annotations

import subprocess
import sys

import pytest

from mrma.core.compare import EquivalenceConfig, equivalent_response
from mrma.core.http_semantics import (
    SEMANTIC_REGISTRY_VERSION,
    canonical_header_values,
    resolve_charset,
)


def test_content_type_equivalence_uses_full_parser():
    assert canonical_header_values(
        "content-type", ("text/html;charset=utf-8",)
    ) == canonical_header_values(
        "content-type", ('Text/HTML;Charset="UTF-8"',)
    )
    assert canonical_header_values(
        "content-type", ("application/example; a=one; b=two",)
    ) == canonical_header_values(
        "content-type", ('Application/Example; B="two"; A=one',)
    )


def test_multipart_boundary_values_remain_case_sensitive():
    lower = canonical_header_values(
        "content-type", ("multipart/form-data; boundary=example",)
    )
    upper = canonical_header_values(
        "content-type", ("multipart/form-data; boundary=Example",)
    )
    assert lower != upper


def test_malformed_and_conflicting_content_type_preserve_ordered_raw_values():
    left = canonical_header_values(
        "content-type", ("text/plain; charset=utf-8; charset=us-ascii",)
    )
    right = canonical_header_values(
        "content-type", ("text/plain; charset=us-ascii; charset=utf-8",)
    )
    assert left != right
    assert left[0] == "ambiguous-content-type"


def test_media_specific_charset_resolution():
    json_resolution = resolve_charset(("application/problem+json",), b'{"ok":true}')
    assert json_resolution.eligible is True
    assert json_resolution.resolved_charset == "utf-8"
    assert json_resolution.resolution_source == "json-default"
    assert json_resolution.registry_version == SEMANTIC_REGISTRY_VERSION

    plain = resolve_charset(("text/plain",), b"ASCII only")
    assert plain.eligible is True
    assert plain.resolved_charset == "us-ascii"
    assert plain.resolution_source == "text-plain-default"

    non_ascii_plain = resolve_charset(("text/plain",), "caf\N{LATIN SMALL LETTER E WITH ACUTE}".encode())
    assert non_ascii_plain.eligible is False
    assert non_ascii_plain.reasons == ("invalid-body-encoding",)

    latin = resolve_charset(
        ("text/plain; charset=iso-8859-1",),
        b"caf\xe9",
    )
    assert latin.eligible is True
    assert latin.resolved_charset == "iso-8859-1"

    unknown = resolve_charset(("text/x-private",), b"hello")
    assert unknown.eligible is False
    assert unknown.reasons == ("unknown-text-subtype",)
    declared_unknown = resolve_charset(
        ("text/x-private; charset=utf-8",), b"hello"
    )
    assert declared_unknown.eligible is False
    assert declared_unknown.reasons == ("unknown-text-subtype",)


def test_xml_bom_declaration_and_http_charset_must_not_conflict():
    valid = resolve_charset(
        ("application/xml",),
        b"\xff\xfe" + '<?xml version="1.0" encoding="utf-16"?><x/>'.encode("utf-16-le"),
    )
    assert valid.eligible is True
    assert valid.resolved_charset == "utf-16le"
    assert valid.resolution_source == "xml-bom"

    conflict = resolve_charset(
        ("application/xml; charset=utf-8",),
        b"\xff\xfe" + '<?xml version="1.0"?><x/>'.encode("utf-16-le"),
    )
    assert conflict.eligible is False
    assert "conflicting-xml-encoding-sources" in conflict.reasons


def test_json_duplicate_keys_and_nonfinite_constants_disable_canonical_json():
    duplicate = equivalent_response(
        200,
        b'{"a":1,"a":2,"b":3}',
        200,
        b'{"b":3,"a":1,"a":2}',
        EquivalenceConfig(preset="api-json", min_similarity=0.0, max_len_delta_ratio=1.0),
    )
    assert "guarded-json" not in duplicate.comparator

    nonfinite = equivalent_response(
        200,
        b'{"a":NaN,"b":1}',
        200,
        b'{"b":1,"a":NaN}',
        EquivalenceConfig(preset="api-json", min_similarity=0.0, max_len_delta_ratio=1.0),
    )
    assert "guarded-json" not in nonfinite.comparator


def test_user_regex_timeout_is_indeterminate(monkeypatch):
    def timeout(*_args, **_kwargs):
        raise TimeoutError("bounded test timeout")

    monkeypatch.setattr("mrma.core.compare.regex.sub", timeout)
    result = equivalent_response(
        200,
        b"aaaa",
        200,
        b"aaab",
        EquivalenceConfig(ignore_body_regex=("a+",)),
    )
    assert result.completed is False
    assert result.resource_limit == "NORMALIZATION_RULE_TIMEOUT"
    assert result.normalization_outcomes[0].outcome == "timeout"


@pytest.mark.skipif(sys.platform == "win32" and sys.version_info < (3, 10), reason="unsupported")
def test_catastrophic_regex_cannot_hang_a_process():
    code = """
from mrma.core.compare import EquivalenceConfig, equivalent_response
r = equivalent_response(200, b'a' * 200000 + b'!', 200, b'a', EquivalenceConfig(
    ignore_body_regex=(r'(a+)+$',), regex_rule_timeout_s=0.001, normalization_timeout_s=0.01))
assert not r.completed and r.resource_limit == 'NORMALIZATION_RULE_TIMEOUT'
"""
    completed = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
