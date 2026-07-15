from __future__ import annotations

import codecs
import re
from collections.abc import Iterable
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit, urlunsplit

_PERCENT_ESCAPE = re.compile(r"%([0-9A-Fa-f]{2})")
_TOKEN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
_CASE_INSENSITIVE_FIELD_NAME_SETS = frozenset(
    {
        "vary",
        "access-control-allow-headers",
        "access-control-expose-headers",
    }
)
_CASE_SENSITIVE_METHOD_SETS = frozenset({"allow", "access-control-allow-methods"})
_URI_REFERENCE_HEADERS = frozenset({"location", "content-location"})
SEMANTIC_REGISTRY_VERSION = "http-semantics/2.0"
_SUPPORTED_TEXT_CODECS = frozenset(
    {"utf-8", "us-ascii", "iso-8859-1", "utf-16", "utf-16le", "utf-16be"}
)
_JAVASCRIPT_TYPES = frozenset(
    {
        "text/javascript",
        "application/javascript",
        "application/ecmascript",
        "text/ecmascript",
        "application/x-javascript",
    }
)
_XML_DECLARATION = re.compile(
    r"^<\?xml[\t\r\n ]+[^?]*?encoding[\t\r\n ]*=[\t\r\n ]*(['\"])([A-Za-z][A-Za-z0-9._-]*)\1",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class _CacheControlAnalysis:
    values: tuple[object, ...]
    ambiguities: tuple[str, ...] = ()


@dataclass(frozen=True)
class ContentTypeAnalysis:
    media_type: str | None
    parameters: tuple[tuple[str, str], ...] = ()
    canonical_parameters: tuple[tuple[str, str], ...] = ()
    charset: str | None = None
    ambiguities: tuple[str, ...] = ()


@dataclass(frozen=True)
class CharsetResolution:
    declared_media_type: str | None
    declared_charset: str | None
    resolved_charset: str | None
    resolution_source: str
    eligible: bool
    reasons: tuple[str, ...] = ()
    registry_version: str = SEMANTIC_REGISTRY_VERSION


def _normalize_percent_encoding(value: str) -> str:
    def replace(match: re.Match[str]) -> str:
        octet = int(match.group(1), 16)
        character = chr(octet)
        return character if character in _UNRESERVED else f"%{octet:02X}"

    return _PERCENT_ESCAPE.sub(replace, value)


def _remove_last_segment(value: str) -> str:
    if not value:
        return ""
    return value.rsplit("/", 1)[0]


def _remove_dot_segments(path: str) -> str:
    """Apply RFC 3986 section 5.2.4 without collapsing meaningful empty segments."""
    remaining = path
    output = ""
    while remaining:
        if remaining.startswith("../"):
            remaining = remaining[3:]
        elif remaining.startswith("./"):
            remaining = remaining[2:]
        elif remaining.startswith("/./"):
            remaining = "/" + remaining[3:]
        elif remaining == "/.":
            remaining = "/"
        elif remaining.startswith("/../"):
            remaining = "/" + remaining[4:]
            output = _remove_last_segment(output)
        elif remaining == "/..":
            remaining = "/"
            output = _remove_last_segment(output)
        elif remaining in {".", ".."}:
            remaining = ""
        else:
            start = 1 if remaining.startswith("/") else 0
            boundary = remaining.find("/", start)
            if boundary == -1:
                output += remaining
                remaining = ""
            else:
                output += remaining[:boundary]
                remaining = remaining[boundary:]
    return output


def canonical_uri(reference: str, *, base_url: str | None = None) -> str:
    """Resolve and normalize a URI for semantic comparison, not display."""
    value = reference.strip()
    try:
        resolved = urljoin(base_url, value) if base_url else value
        parts = urlsplit(resolved)
        scheme = parts.scheme.lower()
        hostname = (parts.hostname or "").rstrip(".").lower()
        if hostname:
            hostname = hostname.encode("idna").decode("ascii")
        display_host = f"[{hostname}]" if ":" in hostname else hostname
        port = parts.port
        default_port = 443 if scheme == "https" else 80 if scheme == "http" else None
        port_text = "" if port in {None, default_port} else f":{port}"

        userinfo = ""
        if parts.username is not None:
            userinfo = _normalize_percent_encoding(parts.username)
            if parts.password is not None:
                userinfo += ":" + _normalize_percent_encoding(parts.password)
            userinfo += "@"

        path = _remove_dot_segments(_normalize_percent_encoding(parts.path or "/")) or "/"
        query = _normalize_percent_encoding(parts.query)
        fragment = _normalize_percent_encoding(parts.fragment)
        return urlunsplit((scheme, f"{userinfo}{display_host}{port_text}", path, query, fragment))
    except (UnicodeError, ValueError):
        return value


def _split_quoted_commas(values: Iterable[str]) -> tuple[list[str], bool]:
    fields: list[str] = []
    well_formed = True
    for value in values:
        start = 0
        quoted = False
        escaped = False
        for index, character in enumerate(value):
            if escaped:
                escaped = False
            elif character == "\\" and quoted:
                escaped = True
            elif character == '"':
                quoted = not quoted
            elif character == "," and not quoted:
                fields.append(value[start:index].strip())
                start = index + 1
        fields.append(value[start:].strip())
        if quoted or escaped:
            well_formed = False
    return [field for field in fields if field], well_formed


def _split_quoted(value: str, delimiter: str) -> tuple[list[str], bool]:
    parts: list[str] = []
    start = 0
    quoted = False
    escaped = False
    well_formed = True
    for index, character in enumerate(value):
        if escaped:
            codepoint = ord(character)
            if not (
                character in {"\t", " "}
                or 0x21 <= codepoint <= 0x7E
                or 0x80 <= codepoint <= 0xFF
            ):
                well_formed = False
            escaped = False
        elif character == "\\" and quoted:
            escaped = True
        elif character == '"':
            quoted = not quoted
        elif character == delimiter and not quoted:
            parts.append(value[start:index])
            start = index + 1
        elif quoted and not (
            character in {"\t", " "}
            or character == "!"
            or 0x23 <= ord(character) <= 0x5B
            or 0x5D <= ord(character) <= 0x7E
            or 0x80 <= ord(character) <= 0xFF
        ):
            well_formed = False
    parts.append(value[start:])
    return parts, well_formed and not quoted and not escaped


def _unquote(value: str) -> str:
    if len(value) < 2 or not (value.startswith('"') and value.endswith('"')):
        return value
    output: list[str] = []
    escaped = False
    for character in value[1:-1]:
        if escaped:
            output.append(character)
            escaped = False
        elif character == "\\":
            escaped = True
        else:
            output.append(character)
    if escaped:
        output.append("\\")
    return "".join(output)


def _cache_control(values: tuple[str, ...]) -> _CacheControlAnalysis:
    fields, well_formed = _split_quoted_commas(values)
    directives: list[tuple[str, str | None]] = []
    malformed = not well_formed
    for field in fields:
        name, separator, raw_value = field.partition("=")
        directive_name = name.strip().lower()
        raw_value = raw_value.strip()
        if not directive_name or _TOKEN.fullmatch(directive_name) is None:
            malformed = True
        if separator and not raw_value:
            malformed = True
        if separator and raw_value.startswith('"'):
            if not raw_value.endswith('"') or len(raw_value) < 2:
                malformed = True
        elif separator and _TOKEN.fullmatch(raw_value) is None:
            malformed = True
        directive_value = _unquote(raw_value) if separator else None
        directives.append((directive_name, directive_value))

    if malformed:
        ordered = tuple(value.strip() for value in values)
        return _CacheControlAnalysis(
            ("ambiguous-cache-control", "malformed-syntax", *ordered),
            ("malformed-syntax",),
        )

    names = [name for name, _ in directives]
    if len(names) != len(set(names)):
        return _CacheControlAnalysis(
            ("ambiguous-cache-control", "duplicate-directive", *directives),
            ("duplicate-directive",),
        )

    canonical = tuple(sorted(directives, key=lambda item: (item[0], item[1] or "")))
    return _CacheControlAnalysis(canonical)


def _content_type(values: tuple[str, ...]) -> ContentTypeAnalysis:
    if not values:
        return ContentTypeAnalysis(None)

    fields: list[str] = []
    well_formed = True
    for value in values:
        split, valid = _split_quoted(value, ",")
        fields.extend(part.strip(" \t") for part in split)
        well_formed = well_formed and valid
    if not well_formed:
        return ContentTypeAnalysis(None, ambiguities=("malformed-quoted-string",))
    if len(fields) != 1:
        return ContentTypeAnalysis(None, ambiguities=("multiple-values",))

    segments, well_formed = _split_quoted(fields[0], ";")
    if not well_formed:
        return ContentTypeAnalysis(None, ambiguities=("malformed-quoted-string",))
    media_type = segments[0].strip(" \t").lower()
    parts = media_type.split("/")
    if len(parts) != 2 or any(_TOKEN.fullmatch(part) is None for part in parts):
        return ContentTypeAnalysis(None, ambiguities=("malformed-media-type",))

    parsed: list[tuple[str, str]] = []
    canonical_parameters: list[tuple[str, str]] = []
    ambiguities: list[str] = []
    by_name: dict[str, str] = {}
    charset: str | None = None
    for raw_parameter in segments[1:]:
        parameter = raw_parameter.strip(" \t")
        name, separator, raw_value = parameter.partition("=")
        lowered_name = name.lower()
        if not separator or not raw_value:
            ambiguities.append("missing-parameter-value")
            continue
        if _TOKEN.fullmatch(name) is None:
            ambiguities.append("invalid-parameter-name")
            continue

        if raw_value.startswith('"'):
            value = _unquote(raw_value)
            if not raw_value.endswith('"') or len(raw_value) < 2:
                ambiguities.append("malformed-quoted-string")
                continue
        elif _TOKEN.fullmatch(raw_value) is not None:
            value = raw_value
        else:
            ambiguities.append("invalid-parameter-value")
            continue

        comparison_value = value
        parsed_charset: str | None = None
        if lowered_name == "charset":
            canonical_charset = _canonical_charset(value)
            if canonical_charset is None:
                comparison_value = value.lower()
                ambiguities.append("unsupported-charset")
            else:
                comparison_value = canonical_charset
                parsed_charset = canonical_charset
        if lowered_name in by_name:
            if by_name[lowered_name] != comparison_value:
                ambiguities.append("conflicting-duplicate-parameter")
            continue
        by_name[lowered_name] = comparison_value
        if parsed_charset is not None:
            charset = parsed_charset
        parsed.append((lowered_name, value))
        canonical_parameters.append((lowered_name, comparison_value))

    unique_ambiguities = tuple(dict.fromkeys(ambiguities))
    return ContentTypeAnalysis(
        media_type if not unique_ambiguities else None,
        parameters=tuple(parsed),
        canonical_parameters=tuple(
            sorted(canonical_parameters, key=lambda item: (item[0], item[1]))
        ),
        charset=charset,
        ambiguities=unique_ambiguities,
    )


def _canonical_charset(value: str) -> str | None:
    try:
        codec = codecs.lookup(value).name
    except LookupError:
        return None
    return {
        "utf-8": "utf-8",
        "ascii": "us-ascii",
        "iso8859-1": "iso-8859-1",
        "latin-1": "iso-8859-1",
        "utf-16": "utf-16",
        "utf-16-le": "utf-16le",
        "utf-16-be": "utf-16be",
        "utf-32": "utf-32",
        "utf-32-le": "utf-32le",
        "utf-32-be": "utf-32be",
    }.get(codec, codec)


def _xml_encoding_sources(body: bytes) -> tuple[str | None, str | None, tuple[str, ...]]:
    prefix = body[:1024]
    reasons: list[str] = []
    bom: str | None = None
    decoder = "latin-1"
    skip = 0
    if prefix.startswith(b"\x00\x00\xfe\xff") or prefix.startswith(b"\xff\xfe\x00\x00"):
        return "utf-32", None, ("unsupported-xml-utf32",)
    if prefix.startswith(b"\xef\xbb\xbf"):
        bom, decoder, skip = "utf-8", "utf-8", 3
    elif prefix.startswith(b"\xfe\xff"):
        bom, decoder, skip = "utf-16be", "utf-16-be", 2
    elif prefix.startswith(b"\xff\xfe"):
        bom, decoder, skip = "utf-16le", "utf-16-le", 2
    elif prefix.startswith(b"\x00\x3c\x00\x3f"):
        decoder = "utf-16-be"
    elif prefix.startswith(b"\x3c\x00\x3f\x00"):
        decoder = "utf-16-le"
    elif prefix.startswith(b"\x00\x00\x00\x3c") or prefix.startswith(b"\x3c\x00\x00\x00"):
        return "utf-32", None, ("unsupported-xml-utf32",)
    try:
        declaration_text = prefix[skip:].decode(decoder, errors="strict")
    except UnicodeDecodeError:
        return bom, None, ("invalid-xml-encoding-prefix",)
    declaration = _XML_DECLARATION.match(declaration_text)
    declared: str | None = None
    if declaration is not None:
        declared = _canonical_charset(declaration.group(2))
        if declared is None:
            reasons.append("unsupported-xml-declaration-encoding")
    return bom, declared, tuple(reasons)


def _javascript_bom(body: bytes) -> str | None:
    if body.startswith(b"\xef\xbb\xbf"):
        return "utf-8"
    if body.startswith(b"\xff\xfe"):
        return "utf-16le"
    if body.startswith(b"\xfe\xff"):
        return "utf-16be"
    return None


def _strict_body_decodes(body: bytes, charset: str) -> bool:
    decoder = {
        "us-ascii": "ascii",
        "iso-8859-1": "iso-8859-1",
        "utf-16le": "utf-16-le",
        "utf-16be": "utf-16-be",
    }.get(charset, charset)
    try:
        body.decode(decoder, errors="strict")
    except (UnicodeDecodeError, LookupError):
        return False
    return True


def resolve_charset(
    values: tuple[str, ...],
    body: bytes,
    *,
    assume_text_without_content_type: bool = False,
) -> CharsetResolution:
    """Resolve text eligibility under media-type-specific, conservative rules."""
    if not values:
        if assume_text_without_content_type:
            eligible = _strict_body_decodes(body, "utf-8")
            return CharsetResolution(
                None,
                None,
                "utf-8" if eligible else None,
                "explicit-user-override",
                eligible,
                () if eligible else ("invalid-body-encoding",),
            )
        return CharsetResolution(None, None, None, "none", False, ("missing-content-type",))

    analysis = _content_type(values)
    if analysis.ambiguities:
        return CharsetResolution(
            None,
            analysis.charset,
            None,
            "rejected",
            False,
            analysis.ambiguities,
        )
    media_type = analysis.media_type
    declared = analysis.charset
    assert media_type is not None
    resolved: str | None = None
    source = "none"
    reasons: list[str] = []

    is_json = media_type == "application/json" or media_type.endswith("+json")
    is_xml = media_type in {"application/xml", "text/xml"} or media_type.endswith("+xml")
    if is_json:
        if declared is not None and declared != "utf-8":
            reasons.append("json-non-utf8-charset")
        else:
            resolved, source = "utf-8", "json-default" if declared is None else "http-charset"
    elif is_xml:
        bom, xml_declaration, xml_reasons = _xml_encoding_sources(body)
        reasons.extend(xml_reasons)
        sources = [value for value in (bom, declared, xml_declaration) if value is not None]
        compatible = {"utf-16", "utf-16le", "utf-16be"}
        if len(set(sources)) > 1 and not set(sources).issubset(compatible):
            reasons.append("conflicting-xml-encoding-sources")
        elif bom is not None:
            resolved, source = bom, "xml-bom"
        elif declared is not None:
            resolved, source = declared, "http-charset"
        elif xml_declaration is not None:
            resolved, source = xml_declaration, "xml-declaration"
        else:
            resolved, source = "utf-8", "xml-default"
    elif media_type in _JAVASCRIPT_TYPES:
        bom = _javascript_bom(body)
        if bom is not None and declared is not None and bom != declared:
            reasons.append("conflicting-javascript-encoding-sources")
        elif bom is not None:
            resolved, source = bom, "javascript-bom"
        elif declared is not None:
            resolved, source = declared, "http-charset"
        else:
            resolved, source = "utf-8", "javascript-default"
    elif media_type == "application/x-www-form-urlencoded":
        if declared is None:
            reasons.append("form-charset-not-declared")
        else:
            resolved, source = declared, "http-charset"
    elif media_type.startswith("text/"):
        if media_type == "text/plain":
            if declared is None:
                resolved, source = "us-ascii", "text-plain-default"
            else:
                resolved, source = declared, "http-charset"
        else:
            reasons.append("unknown-text-subtype")
    else:
        reasons.append("unsupported-media-type")

    if resolved is not None and resolved not in _SUPPORTED_TEXT_CODECS:
        reasons.append("unsupported-resolved-charset")
    if reasons:
        resolved = None
        source = "rejected"
    elif resolved is not None and not _strict_body_decodes(body, resolved):
        reasons.append("invalid-body-encoding")
        resolved = None
        source = "rejected"
    return CharsetResolution(
        media_type,
        declared,
        resolved,
        source,
        resolved is not None and not reasons,
        tuple(dict.fromkeys(reasons)),
    )


def content_type_analysis(values: tuple[str, ...]) -> ContentTypeAnalysis:
    """Parse one Content-Type declaration under conservative HTTP field semantics."""
    return _content_type(values)


def content_type_media_type(values: tuple[str, ...]) -> str | None:
    """Return one unambiguous declared media type, or None for absent/invalid evidence."""
    analysis = _content_type(values)
    return analysis.media_type if not analysis.ambiguities else None


def header_semantic_ambiguities(name: str, values: tuple[str, ...]) -> tuple[str, ...]:
    """Return stable ambiguity reasons for fields that cannot be safely canonicalized."""
    lowered = name.lower()
    if lowered == "cache-control":
        return _cache_control(values).ambiguities
    if lowered == "content-type":
        return _content_type(values).ambiguities
    return ()


def canonical_header_values(
    name: str,
    values: tuple[str, ...],
    *,
    base_url: str | None = None,
) -> tuple[object, ...]:
    """Canonicalize only fields whose semantics are explicitly understood."""
    lowered = name.lower()
    if lowered in _CASE_INSENSITIVE_FIELD_NAME_SETS:
        tokens = {
            token.strip().lower() for value in values for token in value.split(",") if token.strip()
        }
        return tuple(sorted(tokens))
    if lowered in _CASE_SENSITIVE_METHOD_SETS:
        tokens = {token.strip() for value in values for token in value.split(",") if token.strip()}
        return tuple(sorted(tokens))
    if lowered == "cache-control":
        return _cache_control(values).values
    if lowered == "content-type":
        analysis = _content_type(values)
        if analysis.ambiguities or analysis.media_type is None:
            return (
                "ambiguous-content-type",
                *analysis.ambiguities,
                *(value.strip() for value in values),
            )
        return (analysis.media_type, *analysis.canonical_parameters)
    if lowered in _URI_REFERENCE_HEADERS and base_url:
        return tuple(canonical_uri(value, base_url=base_url) for value in values)
    return values
