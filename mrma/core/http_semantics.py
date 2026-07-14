from __future__ import annotations

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


@dataclass(frozen=True)
class _CacheControlAnalysis:
    values: tuple[object, ...]
    ambiguities: tuple[str, ...] = ()


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


def header_semantic_ambiguities(name: str, values: tuple[str, ...]) -> tuple[str, ...]:
    """Return stable ambiguity reasons for fields that cannot be safely canonicalized."""
    if name.lower() == "cache-control":
        return _cache_control(values).ambiguities
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
    if lowered in _URI_REFERENCE_HEADERS and base_url:
        return tuple(canonical_uri(value, base_url=base_url) for value in values)
    return values
