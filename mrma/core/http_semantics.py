from __future__ import annotations

import re
from collections.abc import Iterable
from urllib.parse import urljoin, urlsplit, urlunsplit

_PERCENT_ESCAPE = re.compile(r"%([0-9A-Fa-f]{2})")
_UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
_CASE_INSENSITIVE_TOKEN_SETS = frozenset(
    {
        "allow",
        "vary",
        "access-control-allow-headers",
        "access-control-allow-methods",
        "access-control-expose-headers",
    }
)
_URI_REFERENCE_HEADERS = frozenset({"location", "content-location"})


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


def _split_quoted_commas(values: Iterable[str]) -> list[str]:
    fields: list[str] = []
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
    return [field for field in fields if field]


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


def _cache_control(values: tuple[str, ...]) -> tuple[tuple[str, str | None], ...]:
    directives: list[tuple[str, str | None]] = []
    for field in _split_quoted_commas(values):
        name, separator, raw_value = field.partition("=")
        directive_name = name.strip().lower()
        if not directive_name:
            continue
        directive_value = _unquote(raw_value.strip()) if separator else None
        directives.append((directive_name, directive_value))
    return tuple(sorted(directives, key=lambda item: (item[0], item[1] or "")))


def canonical_header_values(
    name: str,
    values: tuple[str, ...],
    *,
    base_url: str | None = None,
) -> tuple[object, ...]:
    """Canonicalize only fields whose semantics are explicitly understood."""
    lowered = name.lower()
    if lowered in _CASE_INSENSITIVE_TOKEN_SETS:
        tokens = {
            token.strip().lower() for value in values for token in value.split(",") if token.strip()
        }
        return tuple(sorted(tokens))
    if lowered == "cache-control":
        return _cache_control(values)
    if lowered in _URI_REFERENCE_HEADERS and base_url:
        return tuple(canonical_uri(value, base_url=base_url) for value in values)
    return values
