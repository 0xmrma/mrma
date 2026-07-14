from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from difflib import SequenceMatcher

MAX_SEQUENCE_BYTES = 256 * 1024


@dataclass(frozen=True)
class EquivalenceConfig:
    min_similarity: float = 0.985
    max_len_delta_ratio: float = 0.02
    require_same_status: bool = True
    preset: str = "default"
    ignore_headers: tuple[str, ...] = ()
    ignore_body_regex: tuple[str, ...] = ()


@dataclass(frozen=True)
class EffectiveEquivalencePolicy:
    preset: str
    min_similarity: float
    max_len_delta_ratio: float
    require_same_status: bool
    ignore_headers: tuple[str, ...]
    ignore_body_regex: tuple[str, ...]
    max_sequence_bytes: int = MAX_SEQUENCE_BYTES

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class CompareResult:
    equivalent: bool
    sim: float
    status_a: int
    status_b: int
    len_a: int
    len_b: int
    comparator: str


def _preset_defaults(preset: str) -> dict[str, tuple[str, ...]]:
    p = (preset or "default").lower().strip()
    if p == "nextjs":
        return {
            "ignore_headers": (
                "set-cookie",
                "date",
                "etag",
                "x-vercel-id",
                "x-matched-path",
                "x-powered-by",
                "x-nextjs-cache",
                "x-nextjs-page",
                "x-nextjs-router-state-tree",
                "x-nextjs-data",
                "vary",
            ),
            "ignore_body_regex": (
                r'"buildId"\s*:\s*"[A-Za-z0-9\-_]+"',
                r'"requestId"\s*:\s*"[A-Za-z0-9\-_]+"',
                r'"traceId"\s*:\s*"[A-Za-z0-9\-_]+"',
                r'"nonce"\s*:\s*"[A-Za-z0-9\-_]+"',
            ),
        }
    if p == "api-json":
        return {
            "ignore_headers": ("set-cookie", "date", "etag"),
            "ignore_body_regex": (
                r'"(timestamp|time|ts)"\s*:\s*"?\d+"?',
                r'"(request_id|requestId|trace_id|traceId)"\s*:\s*"[A-Za-z0-9\-_]+"',
                r'"(nonce|csrf|token)"\s*:\s*"[A-Za-z0-9\-_\.]+"',
            ),
        }
    return {"ignore_headers": (), "ignore_body_regex": ()}


def _unique(values: tuple[str, ...], *, lower: bool = False) -> tuple[str, ...]:
    normalized = ((value.lower() if lower else value) for value in values)
    return tuple(dict.fromkeys(normalized))


def resolve_equivalence_policy(cfg: EquivalenceConfig) -> EffectiveEquivalencePolicy:
    preset_name = (cfg.preset or "default").lower().strip()
    if preset_name not in {"default", "dynamic", "nextjs", "api-json"}:
        raise ValueError(f"unknown equivalence preset: {cfg.preset!r}")
    defaults = _preset_defaults(preset_name)
    body_patterns = _unique(defaults["ignore_body_regex"] + cfg.ignore_body_regex)
    for pattern in body_patterns:
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ValueError(f"invalid ignore_body_regex {pattern!r}: {exc}") from exc
    return EffectiveEquivalencePolicy(
        preset=preset_name,
        min_similarity=cfg.min_similarity,
        max_len_delta_ratio=cfg.max_len_delta_ratio,
        require_same_status=cfg.require_same_status,
        ignore_headers=_unique(defaults["ignore_headers"] + cfg.ignore_headers, lower=True),
        ignore_body_regex=body_patterns,
    )


def _apply_body_ignores(body: bytes, patterns: tuple[str, ...]) -> bytes:
    if not patterns or not body:
        return body
    text = body.decode("utf-8", errors="replace")
    for pattern in patterns:
        text = re.sub(pattern, "<MRMA_IGNORED>", text, flags=re.MULTILINE)
    return text.encode("utf-8", errors="replace")


def normalize_text(body: bytes, preset: str = "default") -> str:
    text = body.decode("utf-8", errors="replace")
    preset_name = (preset or "default").lower().strip()

    text = re.sub(
        r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
        r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b",
        "<UUID>",
        text,
    )
    text = re.sub(r"\b[0-9a-fA-F]{32,}\b", "<HEX>", text)
    text = re.sub(r"\b1[0-9]{9}\b", "<TS>", text)

    if preset_name in ("dynamic", "nextjs"):
        text = re.sub(r"\b[A-Za-z0-9+/]{200,}={0,2}\b", "<B64>", text)
        text = re.sub(
            r"(<script[^>]*>)(?s:.*?)(</script>)",
            r"\1<SCRIPT>\2",
            text,
            flags=re.IGNORECASE,
        )
        text = re.sub(
            r'("csrfToken"\s*:\s*)".*?"',
            r'\1"<TOKEN>"',
            text,
            flags=re.IGNORECASE,
        )
        text = re.sub(
            r'("token"\s*:\s*)".*?"',
            r'\1"<TOKEN>"',
            text,
            flags=re.IGNORECASE,
        )

    if preset_name == "nextjs":
        for field, marker in (
            ("buildId", "BUILDID"),
            ("requestId", "REQID"),
            ("traceId", "TRACEID"),
            ("nonce", "NONCE"),
        ):
            text = re.sub(
                rf'("{field}"\s*:\s*)".*?"',
                rf'\1"<{marker}>"',
                text,
                flags=re.IGNORECASE,
            )

    if preset_name == "api-json":
        text = re.sub(
            r'("timestamp"|"time"|"ts")\s*:\s*"?\d+"?',
            r'"ts":"<TS>"',
            text,
            flags=re.IGNORECASE,
        )
        text = re.sub(
            r'("request_id"|"requestId"|"trace_id"|"traceId")\s*:\s*'
            r'"[A-Za-z0-9\-_]+"',
            r'"id":"<ID>"',
            text,
            flags=re.IGNORECASE,
        )
        text = re.sub(
            r'("nonce"|"csrf"|"token")\s*:\s*"[A-Za-z0-9\-_\.]+"',
            r'"token":"<TOKEN>"',
            text,
            flags=re.IGNORECASE,
        )

    return text


def _canonical_json(text: str) -> str | None:
    try:
        value = json.loads(text)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def similarity(
    a: bytes,
    b: bytes,
    preset: str = "default",
    max_sequence_bytes: int = MAX_SEQUENCE_BYTES,
) -> tuple[float, str]:
    if a == b:
        return 1.0, "exact-bytes"
    if max(len(a), len(b)) > max_sequence_bytes:
        return 0.0, "bounded-size"

    text_a = normalize_text(a, preset=preset)
    text_b = normalize_text(b, preset=preset)
    if preset == "api-json":
        json_a = _canonical_json(text_a)
        json_b = _canonical_json(text_b)
        if json_a is not None and json_b is not None:
            text_a, text_b = json_a, json_b
            comparator = "canonical-json"
        else:
            comparator = "bounded-text"
    else:
        comparator = "bounded-text"
    return SequenceMatcher(None, text_a, text_b, autojunk=True).ratio(), comparator


def equivalent_response(
    status_a: int,
    body_a: bytes,
    status_b: int,
    body_b: bytes,
    cfg: EquivalenceConfig | EffectiveEquivalencePolicy,
) -> CompareResult:
    policy = cfg if isinstance(cfg, EffectiveEquivalencePolicy) else resolve_equivalence_policy(cfg)
    body_a2 = _apply_body_ignores(body_a, policy.ignore_body_regex)
    body_b2 = _apply_body_ignores(body_b, policy.ignore_body_regex)
    sim, comparator = similarity(
        body_a2,
        body_b2,
        preset=policy.preset,
        max_sequence_bytes=policy.max_sequence_bytes,
    )
    len_a, len_b = len(body_a2), len(body_b2)

    if policy.require_same_status and status_a != status_b:
        return CompareResult(False, sim, status_a, status_b, len_a, len_b, comparator)

    length_delta_ratio = abs(len_b - len_a) / max(len_a, 1)
    equivalent = (
        sim >= policy.min_similarity and length_delta_ratio <= policy.max_len_delta_ratio
    )
    return CompareResult(equivalent, sim, status_a, status_b, len_a, len_b, comparator)
