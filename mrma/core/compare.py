from __future__ import annotations

import re
from dataclasses import dataclass
from difflib import SequenceMatcher


def normalize_text(b: bytes, preset: str = "default") -> str:
    """
    preset:
      - default: conservative normalization
      - dynamic: stronger normalization for tokenized pages
      - nextjs: dynamic + extra Next/Vercel noise stripping
      - api-json: normalize common JSON API noise
    """
    s = b.decode("utf-8", errors="replace")
    p = (preset or "default").lower().strip()

    # Conservative: UUIDs, long hex, timestamps
    s = re.sub(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b", "<UUID>", s)
    s = re.sub(r"\b[0-9a-fA-F]{32,}\b", "<HEX>", s)
    s = re.sub(r"\b1[0-9]{9}\b", "<TS>", s)

    # dynamic / nextjs: stronger
    if p in ("dynamic", "nextjs"):
        # Strip long base64-ish blobs
        s = re.sub(r"\b[A-Za-z0-9+/]{200,}={0,2}\b", "<B64>", s)

        # Strip script blobs
        s = re.sub(r"(<script[^>]*>)(?s:.*?)(</script>)", r"\1<SCRIPT>\2", s, flags=re.IGNORECASE)

        # Strip common token-like fields
        s = re.sub(r'("csrfToken"\s*:\s*)".*?"', r'\1"<TOKEN>"', s, flags=re.IGNORECASE)
        s = re.sub(r'("token"\s*:\s*)".*?"', r'\1"<TOKEN>"', s, flags=re.IGNORECASE)

    # nextjs: extra common fields
    if p == "nextjs":
        s = re.sub(r'("buildId"\s*:\s*)".*?"', r'\1"<BUILDID>"', s, flags=re.IGNORECASE)
        s = re.sub(r'("requestId"\s*:\s*)".*?"', r'\1"<REQID>"', s, flags=re.IGNORECASE)
        s = re.sub(r'("traceId"\s*:\s*)".*?"', r'\1"<TRACEID>"', s, flags=re.IGNORECASE)
        s = re.sub(r'("nonce"\s*:\s*)".*?"', r'\1"<NONCE>"', s, flags=re.IGNORECASE)

    # api-json: normalize frequent JSON keys (simple, no full JSON parsing)
    if p == "api-json":
        s = re.sub(r'("timestamp"|"time"|"ts")\s*:\s*"?\d+"?', r'"ts":"<TS>"', s, flags=re.IGNORECASE)
        s = re.sub(r'("request_id"|"requestId"|"trace_id"|"traceId")\s*:\s*"[A-Za-z0-9\-_]+"', r'"id":"<ID>"', s, flags=re.IGNORECASE)
        s = re.sub(r'("nonce"|"csrf"|"token")\s*:\s*"[A-Za-z0-9\-_\.]+"', r'"token":"<TOKEN>"', s, flags=re.IGNORECASE)

    return s

def similarity(a: bytes, b: bytes, preset: str = "default") -> float:
    ta = normalize_text(a, preset=preset)
    tb = normalize_text(b, preset=preset)
    return SequenceMatcher(None, ta, tb).ratio()
@dataclass
class EquivalenceConfig:
    min_similarity: float = 0.985
    max_len_delta_ratio: float = 0.02
    require_same_status: bool = True
    preset: str = "default"
    ignore_headers: tuple[str, ...] = ()
    ignore_body_regex: tuple[str, ...] = ()

@dataclass
class CompareResult:
    equivalent: bool
    sim: float
    status_a: int
    status_b: int
    len_a: int
    len_b: int

def _apply_body_ignores(body: bytes, patterns: tuple[str, ...]) -> bytes:
    if not patterns or not body:
        return body
    try:
        text = body.decode("utf-8", errors="replace")
    except Exception:
        return body
    for pat in patterns:
        try:
            text = re.sub(pat, "<MRMA_IGNORED>", text, flags=re.MULTILINE)
        except re.error:
            # ignore invalid regex
            continue
    return text.encode("utf-8", errors="replace")

def _preset_defaults(preset: str):
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

def equivalent_response(
    status_a: int, body_a: bytes,
    status_b: int, body_b: bytes,
    cfg: EquivalenceConfig,
) -> CompareResult:
    # Merge preset defaults + user-provided ignore rules
    preset = _preset_defaults(cfg.preset)
    ignore_body = tuple(cfg.ignore_body_regex + preset["ignore_body_regex"])

    # Apply body ignore regex before normalization/similarity
    body_a2 = _apply_body_ignores(body_a, ignore_body)
    body_b2 = _apply_body_ignores(body_b, ignore_body)

    sim = similarity(body_a2, body_b2, preset=cfg.preset)
    la, lb = len(body_a2), len(body_b2)

    if cfg.require_same_status and status_a != status_b:
        return CompareResult(False, sim, status_a, status_b, la, lb)

    # length delta as a ratio of baseline length
    base = max(la, 1)
    len_delta_ratio = abs(lb - la) / base

    eq = (sim >= cfg.min_similarity) and (len_delta_ratio <= cfg.max_len_delta_ratio)
    return CompareResult(eq, sim, status_a, status_b, la, lb)
