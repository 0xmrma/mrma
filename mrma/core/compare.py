from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from decimal import Decimal, InvalidOperation

import regex

MAX_SEQUENCE_BYTES = 256 * 1024
MAX_NORMALIZATION_RULES = 32
MAX_REGEX_PATTERN_BYTES = 4096
REGEX_RULE_TIMEOUT_S = 0.050
NORMALIZATION_TIMEOUT_S = 0.250
SIMILARITY_BUCKETS = 8192
COMPARATOR_VERSION = "bounded-trigram-dice/1.0"
NORMALIZER_VERSION = "timeout-regex-normalizer/1.0"
GUARDED_JSON_VERSION = "guarded-json/1.0"


class ComparatorResourceError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


class GuardedJsonRejected(ValueError):
    pass


@dataclass(frozen=True)
class NormalizationOutcome:
    rule_type: str
    rule: str
    outcome: str
    elapsed_ms: float


@dataclass(frozen=True)
class EquivalenceConfig:
    min_similarity: float = 0.985
    max_len_delta_ratio: float = 0.02
    require_same_status: bool = True
    preset: str = "default"
    ignore_headers: tuple[str, ...] = ()
    ignore_body_regex: tuple[str, ...] = ()
    regex_rule_timeout_s: float = REGEX_RULE_TIMEOUT_S
    normalization_timeout_s: float = NORMALIZATION_TIMEOUT_S


@dataclass(frozen=True)
class EffectiveEquivalencePolicy:
    preset: str
    min_similarity: float
    max_len_delta_ratio: float
    require_same_status: bool
    ignore_headers: tuple[str, ...]
    ignore_body_regex: tuple[str, ...]
    max_sequence_bytes: int = MAX_SEQUENCE_BYTES
    regex_rule_timeout_s: float = REGEX_RULE_TIMEOUT_S
    normalization_timeout_s: float = NORMALIZATION_TIMEOUT_S
    comparator_version: str = COMPARATOR_VERSION
    normalizer_version: str = NORMALIZER_VERSION
    guarded_json_version: str = GUARDED_JSON_VERSION

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
    completed: bool = True
    resource_limit: str | None = None
    normalization_outcomes: tuple[NormalizationOutcome, ...] = ()


@dataclass(frozen=True)
class _SimilarityResult:
    score: float
    comparator: str
    completed: bool
    resource_limit: str | None = None


def _preset_defaults(preset: str) -> dict[str, tuple[str, ...]]:
    normalized = (preset or "default").lower().strip()
    if normalized == "nextjs":
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
    if normalized == "api-json":
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
    if not 0 < cfg.regex_rule_timeout_s <= 1:
        raise ValueError("regex_rule_timeout_s must be in (0, 1]")
    if not cfg.regex_rule_timeout_s <= cfg.normalization_timeout_s <= 5:
        raise ValueError("normalization_timeout_s must cover a rule and be at most 5 seconds")
    defaults = _preset_defaults(preset_name)
    body_patterns = _unique(defaults["ignore_body_regex"] + cfg.ignore_body_regex)
    if len(body_patterns) > MAX_NORMALIZATION_RULES:
        raise ValueError(f"at most {MAX_NORMALIZATION_RULES} body normalization rules are allowed")
    for pattern in body_patterns:
        if len(pattern.encode("utf-8")) > MAX_REGEX_PATTERN_BYTES:
            raise ValueError("ignore_body_regex exceeds the bounded pattern size")
        try:
            regex.compile(pattern, flags=regex.MULTILINE | regex.VERSION1)
        except regex.error as exc:
            raise ValueError(f"invalid ignore_body_regex {pattern!r}: {exc}") from exc
    return EffectiveEquivalencePolicy(
        preset=preset_name,
        min_similarity=cfg.min_similarity,
        max_len_delta_ratio=cfg.max_len_delta_ratio,
        require_same_status=cfg.require_same_status,
        ignore_headers=_unique(defaults["ignore_headers"] + cfg.ignore_headers, lower=True),
        ignore_body_regex=body_patterns,
        regex_rule_timeout_s=cfg.regex_rule_timeout_s,
        normalization_timeout_s=cfg.normalization_timeout_s,
    )


def _sub(
    pattern: str,
    replacement: str,
    text: str,
    *,
    flags: int,
    rule_type: str,
    deadline: float,
    per_rule_timeout_s: float,
    outcomes: list[NormalizationOutcome],
) -> str:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ComparatorResourceError(
            "NORMALIZATION_TOTAL_TIMEOUT",
            "normalization run budget was exhausted",
        )
    timeout = min(per_rule_timeout_s, remaining)
    started = time.perf_counter()
    try:
        result = regex.sub(
            pattern,
            replacement,
            text,
            flags=flags | regex.VERSION1,
            timeout=timeout,
        )
    except TimeoutError as exc:
        outcomes.append(
            NormalizationOutcome(
                rule_type,
                pattern,
                "timeout",
                round((time.perf_counter() - started) * 1000, 3),
            )
        )
        raise ComparatorResourceError(
            "NORMALIZATION_RULE_TIMEOUT",
            "a normalization rule exceeded its execution budget",
        ) from exc
    outcomes.append(
        NormalizationOutcome(
            rule_type,
            pattern,
            "completed",
            round((time.perf_counter() - started) * 1000, 3),
        )
    )
    return result


def _apply_body_ignores(
    body: bytes,
    patterns: tuple[str, ...],
    *,
    policy: EffectiveEquivalencePolicy,
    deadline: float,
    outcomes: list[NormalizationOutcome],
) -> bytes:
    if not patterns or not body:
        return body
    try:
        text = body.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ComparatorResourceError(
            "INVALID_COMPARISON_ENCODING",
            "comparison input was not strict UTF-8",
        ) from exc
    original = text
    try:
        for pattern in patterns:
            text = _sub(
                pattern,
                "<MRMA_IGNORED>",
                text,
                flags=regex.MULTILINE,
                rule_type="user-regex",
                deadline=deadline,
                per_rule_timeout_s=policy.regex_rule_timeout_s,
                outcomes=outcomes,
            )
    except ComparatorResourceError:
        del original
        raise
    return text.encode("utf-8")


def normalize_text(
    body: bytes,
    preset: str = "default",
    *,
    deadline: float | None = None,
    per_rule_timeout_s: float = REGEX_RULE_TIMEOUT_S,
    outcomes: list[NormalizationOutcome] | None = None,
) -> str:
    try:
        text = body.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ComparatorResourceError(
            "INVALID_COMPARISON_ENCODING",
            "comparison input was not strict UTF-8",
        ) from exc
    preset_name = (preset or "default").lower().strip()
    final_deadline = deadline or (time.monotonic() + NORMALIZATION_TIMEOUT_S)
    records = outcomes if outcomes is not None else []

    fixed_rules: list[tuple[str, str, int]] = []
    if preset_name in ("dynamic", "nextjs"):
        fixed_rules.extend(
            [
                (
                    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
                    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b",
                    "<UUID>",
                    0,
                ),
                (r"\b[0-9a-fA-F]{32,}\b", "<HEX>", 0),
                (r"\b1[0-9]{9}\b", "<TS>", 0),
                (r"\b[A-Za-z0-9+/]{200,}={0,2}\b", "<B64>", 0),
                (r"(<script[^>]*>)(?s:.*?)(</script>)", r"\1<SCRIPT>\2", regex.IGNORECASE),
                (r'("csrfToken"\s*:\s*)".*?"', r'\1"<TOKEN>"', regex.IGNORECASE),
                (r'("token"\s*:\s*)".*?"', r'\1"<TOKEN>"', regex.IGNORECASE),
            ]
        )
    if preset_name == "nextjs":
        for field, marker in (
            ("buildId", "BUILDID"),
            ("requestId", "REQID"),
            ("traceId", "TRACEID"),
            ("nonce", "NONCE"),
        ):
            fixed_rules.append(
                (rf'("{field}"\s*:\s*)".*?"', rf'\1"<{marker}>"', regex.IGNORECASE)
            )
    if preset_name == "api-json":
        fixed_rules.extend(
            [
                (
                    r'("timestamp"|"time"|"ts")\s*:\s*"?\d+"?',
                    r'"ts":"<TS>"',
                    regex.IGNORECASE,
                ),
                (
                    r'("request_id"|"requestId"|"trace_id"|"traceId")\s*:\s*'
                    r'"[A-Za-z0-9\-_]+"',
                    r'"id":"<ID>"',
                    regex.IGNORECASE,
                ),
                (
                    r'("nonce"|"csrf"|"token")\s*:\s*"[A-Za-z0-9\-_\.]+"',
                    r'"token":"<TOKEN>"',
                    regex.IGNORECASE,
                ),
            ]
        )
    for pattern, replacement, flags in fixed_rules:
        text = _sub(
            pattern,
            replacement,
            text,
            flags=flags,
            rule_type="built-in",
            deadline=final_deadline,
            per_rule_timeout_s=per_rule_timeout_s,
            outcomes=records,
        )
    return text


def _strict_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise GuardedJsonRejected("duplicate object key")
        result[key] = value
    return result


def _json_number(value: str) -> Decimal:
    if len(value) > 256:
        raise ComparatorResourceError("JSON_NUMBER_LIMIT", "JSON number token is too large")
    try:
        number = Decimal(value)
    except InvalidOperation as exc:
        raise GuardedJsonRejected("invalid JSON number") from exc
    if not number.is_finite() or abs(number.adjusted()) > 10000:
        raise ComparatorResourceError("JSON_NUMBER_LIMIT", "JSON number exponent is too large")
    return number


def _reject_constant(value: str) -> object:
    raise GuardedJsonRejected(f"non-finite JSON constant {value}")


def _canonical_json_value(value: object) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=True, separators=(",", ":"))
    if isinstance(value, Decimal):
        normalized = value.normalize()
        if normalized == 0:
            return "-0" if normalized.is_signed() else "0"
        return str(normalized).lower()
    if isinstance(value, list):
        return "[" + ",".join(_canonical_json_value(item) for item in value) + "]"
    if isinstance(value, dict):
        return "{" + ",".join(
            json.dumps(key, ensure_ascii=True) + ":" + _canonical_json_value(value[key])
            for key in sorted(value)
        ) + "}"
    raise GuardedJsonRejected("unsupported parsed JSON value")


def _canonical_json(text: str) -> str | None:
    try:
        value = json.loads(
            text,
            object_pairs_hook=_strict_pairs,
            parse_int=_json_number,
            parse_float=_json_number,
            parse_constant=_reject_constant,
        )
        return _canonical_json_value(value)
    except (json.JSONDecodeError, GuardedJsonRejected, RecursionError):
        return None


def _gram_bucket(text: str, index: int, width: int) -> int:
    value = 2166136261
    for offset in range(width):
        codepoint = ord(text[index + offset])
        value ^= codepoint & 0xFF
        value = (value * 16777619) & 0xFFFFFFFF
        value ^= (codepoint >> 8) & 0xFFFF
        value = (value * 16777619) & 0xFFFFFFFF
    return value % SIMILARITY_BUCKETS


def bounded_text_similarity(left: str, right: str) -> float:
    """Return the deterministic bounded-memory approximate trigram Dice score."""
    if left == right:
        return 1.0
    width = 3 if min(len(left), len(right)) >= 3 else 1
    left_counts = [0] * SIMILARITY_BUCKETS
    right_counts = [0] * SIMILARITY_BUCKETS
    left_total = max(len(left) - width + 1, 0)
    right_total = max(len(right) - width + 1, 0)
    if left_total == 0 or right_total == 0:
        return 0.0
    for index in range(left_total):
        left_counts[_gram_bucket(left, index, width)] += 1
    for index in range(right_total):
        right_counts[_gram_bucket(right, index, width)] += 1
    intersection = sum(min(a, b) for a, b in zip(left_counts, right_counts))
    return (2.0 * intersection) / (left_total + right_total)


def _similarity_result(
    a: bytes,
    b: bytes,
    *,
    preset: str,
    max_sequence_bytes: int,
    deadline: float,
    per_rule_timeout_s: float,
    outcomes: list[NormalizationOutcome],
) -> _SimilarityResult:
    if a == b:
        return _SimilarityResult(1.0, "exact-bytes", True)
    if max(len(a), len(b)) > max_sequence_bytes:
        return _SimilarityResult(0.0, COMPARATOR_VERSION, False, "COMPARATOR_INPUT_LIMIT")
    left = normalize_text(
        a,
        preset=preset,
        deadline=deadline,
        per_rule_timeout_s=per_rule_timeout_s,
        outcomes=outcomes,
    )
    right = normalize_text(
        b,
        preset=preset,
        deadline=deadline,
        per_rule_timeout_s=per_rule_timeout_s,
        outcomes=outcomes,
    )
    comparator = COMPARATOR_VERSION
    if preset == "api-json":
        json_left = _canonical_json(left)
        json_right = _canonical_json(right)
        if json_left is not None and json_right is not None:
            left, right = json_left, json_right
            comparator = GUARDED_JSON_VERSION + "+" + COMPARATOR_VERSION
    return _SimilarityResult(bounded_text_similarity(left, right), comparator, True)


def similarity(
    a: bytes,
    b: bytes,
    preset: str = "default",
    max_sequence_bytes: int = MAX_SEQUENCE_BYTES,
) -> tuple[float, str]:
    outcomes: list[NormalizationOutcome] = []
    try:
        result = _similarity_result(
            a,
            b,
            preset=preset,
            max_sequence_bytes=max_sequence_bytes,
            deadline=time.monotonic() + NORMALIZATION_TIMEOUT_S,
            per_rule_timeout_s=REGEX_RULE_TIMEOUT_S,
            outcomes=outcomes,
        )
    except ComparatorResourceError as exc:
        return 0.0, f"resource-limit:{exc.code}"
    return result.score, result.comparator if result.completed else f"resource-limit:{result.resource_limit}"


def equivalent_response(
    status_a: int,
    body_a: bytes,
    status_b: int,
    body_b: bytes,
    cfg: EquivalenceConfig | EffectiveEquivalencePolicy,
) -> CompareResult:
    policy = cfg if isinstance(cfg, EffectiveEquivalencePolicy) else resolve_equivalence_policy(cfg)
    outcomes: list[NormalizationOutcome] = []
    deadline = time.monotonic() + policy.normalization_timeout_s
    try:
        left = _apply_body_ignores(
            body_a,
            policy.ignore_body_regex,
            policy=policy,
            deadline=deadline,
            outcomes=outcomes,
        )
        right = _apply_body_ignores(
            body_b,
            policy.ignore_body_regex,
            policy=policy,
            deadline=deadline,
            outcomes=outcomes,
        )
        result = _similarity_result(
            left,
            right,
            preset=policy.preset,
            max_sequence_bytes=policy.max_sequence_bytes,
            deadline=deadline,
            per_rule_timeout_s=policy.regex_rule_timeout_s,
            outcomes=outcomes,
        )
    except ComparatorResourceError as exc:
        return CompareResult(
            False,
            0.0,
            status_a,
            status_b,
            len(body_a),
            len(body_b),
            COMPARATOR_VERSION,
            completed=False,
            resource_limit=exc.code,
            normalization_outcomes=tuple(outcomes),
        )
    len_a, len_b = len(left), len(right)
    if not result.completed:
        return CompareResult(
            False,
            result.score,
            status_a,
            status_b,
            len_a,
            len_b,
            result.comparator,
            completed=False,
            resource_limit=result.resource_limit,
            normalization_outcomes=tuple(outcomes),
        )
    if policy.require_same_status and status_a != status_b:
        return CompareResult(
            False,
            result.score,
            status_a,
            status_b,
            len_a,
            len_b,
            result.comparator,
            normalization_outcomes=tuple(outcomes),
        )
    length_delta_ratio = abs(len_b - len_a) / max(len_a, 1)
    equivalent = (
        result.score >= policy.min_similarity
        and length_delta_ratio <= policy.max_len_delta_ratio
    )
    return CompareResult(
        equivalent,
        result.score,
        status_a,
        status_b,
        len_a,
        len_b,
        result.comparator,
        normalization_outcomes=tuple(outcomes),
    )
