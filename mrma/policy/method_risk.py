from __future__ import annotations

from dataclasses import dataclass

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
IDEMPOTENT_RISKY_METHODS = frozenset({"PUT", "DELETE", "TRACE"})
NON_IDEMPOTENT_METHODS = frozenset({"POST", "PATCH", "CONNECT"})
RISK_RANK = {
    "safe": 0,
    "idempotent-destructive": 1,
    "non-idempotent": 2,
    "unknown-extension": 3,
}


@dataclass(frozen=True)
class MethodRisk:
    method: str
    risk_class: str
    repeat_requires_explicit_authorization: bool


def classify_method(method: str) -> MethodRisk:
    if method in SAFE_METHODS:
        return MethodRisk(method, "safe", False)
    if method in IDEMPOTENT_RISKY_METHODS:
        return MethodRisk(method, "idempotent-destructive", True)
    if method in NON_IDEMPOTENT_METHODS:
        return MethodRisk(method, "non-idempotent", True)
    return MethodRisk(method, "unknown-extension", True)
