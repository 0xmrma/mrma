from __future__ import annotations

from dataclasses import dataclass

from mrma.core.compare import (
    COMPARATOR_VERSION,
    CompareResult,
    EffectiveEquivalencePolicy,
    EquivalenceConfig,
    equivalent_response,
    resolve_equivalence_policy,
)


@dataclass(frozen=True)
class ComparisonPolicy:
    """Typed public owner of MRMA's bounded response-comparison policy."""

    config: EquivalenceConfig
    version: str = COMPARATOR_VERSION

    def resolved(self) -> EffectiveEquivalencePolicy:
        return resolve_equivalence_policy(self.config)

    def compare(
        self,
        status_left: int,
        body_left: bytes,
        status_right: int,
        body_right: bytes,
    ) -> CompareResult:
        return equivalent_response(
            status_left,
            body_left,
            status_right,
            body_right,
            self.config,
        )
