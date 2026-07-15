from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from mrma.core.experiment import ExperimentConfig
from mrma.core.raw_request import RawRequest
from mrma.core.sender import SendPolicy
from mrma.transport.semantic_http import estimate_semantic_request_bytes

PLAN_SCHEMA_VERSION = "mrma.plan/v1"


@dataclass(frozen=True)
class PlanSummary:
    schema_version: str
    plan_digest: str
    maximum_rounds: int
    observations_per_round: int
    maximum_logical_observations: int
    maximum_attempts_with_retries: int
    maximum_attempts_with_redirects: int
    maximum_request_bytes: int
    maximum_response_bytes: int
    target_count: int

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "plan_digest": self.plan_digest,
            "maximum_rounds": self.maximum_rounds,
            "observations_per_round": self.observations_per_round,
            "maximum_logical_observations": self.maximum_logical_observations,
            "maximum_attempts_with_retries": self.maximum_attempts_with_retries,
            "maximum_attempts_with_redirects": self.maximum_attempts_with_redirects,
            "maximum_request_bytes": self.maximum_request_bytes,
            "maximum_response_bytes": self.maximum_response_bytes,
            "target_count": self.target_count,
        }


@dataclass(frozen=True)
class ExperimentPlan:
    baseline: RawRequest
    mutation: RawRequest
    base_url: str
    experiment: ExperimentConfig
    send: SendPolicy
    follow_redirects: bool = False
    mutation_family: str = "header"
    mutation_risk_class: str = "safe"
    exploration_role: str = "confirmation"
    candidate_manifest_digest: str | None = None
    setup_hooks: tuple[RawRequest, ...] = ()
    reset_hooks: tuple[RawRequest, ...] = ()

    def __post_init__(self) -> None:
        if self.exploration_role not in {"exploration", "confirmation"}:
            raise ValueError("exploration_role must be exploration or confirmation")
        if self.exploration_role == "confirmation" and self.experiment.assurance_preset not in {
            "research",
            "forensic",
        }:
            raise ValueError("confirmatory plans require research or forensic assurance")
        if not self.baseline.semantic_replay_eligible or not self.mutation.semantic_replay_eligible:
            raise ValueError("request input is not eligible for semantic HTTP replay")
        if any(
            not request.semantic_replay_eligible
            for request in (*self.setup_hooks, *self.reset_hooks)
        ):
            raise ValueError("hook request input is not eligible for semantic HTTP replay")

    def summary(self, redirect_depth: int) -> PlanSummary:
        _, maximum_rounds = self.experiment.round_limits()
        observations_per_round = 3 if self.experiment.schedule_mode == "bracketed" else 2
        logical = maximum_rounds * observations_per_round
        header_setup = (
            self.experiment.stable_header_control_observations
            if self.experiment.response_header_scope == "all-stable"
            else 0
        )
        hook_attempts = len(self.setup_hooks) + maximum_rounds * len(self.reset_hooks)
        setup = header_setup + hook_attempts
        with_retries = (logical + setup) * (1 + self.send.retries)
        with_redirects = with_retries * (1 + redirect_depth if self.follow_redirects else 1)
        request_estimates = [
            estimate_semantic_request_bytes(request, self.base_url)
            for request in (
                self.baseline,
                self.mutation,
                *self.setup_hooks,
                *self.reset_hooks,
            )
        ]
        digest_payload = {
            "schema_version": PLAN_SCHEMA_VERSION,
            "baseline": self.baseline.original_sha256,
            "mutation": self.mutation.original_sha256,
            "base_target": hashlib.sha256(self.base_url.encode()).hexdigest(),
            "rounds": maximum_rounds,
            "schedule": self.experiment.schedule_mode,
            "retries": self.send.retries,
            "redirect_depth": redirect_depth if self.follow_redirects else 0,
            "mutation_family": self.mutation_family,
            "mutation_risk_class": self.mutation_risk_class,
            "exploration_role": self.exploration_role,
            "candidate_manifest_digest": self.candidate_manifest_digest,
            "stable_header_control_observations": header_setup,
            "setup_hook_digests": [request.original_sha256 for request in self.setup_hooks],
            "reset_hook_digests": [request.original_sha256 for request in self.reset_hooks],
        }
        digest = "sha256:" + hashlib.sha256(
            json.dumps(digest_payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return PlanSummary(
            schema_version=PLAN_SCHEMA_VERSION,
            plan_digest=digest,
            maximum_rounds=maximum_rounds,
            observations_per_round=observations_per_round,
            maximum_logical_observations=logical,
            maximum_attempts_with_retries=with_retries,
            maximum_attempts_with_redirects=with_redirects,
            maximum_request_bytes=with_redirects * max(request_estimates),
            maximum_response_bytes=with_redirects * self.experiment.max_response_bytes,
            target_count=1,
        )
