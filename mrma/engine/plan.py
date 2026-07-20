from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import cast
from urllib.parse import urljoin

from mrma.core.compare import resolve_equivalence_policy
from mrma.core.experiment import ExperimentConfig
from mrma.core.http_semantics import canonical_uri
from mrma.core.raw_request import RawRequest
from mrma.core.sender import SendPolicy
from mrma.transport.semantic_http import estimate_semantic_request_bytes

PLAN_SCHEMA_VERSION = "mrma.plan/v2"


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
    effective_plan: dict[str, object]

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
            "effective_plan": self.effective_plan,
        }

    def to_journal_dict(self) -> dict[str, object]:
        payload = self.to_dict()
        payload.pop("effective_plan")
        return payload


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

    def _request_document(self, request: RawRequest) -> dict[str, object]:
        target = (
            request.path
            if request.target_form == "absolute"
            else urljoin(self.base_url.rstrip("/") + "/", request.path.lstrip("/"))
        )
        canonical_target = canonical_uri(target)
        redactor = self.experiment.redactor
        return {
            "method": request.method,
            "target": redactor.url(canonical_target),
            "declared_http_version": request.http_version,
            "target_form": request.target_form,
            "headers": [
                {
                    "position": position,
                    "name": redactor.header_name(name),
                    "value_fingerprint": redactor.fingerprint(
                        value,
                        label=f"plan-header-value:{name.lower()}",
                    ),
                }
                for position, (name, value) in enumerate(request.headers)
            ],
            "body_fingerprint": redactor.fingerprint(request.body, label="plan-request-body"),
            "body_length": len(request.body),
            "original_source_sha256": (
                f"sha256:{request.original_sha256}"
                if request.original_sha256
                and re.fullmatch(r"[0-9a-f]{64}", request.original_sha256)
                else None
            ),
            "source_line_ending": request.source_line_ending,
            "semantic_replay_eligible": request.semantic_replay_eligible,
            "semantic_replay_limitations": list(request.semantic_replay_limitations),
        }

    def _effective_plan_document(
        self,
        *,
        redirect_depth: int,
        authorization_digest: str | None,
        comparison_policy: dict[str, object] | None,
        transport_policy: dict[str, object] | None,
    ) -> dict[str, object]:
        redactor = self.experiment.redactor
        resolved_comparison = dict(
            comparison_policy or resolve_equivalence_policy(self.experiment.equivalence).to_dict()
        )
        patterns = cast(tuple[str, ...], resolved_comparison.pop("ignore_body_regex", ()))
        if "ignore_headers" in resolved_comparison:
            ignore_headers = cast(tuple[str, ...], resolved_comparison["ignore_headers"])
            resolved_comparison["ignore_headers"] = list(ignore_headers)
        resolved_comparison["ignore_body_regex_fingerprints"] = [
            redactor.fingerprint(pattern, label="plan-normalization-rule")
            for pattern in patterns
        ]
        return {
            "schema_version": PLAN_SCHEMA_VERSION,
            "requests": {
                "baseline": self._request_document(self.baseline),
                "mutation": self._request_document(self.mutation),
                "setup": [self._request_document(request) for request in self.setup_hooks],
                "reset": [self._request_document(request) for request in self.reset_hooks],
            },
            "experiment": {
                "minimum_rounds": self.experiment.round_limits()[0],
                "maximum_rounds": self.experiment.round_limits()[1],
                "minimum_reproducibility": self.experiment.min_reproducibility,
                "no_influence_threshold": self.experiment.no_influence_threshold,
                "maximum_control_change_rate": self.experiment.max_control_change_rate,
                "seed": self.experiment.seed,
                "schedule_mode": self.experiment.schedule_mode,
                "state_mode": self.experiment.state_mode,
                "connection_mode": self.experiment.connection_mode,
                "maximum_response_bytes": self.experiment.max_response_bytes,
                "body_storage": self.experiment.body_storage,
                "response_header_scope": self.experiment.response_header_scope,
                "include_response_headers": list(self.experiment.include_response_headers),
                "include_response_header_pattern_fingerprints": [
                    redactor.fingerprint(pattern, label="plan-header-pattern")
                    for pattern in self.experiment.include_response_header_patterns
                ],
                "exclude_response_headers": list(self.experiment.exclude_response_headers),
                "response_header_profile": self.experiment.response_header_profile,
                "stable_header_control_observations": (
                    self.experiment.stable_header_control_observations
                ),
                "assume_text_without_content_type": (
                    self.experiment.assume_text_without_content_type
                ),
                "trust_environment": self.experiment.trust_environment,
                "tls_verification": self.experiment.tls_verification,
                "proxy_mode": self.experiment.proxy_mode,
                "assurance_preset": self.experiment.assurance_preset,
            },
            "comparison": resolved_comparison,
            "send": {
                "delay_s": self.send.delay_s,
                "rps": self.send.rps,
                "retries": self.send.retries,
                "retry_status": list(self.send.retry_status),
                "backoff_base_s": self.send.backoff_base_s,
                "backoff_cap_s": self.send.backoff_cap_s,
            },
            "redirects": {
                "follow": self.follow_redirects,
                "maximum_depth": redirect_depth if self.follow_redirects else 0,
            },
            "mutation": {
                "family": self.mutation_family,
                "risk_class": self.mutation_risk_class,
            },
            "role": {
                "type": self.exploration_role,
                "candidate_manifest_digest": self.candidate_manifest_digest,
            },
            "authorization_digest": authorization_digest,
            "transport": transport_policy or {},
        }

    def summary(
        self,
        redirect_depth: int,
        *,
        authorization_digest: str | None = None,
        comparison_policy: dict[str, object] | None = None,
        transport_policy: dict[str, object] | None = None,
    ) -> PlanSummary:
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
        digest_payload = self._effective_plan_document(
            redirect_depth=redirect_depth,
            authorization_digest=authorization_digest,
            comparison_policy=comparison_policy,
            transport_policy=transport_policy,
        )
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
            effective_plan=digest_payload,
        )
