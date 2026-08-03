from __future__ import annotations

import hashlib
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, replace
from fnmatch import fnmatchcase
from threading import Event
from typing import NoReturn
from urllib.parse import urljoin, urlsplit

from mrma.core.compare import resolve_equivalence_policy
from mrma.core.experiment import (
    HTTP_RESPONSE,
    ExperimentResult,
    Observation,
    analyze_experiment,
    run_experiment,
)
from mrma.core.http_client import CapturedResponse, RedirectHop
from mrma.core.http_semantics import canonical_header_values, canonical_uri
from mrma.core.raw_request import RawRequest
from mrma.core.sender import AttemptRecord, RateGate, SendOutcome
from mrma.evidence.journal import EvidenceContext, EvidenceJournal
from mrma.policy.authorization import AuthorizationError, ManifestAuthorizationPolicy
from mrma.policy.budget import AttemptCost, BudgetError, BudgetLedger, BudgetSnapshot
from mrma.policy.comparison import ComparisonPolicy
from mrma.policy.method_risk import RISK_RANK, classify_method
from mrma.transport.semantic_http import (
    SemanticHttpAdapter,
    estimate_semantic_request_bytes,
    origin_fingerprint,
)

from .plan import ExperimentPlan, PlanSummary

ORACLE_VERSION = "experiment-oracle/1.0"
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_SENSITIVE_FIELD_MARKERS = ("token", "secret", "credential", "api-key", "apikey")
_CREDENTIAL_FIELDS = frozenset({"authorization", "cookie", "proxy-authorization"})
_SAFE_CROSS_ORIGIN_FIELDS = frozenset({"accept", "accept-language", "user-agent"})
_CONTENT_FIELDS = frozenset(
    {
        "content-encoding",
        "content-language",
        "content-length",
        "content-location",
        "content-md5",
        "content-type",
        "digest",
        "content-digest",
        "repr-digest",
        "transfer-encoding",
        "trailer",
        "last-modified",
        "signature",
        "signature-input",
        "x-amz-content-sha256",
    }
)
_BODY_SAFETY_FIELDS = frozenset({"content-type", "content-encoding"})
_HEADER_PROFILES = {
    "routing": frozenset(
        {"location", "content-location", "server", "via", "x-served-by", "x-matched-path"}
    ),
    "security": frozenset(
        {
            "content-security-policy",
            "cross-origin-embedder-policy",
            "cross-origin-opener-policy",
            "cross-origin-resource-policy",
            "permissions-policy",
            "referrer-policy",
            "strict-transport-security",
            "x-content-type-options",
            "x-frame-options",
        }
    ),
    "cache": frozenset(
        {"age", "cache-control", "etag", "vary", "x-cache", "x-cache-status", "cf-cache-status"}
    ),
}


@dataclass(frozen=True)
class HeaderCoverage:
    mode: str
    complete: bool
    all_fields_evaluated: bool
    policy_version: str
    control_observations: int
    observed_fields: tuple[str, ...]
    promoted_fields: tuple[str, ...]
    volatile_fields: tuple[str, ...]
    ignored_fields: tuple[str, ...]
    forced_fields: tuple[str, ...]


@dataclass(frozen=True)
class OracleRunResult:
    status: str
    verdict: str
    stop_reason: str
    planned_rounds: int
    completed_rounds: int
    experiment: ExperimentResult
    budget: BudgetSnapshot
    journal_head_digest: str
    journal_event_count: int
    plan: PlanSummary
    header_coverage: HeaderCoverage
    limitations: tuple[dict[str, str], ...]


class ExperimentOracle:
    """Stable authorization-first API around MRMA's pure statistical experiment."""

    def __init__(
        self,
        *,
        authorization: ManifestAuthorizationPolicy,
        budgets: BudgetLedger,
        transport: SemanticHttpAdapter,
        comparison: ComparisonPolicy,
        evidence: EvidenceJournal,
    ) -> None:
        if budgets.journal is not evidence or transport.journal is not evidence:
            raise ValueError("oracle components must share one evidence journal")
        self.authorization = authorization
        self.budgets = budgets
        self.transport = transport
        self.comparison = comparison
        self.evidence = evidence
        self._gate = RateGate()
        self._attempt_sequence = 0

    def _validate_comparison_policy(self, plan: ExperimentPlan) -> None:
        if self.comparison.resolved() != resolve_equivalence_policy(
            plan.experiment.equivalence
        ):
            raise ValueError(
                "oracle comparison policy must match the policy bound into the experiment plan"
            )
        self.authorization.validate_mutation(
            plan.baseline,
            plan.mutation,
            mutation_family=plan.mutation_family,
        )

    def _plan_summary(self, plan: ExperimentPlan) -> PlanSummary:
        return plan.summary(
            self.authorization.manifest.redirects.maximum_depth,
            authorization_digest=self.authorization.digest,
            comparison_policy=self.comparison.resolved().to_dict(),
            transport_policy=self.transport.public_policy(),
        )

    def _validate_plan_budget(
        self,
        plan: ExperimentPlan,
        summary: PlanSummary,
        *,
        require_complete_capacity: bool,
    ) -> None:
        limits = self.budgets.limits
        _, rounds = plan.experiment.round_limits()
        controls = rounds * (2 if plan.experiment.schedule_mode == "bracketed" else 1)
        mutations = rounds
        header_setup = (
            plan.experiment.stable_header_control_observations
            if plan.experiment.response_header_scope == "all-stable"
            else 0
        )
        setup_reset = header_setup + len(plan.setup_hooks) + rounds * len(plan.reset_hooks)
        first_attempts = controls + mutations + setup_reset
        redirect_depth = (
            self.authorization.manifest.redirects.maximum_depth
            if plan.follow_redirects
            else 0
        )
        retries = first_attempts * plan.send.retries * (1 + redirect_depth)
        redirects = first_attempts * redirect_depth
        timeout_ms = int(self.transport.options.timeout_s * 1000)
        if timeout_ms > limits.per_attempt_timeout_ms:
            raise BudgetError(
                "PLAN_EXCEEDS_BUDGET",
                "transport timeout exceeds the per-attempt policy timeout",
            )
        body_maximum = max(
            len(request.body)
            for request in (
                plan.baseline,
                plan.mutation,
                *plan.setup_hooks,
                *plan.reset_hooks,
            )
        )
        checks = {
            "total_network_attempts": summary.maximum_attempts_with_redirects,
            "controls": controls,
            "mutations": mutations,
            "retries": retries,
            "redirects": redirects,
            "setup_reset_attempts": setup_reset,
            "attempts_per_origin": summary.maximum_attempts_with_redirects,
            "requests_per_target": summary.maximum_attempts_with_redirects,
            "bytes_sent": summary.maximum_request_bytes,
            "bytes_received": summary.maximum_response_bytes,
            "total_duration_ms": summary.maximum_attempts_with_redirects * timeout_ms,
        }
        if require_complete_capacity:
            for name, required in checks.items():
                if required > getattr(limits, name):
                    raise BudgetError(
                        "PLAN_EXCEEDS_BUDGET",
                        f"planned {name} requires {required}, policy permits {getattr(limits, name)}",
                    )
        if plan.experiment.max_response_bytes > limits.maximum_response_bytes:
            raise BudgetError(
                "PLAN_EXCEEDS_BUDGET",
                "experiment response bound exceeds the per-attempt policy bound",
            )
        if body_maximum > limits.maximum_request_body_bytes:
            raise BudgetError(
                "PLAN_EXCEEDS_BUDGET",
                "a planned request body exceeds the per-attempt policy bound",
            )
        if redirect_depth > limits.redirect_depth:
            raise BudgetError(
                "PLAN_EXCEEDS_BUDGET",
                "authorization redirect depth exceeds the budget redirect depth",
            )
        planned_risks = [
            plan.mutation_risk_class,
            classify_method(plan.baseline.method).risk_class,
            classify_method(plan.mutation.method).risk_class,
            *(classify_method(request.method).risk_class for request in plan.setup_hooks),
            *(classify_method(request.method).risk_class for request in plan.reset_hooks),
        ]
        if any(
            RISK_RANK[risk] > RISK_RANK[limits.mutation_risk_level]
            for risk in planned_risks
        ):
            raise BudgetError(
                "PLAN_EXCEEDS_BUDGET",
                "a planned operation exceeds the authorized mutation risk level",
            )

    def dry_run(self, plan: ExperimentPlan) -> PlanSummary:
        self._validate_comparison_policy(plan)
        summary = self._plan_summary(plan)
        self._validate_plan_budget(plan, summary, require_complete_capacity=True)
        for request, role in ((plan.baseline, "control"), (plan.mutation, "mutation")):
            context = self.authorization.authorize(
                request,
                base_url=plan.base_url,
                attempt_kind=role,
                mutation_family=plan.mutation_family if role == "mutation" else None,
                risk_class=plan.mutation_risk_class if role == "mutation" else "safe",
                proxy_url=self.transport.options.proxy,
                consume_repetition=False,
            )
            self.evidence.record(
                "AUTHORIZATION_ACCEPTED",
                {
                    "dry_run": True,
                    "role": role,
                    "decision_code": context.decision.code,
                    "manifest_digest": context.decision.manifest_digest,
                    "target_fingerprint": context.decision.target_fingerprint,
                    "address_set_fingerprint": context.decision.address_set_fingerprint,
                    "proxy_address_set_fingerprint": context.decision.proxy_address_set_fingerprint,
                    "host_authority_fingerprint": context.decision.host_authority_fingerprint,
                    "sni_authority_fingerprint": context.decision.sni_authority_fingerprint,
                    "proxy_connect_authority_fingerprint": context.decision.proxy_connect_authority_fingerprint,
                },
            )
        for role, requests in (("setup", plan.setup_hooks), ("reset", plan.reset_hooks)):
            for request in requests:
                context = self.authorization.authorize(
                    request,
                    base_url=plan.base_url,
                    attempt_kind=role,
                    risk_class=classify_method(request.method).risk_class,
                    proxy_url=self.transport.options.proxy,
                    consume_repetition=False,
                )
                self.evidence.record(
                    "AUTHORIZATION_ACCEPTED",
                    {
                        "dry_run": True,
                        "role": role,
                        "decision_code": context.decision.code,
                        "manifest_digest": context.decision.manifest_digest,
                        "target_fingerprint": context.decision.target_fingerprint,
                        "address_set_fingerprint": context.decision.address_set_fingerprint,
                        "proxy_address_set_fingerprint": context.decision.proxy_address_set_fingerprint,
                        "host_authority_fingerprint": context.decision.host_authority_fingerprint,
                        "sni_authority_fingerprint": context.decision.sni_authority_fingerprint,
                        "proxy_connect_authority_fingerprint": context.decision.proxy_connect_authority_fingerprint,
                    },
                )
        self.evidence.record("RUN_PLANNED", summary.to_journal_dict())
        return summary

    def send_observation(
        self,
        plan: ExperimentPlan,
        *,
        arm: str,
        request: RawRequest,
        round_index: int,
        sequence: int,
        initial_role: str | None = None,
    ) -> SendOutcome:
        """Execute one guarded observation for an explicitly exploratory workflow."""
        self._validate_comparison_policy(plan)
        return self._send_observation(
            plan,
            arm=arm,
            request=request,
            round_index=round_index,
            sequence=sequence,
            initial_role=initial_role,
        )

    def run(
        self,
        plan: ExperimentPlan,
        *,
        cancellation: Event | None = None,
        on_progress: Callable[[int, int, str], None] | None = None,
    ) -> OracleRunResult:
        self._validate_comparison_policy(plan)
        summary = self._plan_summary(plan)
        self._validate_plan_budget(plan, summary, require_complete_capacity=False)
        self.evidence.record("RUN_PLANNED", summary.to_journal_dict())
        active_plan = plan
        header_coverage = HeaderCoverage(
            mode=plan.experiment.response_header_scope,
            complete=False,
            all_fields_evaluated=False,
            policy_version="stable-response-headers/1.0",
            control_observations=0,
            observed_fields=(),
            promoted_fields=(),
            volatile_fields=(),
            ignored_fields=(),
            forced_fields=(),
        )
        captured_observations: list[Observation] = []
        started_rounds: set[int] = set()
        completed_rounds: set[int] = set()
        observations_per_round = 3 if plan.experiment.schedule_mode == "bracketed" else 2

        def sender(
            arm: str,
            request: RawRequest,
            *,
            round_index: int,
            sequence: int,
        ) -> SendOutcome:
            if round_index not in started_rounds:
                self._execute_hooks(plan, plan.reset_hooks, "reset", round_index)
                self.evidence.record("ROUND_STARTED", {"round_index": round_index})
                started_rounds.add(round_index)
            return self._send_observation(
                active_plan,
                arm=arm,
                request=request,
                round_index=round_index,
                sequence=sequence,
            )

        def observed(item: Observation) -> None:
            captured_observations.append(item)
            self.evidence.record(
                "OBSERVATION_COMPLETED",
                {
                    "round_index": item.round_index,
                    "sequence": item.sequence,
                    "role": item.arm,
                    "outcome": item.outcome,
                    "status": item.status,
                    "body_digest_complete": item.body_digest_complete,
                    "body_retained_complete": item.body_retained_complete,
                },
            )
            round_count = sum(obs.round_index == item.round_index for obs in captured_observations)
            if round_count == observations_per_round and item.round_index not in completed_rounds:
                completed_rounds.add(item.round_index)
                self.evidence.record("ROUND_COMPLETED", {"round_index": item.round_index})
                self.transport.complete_round(item.round_index)

        status = "completed"
        stop_reason = "fixed_sample_complete"
        try:
            with self.transport:
                self._execute_hooks(plan, plan.setup_hooks, "setup", 0)
                if plan.experiment.response_header_scope == "all-stable":
                    active_plan, header_coverage = self._prepare_stable_response_headers(plan)
                result = run_experiment(
                    active_plan.baseline,
                    active_plan.mutation,
                    sender,
                    active_plan.experiment,
                    on_progress=on_progress,
                    on_observation=observed,
                    should_cancel=(cancellation.is_set if cancellation is not None else None),
                )
            stop_reason = result.stop_reason
            incomplete_transport = any(
                item.outcome != HTTP_RESPONSE for item in result.observations
            )
            if stop_reason == "cancelled":
                status = "cancelled"
                result.verdict = "INCONCLUSIVE"
                self.evidence.record("RUN_CANCELLED", {"stop_reason": stop_reason})
            elif incomplete_transport:
                status = "partial"
                result.verdict = "INCONCLUSIVE"
                stop_reason = "incomplete_transport_sampling"
                self.evidence.record(
                    "RUN_FAILED",
                    {"stop_reason": stop_reason, "error_type": "IncompleteObservation"},
                )
            else:
                self.evidence.record(
                    "RUN_COMPLETED",
                    {"verdict": result.verdict, "stop_reason": stop_reason},
                )
        except KeyboardInterrupt:
            status = "cancelled"
            stop_reason = "keyboard_interrupt"
            result = analyze_experiment(
                captured_observations,
                active_plan.experiment,
                stop_reason=stop_reason,
            )
            result.verdict = "INCONCLUSIVE"
            self.evidence.record("RUN_CANCELLED", {"stop_reason": stop_reason})
        except (AuthorizationError, BudgetError) as exc:
            status = "partial"
            stop_reason = exc.code.lower()
            result = analyze_experiment(
                captured_observations,
                active_plan.experiment,
                stop_reason=stop_reason,
            )
            result.verdict = "INCONCLUSIVE"
            self.evidence.record(
                "RUN_FAILED",
                {"stop_reason": stop_reason, "error_type": type(exc).__name__},
            )
        except Exception as exc:
            status = "partial"
            stop_reason = "transport_or_policy_failure"
            result = analyze_experiment(
                captured_observations,
                active_plan.experiment,
                stop_reason=stop_reason,
            )
            result.verdict = "INCONCLUSIVE"
            self.evidence.record(
                "RUN_FAILED",
                {"stop_reason": stop_reason, "error_type": type(exc).__name__},
            )

        self.budgets.assert_settled()
        if status != "completed":
            result.verdict = "INCONCLUSIVE"
        if header_coverage.mode != "all-stable":
            selected = sorted(
                {name for observation in result.observations for name in observation.headers}
            )
            header_coverage = replace(
                header_coverage,
                observed_fields=tuple(selected),
                promoted_fields=tuple(selected),
            )
        limitations = [
            {
                "code": "SEMANTIC_HTTP_TRANSPORT",
                "severity": "low",
                "scope": "protocol_fidelity",
                "message": "HTTPX replay can normalize syntax, framing, and protocol behavior.",
                "remediation": "Use a future protocol-exact backend for wire-syntax research.",
            },
            {
                "code": "CONNECTED_ADDRESS_UNAVAILABLE",
                "severity": "moderate",
                "scope": "transport_provenance",
                "message": "The supported HTTPX interface did not expose a reliable connected address.",
                "remediation": "Review the authorized address-set fingerprint and repeat with a future pinning backend.",
            },
            {
                "code": "DNS_CONNECTION_BINDING_UNAVAILABLE",
                "severity": "moderate",
                "scope": "authorization_transport_binding",
                "message": "The authorized DNS answer cannot be bound to HTTPX's eventual socket.",
                "remediation": "Use a future address-pinning transport for hostile DNS environments.",
            },
        ]
        if status != "completed":
            limitations.append(
                {
                    "code": "INCOMPLETE_SAMPLING",
                    "severity": "high",
                    "scope": "statistical_design",
                    "message": "The fixed experiment design did not complete.",
                    "remediation": "Resolve the stop condition and repeat as an independent run.",
                }
            )
        _, planned_rounds = plan.experiment.round_limits()
        return OracleRunResult(
            status=status,
            verdict=result.verdict,
            stop_reason=stop_reason,
            planned_rounds=planned_rounds,
            completed_rounds=len(completed_rounds),
            experiment=result,
            budget=self.budgets.snapshot(),
            journal_head_digest=self.evidence.head_digest,
            journal_event_count=len(self.evidence.events),
            plan=summary,
            header_coverage=header_coverage,
            limitations=tuple(limitations),
        )

    def _execute_hooks(
        self,
        plan: ExperimentPlan,
        requests: tuple[RawRequest, ...],
        role: str,
        round_index: int,
    ) -> None:
        for index, request in enumerate(requests, start=1):
            outcome = self._send_observation(
                plan,
                arm="control",
                request=request,
                round_index=round_index,
                sequence=-index,
                initial_role=role,
            )
            if not outcome.succeeded or not isinstance(outcome.response, CapturedResponse):
                raise RuntimeError(f"{role} hook failed")
            if outcome.response.response_limit_exceeded:
                raise BudgetError(
                    "HOOK_RESPONSE_LIMIT",
                    f"{role} hook exceeded the response bound",
                )
            self.evidence.record(
                "OBSERVATION_COMPLETED",
                {
                    "round_index": round_index,
                    "sequence": -index,
                    "role": role,
                    "outcome": HTTP_RESPONSE,
                    "status": outcome.response.status_code,
                    "body_digest_complete": outcome.response.body_digest_complete,
                    "body_retained_complete": outcome.response.body_retained_complete,
                },
            )

    def _prepare_stable_response_headers(
        self, plan: ExperimentPlan
    ) -> tuple[ExperimentPlan, HeaderCoverage]:
        controls: list[tuple[dict[str, tuple[str, ...]], str | None]] = []
        count = plan.experiment.stable_header_control_observations
        for index in range(1, count + 1):
            outcome = self._send_observation(
                plan,
                arm="control",
                request=plan.baseline,
                round_index=0,
                sequence=index,
                initial_role="setup",
            )
            if not outcome.succeeded or not isinstance(outcome.response, CapturedResponse):
                raise RuntimeError("stable response-header setup control failed")
            response = outcome.response
            if response.response_limit_exceeded:
                raise BudgetError(
                    "HEADER_SETUP_RESPONSE_LIMIT",
                    "stable response-header setup control exceeded the response bound",
                )
            field_lists: dict[str, list[str]] = {}
            for name, value in response.headers:
                field_lists.setdefault(name.lower(), []).append(value)
            normalized_fields = {
                name: tuple(values) for name, values in field_lists.items()
            }
            controls.append((normalized_fields, response.final_url))
            self.evidence.record(
                "OBSERVATION_COMPLETED",
                {
                    "round_index": 0,
                    "sequence": index,
                    "role": "setup",
                    "outcome": HTTP_RESPONSE,
                    "status": response.status_code,
                    "body_digest_complete": response.body_digest_complete,
                    "body_retained_complete": response.body_retained_complete,
                },
            )
            self.transport.complete_round(-index)

        observed: set[str] = set()
        for fields, _ in controls:
            observed.update(fields)
        ignored = {
            name.lower()
            for name in (
                *plan.experiment.equivalence.ignore_headers,
                *plan.experiment.exclude_response_headers,
            )
        }
        stable: set[str] = set()
        for name in observed:
            canonical: list[tuple[object, ...]] = []
            present = True
            for fields, final_url in controls:
                if name not in fields:
                    present = False
                    break
                canonical.append(canonical_header_values(name, fields[name], base_url=final_url))
            if present and all(value == canonical[0] for value in canonical[1:]):
                stable.add(name)

        pattern_selected = {
            name
            for name in stable
            if any(
                fnmatchcase(name, pattern.lower())
                for pattern in plan.experiment.include_response_header_patterns
            )
        }
        profile_fields = _HEADER_PROFILES.get(plan.experiment.response_header_profile or "", frozenset())
        forced = (
            _BODY_SAFETY_FIELDS
            | {name.lower() for name in plan.experiment.include_response_headers}
            | set(profile_fields)
        )
        promoted = (stable | pattern_selected | forced) - ignored
        effective = replace(
            plan,
            experiment=replace(
                plan.experiment,
                include_response_headers=tuple(sorted(promoted)),
            ),
        )
        coverage = HeaderCoverage(
            mode="all-stable",
            complete=True,
            all_fields_evaluated=True,
            policy_version="stable-response-headers/1.0",
            control_observations=count,
            observed_fields=tuple(sorted(observed)),
            promoted_fields=tuple(sorted(promoted)),
            volatile_fields=tuple(sorted((observed - stable) - ignored)),
            ignored_fields=tuple(sorted(observed & ignored)),
            forced_fields=tuple(sorted(forced - ignored)),
        )
        return effective, coverage

    def _send_observation(
        self,
        plan: ExperimentPlan,
        *,
        arm: str,
        request: RawRequest,
        round_index: int,
        sequence: int,
        initial_role: str | None = None,
    ) -> SendOutcome:
        session_arm = arm if arm in {"control", "mutation"} else "control"
        with self.transport.observation_session(
            arm=session_arm,
            round_index=round_index,
        ):
            return self._send_observation_in_session(
                plan,
                arm=arm,
                request=request,
                round_index=round_index,
                sequence=sequence,
                initial_role=initial_role,
            )

    def _send_observation_in_session(
        self,
        plan: ExperimentPlan,
        *,
        arm: str,
        request: RawRequest,
        round_index: int,
        sequence: int,
        initial_role: str | None = None,
    ) -> SendOutcome:
        role = initial_role or ("mutation" if arm == "mutation" else "control")
        current = request
        current_base = plan.base_url
        allow_cookie_field = True
        redirect_chain: list[RedirectHop] = []
        all_attempts: list[AttemptRecord] = []
        redirect_depth = 0
        while True:
            outcome = self._send_with_retries(
                plan,
                request=current,
                base_url=current_base,
                role="redirect" if redirect_depth else role,
                arm=arm,
                round_index=round_index,
                sequence=sequence,
                redirect_depth=redirect_depth,
                allow_cookie_field=allow_cookie_field,
            )
            offset = len(all_attempts)
            all_attempts.extend(
                replace(record, attempt=record.attempt + offset) for record in outcome.attempt_trace
            )
            if not outcome.succeeded:
                return SendOutcome(
                    response=None,
                    error=outcome.error,
                    attempts=len(all_attempts),
                    attempt_trace=tuple(all_attempts),
                )
            response = outcome.response
            assert isinstance(response, CapturedResponse)
            if not plan.follow_redirects or response.status_code not in _REDIRECT_STATUSES:
                final = replace(response, redirect_chain=tuple(redirect_chain))
                if all_attempts:
                    all_attempts[-1] = replace(all_attempts[-1], response=final)
                return SendOutcome(
                    response=final,
                    error=None,
                    attempts=len(all_attempts),
                    attempt_trace=tuple(all_attempts),
                )

            locations = [value for name, value in response.headers if name.lower() == "location"]
            if len(locations) != 1:
                error = AuthorizationError(
                    "AMBIGUOUS_REDIRECT_LOCATION",
                    "redirect requires exactly one well-formed Location field",
                )
                raise error
            source_url = response.final_url or canonical_uri(current_base)
            target_url = canonical_uri(urljoin(source_url, locations[0]))
            redirect_policy = self.authorization.manifest.redirects
            if redirect_policy.mode == "deny":
                self._reject_redirect("REDIRECT_NOT_AUTHORIZED")
            if redirect_depth >= redirect_policy.maximum_depth:
                self._reject_redirect("REDIRECT_DEPTH_EXHAUSTED")
            source_origin = _origin(source_url)
            target_origin = _origin(target_url)
            cross_origin = source_origin != target_origin
            if redirect_policy.mode == "same-origin" and cross_origin:
                self._reject_redirect("CROSS_ORIGIN_REDIRECT_NOT_AUTHORIZED")

            (
                next_request,
                method_changed,
                credential_forwarding,
                retained_headers,
                stripped_headers,
            ) = _redirect_request(
                current,
                target_url,
                response.status_code,
                cross_origin=cross_origin,
                cross_origin_mode=redirect_policy.cross_origin_headers.mode,
                cross_origin_allow=redirect_policy.cross_origin_headers.allow,
            )
            self.evidence.record(
                "REDIRECT_PROPOSED",
                {
                    "round_index": round_index,
                    "status": response.status_code,
                    "source_fingerprint": _fingerprint(source_url),
                    "target_fingerprint": _fingerprint(target_url),
                    "next_depth": redirect_depth + 1,
                    "cross_origin": cross_origin,
                    "header_policy": redirect_policy.cross_origin_headers.mode,
                    "retained_header_names": [
                        plan.experiment.redactor.header_name(name)
                        for name in retained_headers
                    ],
                    "stripped_header_names": [
                        plan.experiment.redactor.header_name(name)
                        for name in stripped_headers
                    ],
                    "method_changed": method_changed,
                },
            )
            redirect_chain.append(
                RedirectHop(
                    status=response.status_code,
                    method=current.method,
                    origin=source_origin,
                    target_origin=target_origin,
                    location=locations[0],
                    cross_origin=cross_origin,
                    method_changed=method_changed,
                    credential_forwarding=credential_forwarding,
                    resolved_target=target_url,
                )
            )
            allow_cross_origin_cookie = (
                redirect_policy.cross_origin_headers.mode == "explicit"
                and (
                    "*" in redirect_policy.cross_origin_headers.allow
                    or "cookie" in redirect_policy.cross_origin_headers.allow
                )
            )
            if cross_origin and not allow_cross_origin_cookie:
                self.transport.clear_observation_cookies()
            current = next_request
            current_base = target_url
            allow_cookie_field = not cross_origin or allow_cross_origin_cookie
            redirect_depth += 1

    def _reject_redirect(self, code: str) -> NoReturn:
        self.evidence.record("REDIRECT_REJECTED", {"decision_code": code})
        raise AuthorizationError(code, "redirect policy rejected hop")

    def _send_with_retries(
        self,
        plan: ExperimentPlan,
        *,
        request: RawRequest,
        base_url: str,
        role: str,
        arm: str,
        round_index: int,
        sequence: int,
        redirect_depth: int,
        allow_cookie_field: bool = True,
    ) -> SendOutcome:
        trace: list[AttemptRecord] = []
        retry_statuses = set(plan.send.retry_status)
        for attempt_index in range(1, plan.send.retries + 2):
            self._gate.wait(plan.send)
            attempt_role = role if attempt_index == 1 else "retry"
            started = time.perf_counter()
            response: CapturedResponse | None = None
            error: Exception | None = None
            try:
                response = self._attempt(
                    plan,
                    request=request,
                    base_url=base_url,
                    role=attempt_role,
                    arm=arm,
                    round_index=round_index,
                    sequence=sequence,
                    redirect_depth=redirect_depth,
                    allow_cookie_field=allow_cookie_field,
                )
            except Exception as exc:
                if getattr(exc, "mrma_fatal_policy_error", False):
                    raise
                error = exc
            elapsed_ms = round((time.perf_counter() - started) * 1000, 3)
            retry_reason: str | None = None
            if error is not None:
                if attempt_index <= plan.send.retries:
                    retry_reason = "transport-error"
            elif response is not None and response.status_code in retry_statuses:
                if attempt_index <= plan.send.retries:
                    retry_reason = "configured-status"
            backoff = None
            if retry_reason is not None:
                backoff_s = min(
                    plan.send.backoff_cap_s,
                    plan.send.backoff_base_s * (2 ** (attempt_index - 1)),
                )
                backoff = round(backoff_s * 1000, 3)
            trace.append(
                AttemptRecord(
                    attempt=attempt_index,
                    response=response,
                    error=error,
                    elapsed_ms=elapsed_ms,
                    retry_reason=retry_reason,
                    backoff_ms=backoff,
                )
            )
            if retry_reason is None:
                return SendOutcome(
                    response=response,
                    error=error,
                    attempts=len(trace),
                    attempt_trace=tuple(trace),
                )
            time.sleep(backoff / 1000 if backoff is not None else 0)
        raise AssertionError("retry loop did not return")

    def _attempt(
        self,
        plan: ExperimentPlan,
        *,
        request: RawRequest,
        base_url: str,
        role: str,
        arm: str,
        round_index: int,
        sequence: int,
        redirect_depth: int,
        allow_cookie_field: bool = True,
    ) -> CapturedResponse:
        self._attempt_sequence += 1
        attempt_id = f"a{self._attempt_sequence:06d}-{uuid.uuid4().hex[:12]}"
        evidence = EvidenceContext(
            run_id=self.evidence.run_id,
            attempt_id=attempt_id,
            role=role,
            round_index=round_index,
        )
        mutation_attempt = arm == "mutation"
        declared_risk = plan.mutation_risk_class if mutation_attempt else "safe"
        risk = max(
            (declared_risk, classify_method(request.method).risk_class),
            key=RISK_RANK.__getitem__,
        )
        try:
            context = self.authorization.authorize(
                request,
                base_url=base_url,
                attempt_kind=role,
                mutation_family=plan.mutation_family if mutation_attempt else None,
                risk_class=risk,
                proxy_url=self.transport.options.proxy,
            )
        except AuthorizationError as exc:
            self.evidence.record(
                "AUTHORIZATION_REJECTED",
                {
                    "attempt_id": attempt_id,
                    "role": role,
                    "decision_code": exc.code,
                    "candidate_target_fingerprint": _fingerprint(base_url + "\n" + request.path),
                },
            )
            raise
        self.evidence.record(
            "AUTHORIZATION_ACCEPTED",
            {
                "attempt_id": attempt_id,
                "role": role,
                "decision_code": context.decision.code,
                "manifest_digest": context.decision.manifest_digest,
                "target_fingerprint": context.decision.target_fingerprint,
                "address_set_fingerprint": context.decision.address_set_fingerprint,
                "proxy_address_set_fingerprint": context.decision.proxy_address_set_fingerprint,
                "host_authority_fingerprint": context.decision.host_authority_fingerprint,
                "sni_authority_fingerprint": context.decision.sni_authority_fingerprint,
                "proxy_connect_authority_fingerprint": context.decision.proxy_connect_authority_fingerprint,
            },
        )
        if role == "redirect":
            self.evidence.record(
                "REDIRECT_AUTHORIZED",
                {
                    "attempt_id": attempt_id,
                    "round_index": round_index,
                    "target_fingerprint": context.decision.target_fingerprint,
                    "next_depth": redirect_depth,
                },
            )
        timeout_ms = int(self.transport.options.timeout_s * 1000)
        if timeout_ms > self.budgets.limits.per_attempt_timeout_ms:
            raise BudgetError(
                "ATTEMPT_TIMEOUT_LIMIT",
                "transport timeout exceeds the authorized per-attempt timeout",
            )
        proposed = AttemptCost(
            kind=role,
            origin_fingerprint=origin_fingerprint(context.decision.canonical_origin),
            target_fingerprint=context.decision.target_fingerprint,
            request_body_bytes=len(request.body),
            request_bytes=estimate_semantic_request_bytes(request, context.canonical_url),
            response_bytes=min(
                plan.experiment.max_response_bytes,
                self.budgets.limits.maximum_response_bytes,
            ),
            timeout_ms=timeout_ms,
            redirect_depth=redirect_depth,
            mutation_risk_level=risk,
        )
        lease = self.budgets.reserve(proposed, evidence=evidence)
        try:
            try:
                context = self.authorization.revalidate(context)
            except AuthorizationError as exc:
                self.evidence.record(
                    "AUTHORIZATION_REJECTED",
                    {
                        "attempt_id": attempt_id,
                        "role": role,
                        "policy_phase": "immediate-pre-transport",
                        "decision_code": exc.code,
                        "candidate_target_fingerprint": context.decision.target_fingerprint,
                    },
                )
                raise
            self.evidence.record(
                "AUTHORIZATION_ACCEPTED",
                {
                    "attempt_id": attempt_id,
                    "role": role,
                    "policy_phase": "immediate-pre-transport",
                    "decision_code": context.decision.code,
                    "manifest_digest": context.decision.manifest_digest,
                    "target_fingerprint": context.decision.target_fingerprint,
                    "address_set_fingerprint": context.decision.address_set_fingerprint,
                    "proxy_address_set_fingerprint": context.decision.proxy_address_set_fingerprint,
                    "host_authority_fingerprint": context.decision.host_authority_fingerprint,
                    "sni_authority_fingerprint": context.decision.sni_authority_fingerprint,
                    "proxy_connect_authority_fingerprint": context.decision.proxy_connect_authority_fingerprint,
                    "dns_answer_changed": context.decision.code == "AUTHORIZED_DNS_CHANGED",
                },
            )
            return self.transport.send(
                request,
                authorization=context,
                lease=lease,
                evidence=evidence,
                arm="mutation" if arm == "mutation" else "control",
                round_index=round_index,
                body_storage=plan.experiment.body_storage,
                allow_cookie_field=allow_cookie_field,
            )
        finally:
            if lease.active:
                lease.release("transport-did-not-consume")


def _fingerprint(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


def _origin(url: str) -> str:
    parsed = urlsplit(url)
    host = parsed.hostname or ""
    display = f"[{host}]" if ":" in host else host
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return f"{parsed.scheme.lower()}://{display}:{port}"


def _redirect_request(
    request: RawRequest,
    target_url: str,
    status: int,
    *,
    cross_origin: bool,
    cross_origin_mode: str,
    cross_origin_allow: tuple[str, ...],
) -> tuple[RawRequest, bool, str, tuple[str, ...], tuple[str, ...]]:
    method = request.method
    next_method = method
    if status == 303 and method != "HEAD":
        next_method = "GET"
    elif status in {301, 302} and method == "POST":
        next_method = "GET"
    method_changed = next_method != method
    headers: list[tuple[str, str]] = []
    credentials_present = False
    credentials_retained = False
    retained_names: list[str] = []
    stripped_names: list[str] = []
    allow_all_cross_origin = cross_origin_mode == "explicit" and "*" in cross_origin_allow
    cross_origin_fields = (
        set(cross_origin_allow)
        if cross_origin_mode == "explicit"
        else set(_SAFE_CROSS_ORIGIN_FIELDS)
    )
    for name, value in request.headers:
        lowered = name.lower()
        if lowered == "host":
            stripped_names.append(lowered)
            continue
        sensitive = lowered in _CREDENTIAL_FIELDS or any(
            marker in lowered for marker in _SENSITIVE_FIELD_MARKERS
        )
        if sensitive:
            credentials_present = True
        if method_changed and lowered in _CONTENT_FIELDS:
            stripped_names.append(lowered)
            continue
        if cross_origin and not allow_all_cross_origin and lowered not in cross_origin_fields:
            stripped_names.append(lowered)
            continue
        if sensitive:
            credentials_retained = True
        headers.append((name, value))
        retained_names.append(lowered)
    if not credentials_present:
        credential_forwarding = "none"
    elif credentials_retained:
        credential_forwarding = "retained"
    else:
        credential_forwarding = "stripped"
    return (
        replace(
            request,
            method=next_method,
            path=target_url,
            target_form="absolute",
            headers=headers,
            body=b"" if method_changed else request.body,
            original_sha256=None,
        ),
        method_changed,
        credential_forwarding,
        tuple(dict.fromkeys(retained_names)),
        tuple(dict.fromkeys(stripped_names)),
    )
