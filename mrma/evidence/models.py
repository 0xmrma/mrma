from __future__ import annotations

import platform
import ssl
import sys
from importlib.metadata import PackageNotFoundError, version
from typing import TYPE_CHECKING, cast

from mrma import __version__
from mrma.core.compare import COMPARATOR_VERSION, GUARDED_JSON_VERSION, NORMALIZER_VERSION
from mrma.core.experiment import AttemptEvidence, Observation, PairEvidence
from mrma.core.http_semantics import SEMANTIC_REGISTRY_VERSION
from mrma.core.privacy import EvidenceRedactor
from mrma.policy.authorization import ManifestAuthorizationPolicy
from mrma.policy.budget import BUDGET_MODEL_VERSION, BudgetLedger
from mrma.transport.semantic_http import (
    SEMANTIC_REQUEST_ESTIMATE_VERSION,
    TRANSPORT_ADAPTER_VERSION,
)

from .journal import JOURNAL_SCHEMA_VERSION, EvidenceJournal

if TYPE_CHECKING:
    from mrma.engine.oracle import OracleRunResult
    from mrma.engine.plan import ExperimentPlan

EXPERIMENT_SCHEMA_VERSION = "mrma.experiment/v7"


def _package_version(name: str) -> str | None:
    try:
        return version(name)
    except PackageNotFoundError:
        return None


def runtime_provenance(
    *,
    source_commit: str | None = None,
    package_digest: str | None = None,
    container_image_digest: str | None = None,
) -> dict[str, object]:
    return {
        "mrma_version": __version__,
        "source_commit": source_commit,
        "package_digest": package_digest,
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "operating_system": platform.system(),
        "operating_system_release": platform.release(),
        "machine": platform.machine(),
        "httpx_version": _package_version("httpx"),
        "httpcore_version": _package_version("httpcore"),
        "regex_version": _package_version("regex"),
        "openssl_version": ssl.OPENSSL_VERSION,
        "container_image_digest": container_image_digest,
        "executable_kind": "python",
        "python_hexversion": sys.hexversion,
    }


def _attempt(item: AttemptEvidence, redactor: EvidenceRedactor) -> dict[str, object]:
    return {
        "attempt": item.attempt,
        "outcome": item.outcome,
        "status": item.status,
        "elapsed": redactor.elapsed_ms(item.elapsed_ms),
        "retry_reason": item.retry_reason,
        "backoff": redactor.elapsed_ms(item.backoff_ms) if item.backoff_ms is not None else None,
        "error_type": item.error_type,
    }


def _observation(item: Observation, redactor: EvidenceRedactor) -> dict[str, object]:
    headers = []
    for name, values in sorted(item.headers.items()):
        headers.append(
            {
                "name": redactor.header_name(name),
                "values": [
                    {
                        "length": redactor.size(len(value)),
                        "fingerprint": redactor.fingerprint(
                            f"{name}\0{value}", label="response-header"
                        ),
                    }
                    for value in values
                ],
            }
        )
    redirects = []
    for hop in item.redirect_chain:
        redirects.append(
            {
                "status": hop.status,
                "method": hop.method,
                "origin": redactor.origin(hop.origin),
                "target_origin": redactor.origin(hop.target_origin),
                "raw_location_fingerprint": (
                    redactor.fingerprint(hop.location, label="redirect-location")
                    if hop.location is not None
                    else None
                ),
                "resolved_target": (
                    redactor.url(hop.resolved_target) if hop.resolved_target is not None else None
                ),
                "cross_origin": hop.cross_origin,
                "method_changed": hop.method_changed,
                "credential_forwarding": hop.credential_forwarding,
            }
        )
    return {
        "arm": item.arm,
        "round": item.round_index,
        "sequence": item.sequence,
        "outcome": item.outcome,
        "status": item.status,
        "body": {
            "observed_length": redactor.size(item.length),
            "fingerprint": redactor.fingerprint(
                item.body_sha256, label="response-body-digest"
            ),
            "digest_complete": item.body_digest_complete,
            "retained_complete": item.body_retained_complete,
        },
        "charset_resolution": {
            "declared_media_type": item.body_comparator_media_type,
            "declared_charset": item.body_comparator_declared_charset,
            "resolved_charset": item.body_comparator_charset,
            "resolution_source": item.body_comparator_resolution_source,
            "eligible": item.body_comparator_eligible,
            "reasons": list(item.body_comparator_reasons),
            "registry_version": item.semantic_registry_version,
        },
        "elapsed": redactor.elapsed_ms(item.elapsed_ms),
        "attempts": [_attempt(attempt, redactor) for attempt in item.attempt_trace],
        "response_headers": headers,
        "redirect_chain": redirects,
        "error_type": item.error_type,
        "final_origin": redactor.origin(item.final_origin) if item.final_origin else None,
        "negotiated_http_version": item.http_version,
    }


def _pair(item: PairEvidence, redactor: EvidenceRedactor) -> dict[str, object]:
    return {
        "round": item.round_index,
        "classification": item.classification,
        "status_changed": item.status_changed,
        "body_changed": item.body_changed,
        "outcome_changed": item.outcome_changed,
        "redirect_changed": item.redirect_changed,
        "retry_changed": item.retry_changed,
        "similarity": item.similarity,
        "length_delta_ratio": item.length_delta_ratio,
        "response_header_differences": [
            redactor.header_name(name) for name in item.header_diffs
        ],
        "redirect_differences": list(item.redirect_diffs),
        "attempt_differences": list(item.attempt_diffs),
        "comparator": item.comparator,
        "comparator_resource_limit": item.comparator_resource_limit,
        "normalization": [
            {
                "rule_type": outcome.rule_type,
                "rule_fingerprint": redactor.fingerprint(
                    outcome.rule, label="normalization-rule"
                ),
                "outcome": outcome.outcome,
                "elapsed": redactor.elapsed_ms(outcome.elapsed_ms),
            }
            for outcome in item.normalization_outcomes
        ],
        "attempt_elapsed_delta": (
            redactor.elapsed_ms(abs(item.attempt_elapsed_delta_ms))
            if item.attempt_elapsed_delta_ms is not None
            else None
        ),
        "backoff_delta": (
            redactor.elapsed_ms(abs(item.backoff_delta_ms))
            if item.backoff_delta_ms is not None
            else None
        ),
    }


def build_experiment_v7(
    result: OracleRunResult,
    *,
    plan: ExperimentPlan,
    authorization: ManifestAuthorizationPolicy,
    budgets: BudgetLedger,
    journal: EvidenceJournal,
    run_id: str,
    started_at: str,
    completed_at: str,
    duration_ms: float,
    transport_configuration: dict[str, object],
    source_commit: str | None = None,
    package_digest: str | None = None,
    container_image_digest: str | None = None,
    insecure_exception: bool = False,
) -> dict[str, object]:
    analysis = result.experiment
    redactor = analysis.config.redactor
    public_analysis = analysis.to_dict()
    public_limitations = cast(list[dict[str, str]], public_analysis["limitations"])
    limitations_by_code: dict[str, dict[str, str]] = {
        item["code"]: item for item in public_limitations
    }
    for item in result.limitations:
        limitations_by_code[item["code"]] = item
    if source_commit is None and package_digest is None:
        limitations_by_code["SOURCE_IDENTITY_UNAVAILABLE"] = {
            "code": "SOURCE_IDENTITY_UNAVAILABLE",
            "severity": "low",
            "scope": "runtime_provenance",
            "message": "Neither a source commit nor an installed package digest was supplied.",
            "remediation": "Run a signed release artifact with recorded provenance.",
        }
    limitations_by_code["SEMANTIC_REQUEST_BYTE_ESTIMATE"] = {
        "code": "SEMANTIC_REQUEST_BYTE_ESTIMATE",
        "severity": "low",
        "scope": "budget_accounting",
        "message": "Sent-byte accounting is a conservative semantic estimate, not wire telemetry.",
        "remediation": "Use a future protocol-exact backend when exact wire-byte accounting is required.",
    }
    comparator_failures = sorted(
        {
            pair.comparator_resource_limit
            for pair in analysis.pairs
            if pair.comparator_resource_limit is not None
        }
    )
    complete_sampling = (
        result.status == "completed"
        and result.completed_rounds == result.planned_rounds
        and len(analysis.observations) == result.plan.maximum_logical_observations
    )
    assurance_profile = cast(dict[str, object], public_analysis["assurance_profile"])
    assurance = {
        "authorization_enforcement": "moderate",
        "budget_enforcement": "strong",
        "journal_recoverability": "strong" if journal.mode == "durable" else "moderate",
        "statistical_decisiveness": assurance_profile["statistical_decisiveness"],
        "control_stability": assurance_profile["control_stability"],
        "connection_independence": assurance_profile["connection_independence"],
        "state_isolation": assurance_profile["state_isolation"],
        "transport_integrity": assurance_profile["transport_integrity"],
        "protocol_fidelity": "limited",
        "sampling_complete": complete_sampling,
    }
    runtime = runtime_provenance(
        source_commit=source_commit,
        package_digest=package_digest,
        container_image_digest=container_image_digest,
    )
    negotiated = sorted(
        {
            item.http_version
            for item in analysis.observations
            if item.http_version is not None
        }
    )
    raw_effect = cast(dict[str, object], public_analysis["effect"])
    response_header_shifts = cast(
        dict[str, int], raw_effect["response_header_shift_counts"]
    )
    outcome_counts = cast(dict[str, int], raw_effect["outcome_counts"])
    budget_consumed = result.budget.to_dict()
    budget_consumed["attempts_by_origin"] = [
        list(item) for item in result.budget.attempts_by_origin
    ]
    budget_consumed["requests_by_target"] = [
        list(item) for item in result.budget.requests_by_target
    ]
    effect = {
        "mutation_median_similarity": raw_effect["mutation_median_similarity"],
        "control_minus_mutation_similarity": raw_effect[
            "control_minus_mutation_similarity"
        ],
        "status_shift_rounds": raw_effect["status_shift_rounds"],
        "outcome_shift_rounds": raw_effect["outcome_shift_rounds"],
        "redirect_shift_rounds": raw_effect["redirect_shift_rounds"],
        "retry_shift_rounds": raw_effect["retry_shift_rounds"],
        "response_header_shifts": [
            {"name": name, "rounds": count}
            for name, count in sorted(response_header_shifts.items())
        ],
        "outcome_counts": [
            {"outcome": outcome, "count": count}
            for outcome, count in sorted(outcome_counts.items())
        ],
        "retry_timing": raw_effect["retry_timing"],
    }
    return {
        "schema_version": EXPERIMENT_SCHEMA_VERSION,
        "run": {
            "id": run_id,
            "status": result.status,
            "started_at": redactor.run_timestamp(started_at),
            "completed_at": redactor.run_timestamp(completed_at),
            "timestamp_precision": {
                "standard": "minute",
                "strict": "date",
                "forensic": "millisecond",
            }[redactor.policy],
            "duration": redactor.run_duration_ms(duration_ms),
            "stop_reason": result.stop_reason,
            "planned_rounds": result.planned_rounds,
            "completed_rounds": result.completed_rounds,
            "complete_sampling": complete_sampling,
            "verdict": result.verdict,
        },
        "tool": {
            "name": "mrma",
            "version": __version__,
            "runtime": runtime,
        },
        "authorization": {
            "validated": True,
            "bypass": False,
            **authorization.manifest.public_summary(),
        },
        "plan": result.plan.to_dict(),
        "budget": {
            "model_version": BUDGET_MODEL_VERSION,
            "duration_accounting": {
                "charged_duration": "cumulative-attempt-elapsed-clamped-to-reservation",
                "admission_deadline": "monotonic-wall-clock",
                "backoff_and_processing": "covered-by-admission-deadline",
            },
            "request_accounting": {
                "basis": "conservative-semantic-upper-bound",
                "version": SEMANTIC_REQUEST_ESTIMATE_VERSION,
                "wire_telemetry": False,
            },
            "limits": budgets.limits.__dict__,
            "consumed": budget_consumed,
            "settled": result.budget.active_leases == 0,
        },
        "journal": {
            "schema_version": JOURNAL_SCHEMA_VERSION,
            "mode": journal.mode,
            "event_count": result.journal_event_count,
            "head_digest": result.journal_head_digest,
            "hash_algorithm": "sha256",
            "file_sync": journal.file_sync,
            "directory_sync": journal.directory_sync,
            "durable_claim": (
                journal.mode == "durable"
                and journal.file_sync
                and journal.directory_sync == "performed"
            ),
        },
        "transport": {
            "mode": "semantic-http",
            "adapter": TRANSPORT_ADAPTER_VERSION,
            "wire_exact": False,
            "manual_redirects": True,
            "requested_http_version": plan.baseline.http_version,
            "negotiated_http_versions": negotiated,
            "connection_mode": analysis.config.connection_mode,
            "state_mode": analysis.config.state_mode,
            **transport_configuration,
            "insecure_exception": insecure_exception,
            "connected_address_fingerprint": None,
            "tls_connection": None,
        },
        "comparison": {
            "semantic_registry_version": SEMANTIC_REGISTRY_VERSION,
            "comparator_version": COMPARATOR_VERSION,
            "normalizer_version": NORMALIZER_VERSION,
            "guarded_json_version": GUARDED_JSON_VERSION,
            "regex_engine": "regex",
            "regex_version": runtime["regex_version"],
            "regex_bounded": True,
            "similarity_exact": False,
            "resource_failures": comparator_failures,
        },
        "experiment_role": {
            "role": plan.exploration_role,
            "assurance_preset": analysis.config.assurance_preset,
            "candidate_manifest_digest": plan.candidate_manifest_digest,
            "selection_affects_inference": plan.exploration_role == "exploration",
        },
        "analysis": {
            "verdict": result.verdict,
            "stop_reason": result.stop_reason,
            "reproducibility": public_analysis["reproducibility"],
            "control_stability": public_analysis["control_stability"],
            "effect": effect,
            "reasons": list(analysis.reasons),
            "observations": [_observation(item, redactor) for item in analysis.observations],
            "round_evidence": [_pair(item, redactor) for item in analysis.pairs],
        },
        "response_header_coverage": {
            "mode": result.header_coverage.mode,
            "complete": result.header_coverage.complete,
            "all_fields_evaluated": result.header_coverage.all_fields_evaluated,
            "policy_version": result.header_coverage.policy_version,
            "control_observations": result.header_coverage.control_observations,
            "observed_fields": [
                redactor.header_name(name) for name in result.header_coverage.observed_fields
            ],
            "decision_fields": [
                redactor.header_name(name) for name in result.header_coverage.promoted_fields
            ],
            "volatile_fields": [
                redactor.header_name(name) for name in result.header_coverage.volatile_fields
            ],
            "ignored_fields": [
                redactor.header_name(name) for name in result.header_coverage.ignored_fields
            ],
            "forced_fields": [
                redactor.header_name(name) for name in result.header_coverage.forced_fields
            ],
        },
        "assurance": assurance,
        "privacy": {
            "policy": redactor.policy,
            "fingerprints": "per-run keyed HMAC-SHA256",
            "cross_run_correlation": False,
        },
        "limitations": [limitations_by_code[key] for key in sorted(limitations_by_code)],
    }
