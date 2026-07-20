from __future__ import annotations

import hashlib
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from types import TracebackType

from mrma.core.http_client import (
    _GUARDED_TRANSPORT_CAPABILITY,
    CapturedResponse,
    SemanticHttpTransport,
    SendOptions,
)
from mrma.core.raw_request import RawRequest
from mrma.evidence.journal import EvidenceContext, EvidenceJournal
from mrma.policy.authorization import AuthorizedRequestContext, request_fingerprint
from mrma.policy.budget import BudgetLease

TRANSPORT_ADAPTER_VERSION = "semantic-httpx/1.0"
SEMANTIC_REQUEST_ESTIMATE_VERSION = "semantic-request-upper-bound/1.0"
_LIBRARY_REQUEST_OVERHEAD_BYTES = 2048


class TransportPolicyError(RuntimeError):
    mrma_fatal_policy_error = True

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


class SemanticHttpAdapter:
    """One-attempt HTTPX adapter requiring authorization, budget, and evidence."""

    def __init__(
        self,
        options: SendOptions,
        *,
        journal: EvidenceJournal,
        state_mode: str = "isolated",
        connection_mode: str = "fresh-observation",
    ) -> None:
        if options.trust_env:
            raise TransportPolicyError(
                "AMBIENT_TRANSPORT_CONFIGURATION_REJECTED",
                "authorization-first transport requires explicit proxy and CA configuration",
            )
        if options.follow_redirects:
            options = replace(options, follow_redirects=False)
        self.options = options
        self.journal = journal
        self._transport = SemanticHttpTransport(
            options,
            state_mode=state_mode,
            connection_mode=connection_mode,
            authorization_kernel=_GUARDED_TRANSPORT_CAPABILITY,
        )
        self._entered = False

    def __enter__(self) -> SemanticHttpAdapter:
        self._transport.__enter__()
        self._entered = True
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        if self._entered:
            self._transport.close()
            self._entered = False

    def complete_round(self, round_index: int) -> None:
        self._transport.complete_round(round_index)

    @contextmanager
    def observation_session(
        self,
        *,
        arm: str,
        round_index: int | None,
    ) -> Iterator[None]:
        if not self._entered:
            raise TransportPolicyError("TRANSPORT_NOT_ENTERED", "adapter context is not active")
        normalized_arm = arm if arm in {"control", "mutation"} else "control"
        with self._transport.observation_session(
            arm=normalized_arm,
            round_index=round_index,
        ):
            yield

    def public_policy(self) -> dict[str, object]:
        return {
            "adapter": TRANSPORT_ADAPTER_VERSION,
            "timeout_s": self.options.timeout_s,
            "follow_redirects": False,
            "trust_environment": self.options.trust_env,
            "tls_verification": self.options.verify_tls,
            "proxy_configured": self.options.proxy is not None,
            "state_mode": self._transport.state_mode,
            "connection_mode": self._transport.connection_mode,
        }

    def send(
        self,
        request: RawRequest,
        *,
        authorization: AuthorizedRequestContext,
        lease: BudgetLease,
        evidence: EvidenceContext,
        arm: str,
        round_index: int | None,
        body_storage: str,
    ) -> CapturedResponse:
        if not self._entered:
            raise TransportPolicyError("TRANSPORT_NOT_ENTERED", "adapter context is not active")
        if not lease.active:
            raise TransportPolicyError("BUDGET_LEASE_REQUIRED", "budget lease is inactive")
        if lease.evidence != evidence:
            raise TransportPolicyError("EVIDENCE_CONTEXT_MISMATCH", "lease belongs to another attempt")
        if evidence.run_id != self.journal.run_id:
            raise TransportPolicyError("EVIDENCE_RUN_MISMATCH", "evidence belongs to another run")
        if not authorization.decision.accepted:
            raise TransportPolicyError("AUTHORIZATION_REQUIRED", "authorization was not accepted")
        observed_fingerprint = request_fingerprint(request, authorization.canonical_url)
        if observed_fingerprint != authorization.request_fingerprint:
            raise TransportPolicyError(
                "AUTHORIZATION_REQUEST_MISMATCH",
                "request changed after authorization",
            )
        if lease.proposed.target_fingerprint != authorization.decision.target_fingerprint:
            raise TransportPolicyError("LEASE_TARGET_MISMATCH", "lease belongs to another target")
        if lease.proposed.origin_fingerprint != _origin_fingerprint(
            authorization.decision.canonical_origin
        ):
            raise TransportPolicyError("LEASE_ORIGIN_MISMATCH", "lease belongs to another origin")
        if len(request.body) > lease.proposed.request_body_bytes:
            raise TransportPolicyError("LEASE_SEND_OVERRUN", "request body exceeds reservation")
        request_bytes = estimate_semantic_request_bytes(request, authorization.canonical_url)
        if request_bytes > lease.proposed.request_bytes:
            raise TransportPolicyError(
                "LEASE_SEND_OVERRUN", "semantic request estimate exceeds reservation"
            )

        self.journal.record(
            "ATTEMPT_STARTED",
            {
                "run_id": evidence.run_id,
                "attempt_id": evidence.attempt_id,
                "role": evidence.role,
                "round_index": evidence.round_index,
                "target_fingerprint": authorization.decision.target_fingerprint,
                "address_set_fingerprint": authorization.decision.address_set_fingerprint,
                "host_authority_fingerprint": authorization.decision.host_authority_fingerprint,
                "sni_authority_fingerprint": authorization.decision.sni_authority_fingerprint,
                "proxy_connect_authority_fingerprint": (
                    authorization.decision.proxy_connect_authority_fingerprint
                ),
                "method": authorization.decision.method,
                "transport_adapter": TRANSPORT_ADAPTER_VERSION,
                "redirects_followed_by_adapter": False,
            },
        )
        started = time.perf_counter()
        rebound = replace(request, path=authorization.canonical_url, target_form="absolute")
        try:
            response = self._transport.capture(
                rebound,
                authorization.canonical_url,
                arm if arm in {"control", "mutation"} else "control",
                max_response_bytes=lease.response_allowance,
                body_storage=body_storage,
                round_index=round_index,
            )
        except Exception as exc:
            elapsed_ms = int((time.perf_counter() - started) * 1000)
            lease.commit(
                bytes_sent=request_bytes,
                bytes_received=0,
                duration_ms=elapsed_ms,
            )
            self.journal.record(
                "ATTEMPT_COMPLETED",
                {
                    "run_id": evidence.run_id,
                    "attempt_id": evidence.attempt_id,
                    "outcome": "transport-error",
                    "error_type": type(exc).__name__,
                    "duration_ms": elapsed_ms,
                },
            )
            raise
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        charged_received = min(response.body_length, lease.response_allowance)
        lease.commit(
            bytes_sent=request_bytes,
            bytes_received=charged_received,
            duration_ms=elapsed_ms,
        )
        self.journal.record(
            "ATTEMPT_COMPLETED",
            {
                "run_id": evidence.run_id,
                "attempt_id": evidence.attempt_id,
                "outcome": "policy-abort" if response.response_limit_exceeded else "http-response",
                "status": response.status_code,
                "body_bytes_charged": charged_received,
                "body_digest_complete": response.body_digest_complete,
                "duration_ms": elapsed_ms,
                "negotiated_http_version": response.http_version,
            },
        )
        return response


def _origin_fingerprint(origin: str) -> str:
    return "sha256:" + hashlib.sha256(origin.encode("utf-8")).hexdigest()


def origin_fingerprint(origin: str) -> str:
    return _origin_fingerprint(origin)


def estimate_semantic_request_bytes(request: RawRequest, canonical_url: str) -> int:
    """Conservative deterministic upper bound, not wire-level byte telemetry."""
    request_line = (
        len(request.method.encode("utf-8"))
        + 1
        + len(canonical_url.encode("utf-8"))
        + 1
        + len(request.http_version.encode("ascii"))
        + 2
    )
    fields = sum(
        len(name.encode("utf-8")) + 2 + len(value.encode("utf-8")) + 2
        for name, value in request.headers
    )
    return request_line + fields + 2 + len(request.body) + _LIBRARY_REQUEST_OVERHEAD_BYTES
