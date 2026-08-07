from __future__ import annotations

import hashlib
import hmac
import json
import math
import secrets
import time
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from types import TracebackType

import httpx

from mrma.core.http_client import (
    _GUARDED_TRANSPORT_CAPABILITY,
    CapturedResponse,
    SemanticHttpTransport,
    SendOptions,
)
from mrma.core.raw_request import RawRequest
from mrma.evidence.journal import EvidenceContext, EvidenceJournal
from mrma.policy.authorization import (
    AuthorizationError,
    AuthorizedMutationContext,
    AuthorizedRequestContext,
    canonical_host_authority,
    request_fingerprint,
)
from mrma.policy.budget import AttemptCost, BudgetLease, BudgetLedger

TRANSPORT_ADAPTER_VERSION = "semantic-httpx/1.3"
SEMANTIC_REQUEST_ESTIMATE_VERSION = "declared-request-preflight/2.0"
_LIBRARY_REQUEST_OVERHEAD_BYTES = 2048


class TransportPolicyError(RuntimeError):
    mrma_fatal_policy_error = True

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


@dataclass(frozen=True, slots=True)
class _PreparedSemanticRequest:
    _request: httpx.Request = field(repr=False, compare=False)
    _capability_id: str = field(repr=False)
    _observation_token: str = field(repr=False)
    prepared_request_digest: str = field(repr=False)
    capability_seal: str = field(repr=False)
    authorization_request_fingerprint: str
    target_fingerprint: str
    origin_fingerprint: str
    mutation_delta_digest: str | None
    arm: str
    round_index: int | None
    attempt_kind: str
    effective_risk: str
    redirect_depth: int
    transport_timeout_ms: int
    budget_policy_digest: str
    request_body_bytes: int
    represented_bytes: int
    response_allowance: int
    allow_cookie_field: bool

    def budget_cost(self) -> AttemptCost:
        return AttemptCost(
            kind=self.attempt_kind,
            origin_fingerprint=self.origin_fingerprint,
            target_fingerprint=self.target_fingerprint,
            request_body_bytes=self.request_body_bytes,
            request_bytes=self.represented_bytes,
            response_bytes=self.response_allowance,
            timeout_ms=self.transport_timeout_ms,
            redirect_depth=self.redirect_depth,
            mutation_risk_level=self.effective_risk,
        )


PreparedSemanticRequest = _PreparedSemanticRequest


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
        self._capability_key = secrets.token_bytes(32)
        self._active_observation_token: str | None = None
        self._consumed_capabilities: set[str] = set()
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

    def clear_observation_cookies(self) -> None:
        if not self._entered:
            raise TransportPolicyError("TRANSPORT_NOT_ENTERED", "adapter context is not active")
        self._transport.clear_observation_cookies()

    @contextmanager
    def observation_session(
        self,
        *,
        arm: str,
        round_index: int | None,
    ) -> Iterator[None]:
        if not self._entered:
            raise TransportPolicyError("TRANSPORT_NOT_ENTERED", "adapter context is not active")
        if self._active_observation_token is not None:
            raise TransportPolicyError(
                "OBSERVATION_SESSION_NESTED",
                "adapter observation sessions cannot be nested",
            )
        normalized_arm = arm if arm in {"control", "mutation"} else "control"
        self._active_observation_token = secrets.token_hex(16)
        try:
            with self._transport.observation_session(
                arm=normalized_arm,
                round_index=round_index,
            ):
                yield
        finally:
            self._active_observation_token = None

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

    def approval_policy(self) -> dict[str, object]:
        payload = self.public_policy()
        payload.update(
            {
                "request_byte_accounting": "prepared-httpx-representation/1.0",
                "proxy_endpoint_digest": (
                    "sha256:" + hashlib.sha256(self.options.proxy.encode("utf-8")).hexdigest()
                    if self.options.proxy is not None
                    else None
                ),
                "custom_tls_context": self.options.ssl_context is not None,
            }
        )
        return payload

    def prepare(
        self,
        request: RawRequest,
        *,
        authorization: AuthorizedRequestContext,
        arm: str,
        round_index: int | None,
        response_allowance: int,
        redirect_depth: int = 0,
        allow_cookie_field: bool = True,
    ) -> _PreparedSemanticRequest:
        if not self._entered:
            raise TransportPolicyError("TRANSPORT_NOT_ENTERED", "adapter context is not active")
        normalized_arm = arm if arm in {"control", "mutation"} else "control"
        if normalized_arm == "mutation" and not isinstance(
            authorization, AuthorizedMutationContext
        ):
            raise TransportPolicyError(
                "MUTATION_AUTHORIZATION_REQUIRED",
                "mutation transport requires a context bound to the validated mutation delta",
            )
        if not authorization.decision.accepted:
            raise TransportPolicyError("AUTHORIZATION_REQUIRED", "authorization was not accepted")
        for name, value in {"redirect_depth": redirect_depth}.items():
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise TransportPolicyError(
                    "PREPARED_ATTEMPT_INVALID",
                    f"{name} must be a non-negative integer",
                )
        if (
            not isinstance(response_allowance, int)
            or isinstance(response_allowance, bool)
            or response_allowance < 1
        ):
            raise TransportPolicyError(
                "PREPARED_ATTEMPT_INVALID",
                "response_allowance must be a positive integer",
            )
        attempt_kind = authorization.decision.attempt_kind
        if (attempt_kind == "redirect" and redirect_depth < 1) or (
            redirect_depth > 0 and attempt_kind not in {"redirect", "retry"}
        ):
            raise TransportPolicyError(
                "PREPARED_REDIRECT_DEPTH_INVALID",
                "redirect depth is inconsistent with the authorized attempt kind",
            )
        observation_token = self._active_observation_token
        if observation_token is None:
            raise TransportPolicyError(
                "OBSERVATION_SESSION_REQUIRED",
                "request preparation requires an active adapter observation session",
            )
        observed_fingerprint = request_fingerprint(request, authorization.canonical_url)
        if observed_fingerprint != authorization.request_fingerprint:
            raise TransportPolicyError(
                "AUTHORIZATION_REQUEST_MISMATCH",
                "request changed after authorization",
            )
        rebound = replace(request, path=authorization.canonical_url, target_form="absolute")
        prepared = self._transport.prepare(
            rebound,
            authorization.canonical_url,
            normalized_arm,
            round_index=round_index,
            allow_cookie_field=allow_cookie_field,
        )
        try:
            prepared_host, represented_bytes = _prepared_request_state(prepared)
            _enforce_prepared_authorization(prepared, prepared_host, authorization)
            prepared_request_digest = _prepared_request_digest(
                prepared,
                effective_host=prepared_host,
                represented_bytes=represented_bytes,
            )
        except TransportPolicyError:
            raise
        except (TypeError, ValueError, UnicodeError, httpx.HTTPError) as exc:
            raise TransportPolicyError(
                "PREPARED_REQUEST_INVALID",
                "HTTPX produced a request that cannot be sealed for exact semantic replay",
            ) from exc
        mutation_digest = (
            authorization.mutation.delta_digest
            if isinstance(authorization, AuthorizedMutationContext)
            else None
        )
        capability_id = secrets.token_hex(16)
        transport_timeout_ms = int(self.options.timeout_s * 1000)
        capability_values = {
            "capability_id": capability_id,
            "observation_token": observation_token,
            "prepared_request_digest": prepared_request_digest,
            "authorization_request_fingerprint": authorization.request_fingerprint,
            "target_fingerprint": authorization.decision.target_fingerprint,
            "origin_fingerprint": _origin_fingerprint(authorization.decision.canonical_origin),
            "mutation_delta_digest": mutation_digest,
            "arm": normalized_arm,
            "round_index": round_index,
            "attempt_kind": attempt_kind,
            "effective_risk": authorization.decision.effective_risk,
            "redirect_depth": redirect_depth,
            "transport_timeout_ms": transport_timeout_ms,
            "budget_policy_digest": authorization.decision.budget_policy_digest,
            "request_body_bytes": len(request.body),
            "represented_bytes": represented_bytes,
            "response_allowance": response_allowance,
            "allow_cookie_field": allow_cookie_field,
        }
        return _PreparedSemanticRequest(
            _request=prepared,
            _capability_id=capability_id,
            _observation_token=observation_token,
            prepared_request_digest=prepared_request_digest,
            capability_seal=self._seal_capability(capability_values),
            authorization_request_fingerprint=authorization.request_fingerprint,
            target_fingerprint=authorization.decision.target_fingerprint,
            origin_fingerprint=_origin_fingerprint(authorization.decision.canonical_origin),
            mutation_delta_digest=mutation_digest,
            arm=normalized_arm,
            round_index=round_index,
            attempt_kind=attempt_kind,
            effective_risk=authorization.decision.effective_risk,
            redirect_depth=redirect_depth,
            transport_timeout_ms=transport_timeout_ms,
            budget_policy_digest=authorization.decision.budget_policy_digest,
            request_body_bytes=len(request.body),
            represented_bytes=represented_bytes,
            response_allowance=response_allowance,
            allow_cookie_field=allow_cookie_field,
        )

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
        allow_cookie_field: bool = True,
    ) -> CapturedResponse:
        prepared = self.prepare(
            request,
            authorization=authorization,
            arm=arm,
            round_index=round_index,
            response_allowance=lease.proposed.response_bytes,
            redirect_depth=lease.proposed.redirect_depth,
            allow_cookie_field=allow_cookie_field,
        )
        return self.send_prepared(
            prepared,
            authorization=authorization,
            lease=lease,
            evidence=evidence,
            body_storage=body_storage,
        )

    def reserve(
        self,
        prepared: _PreparedSemanticRequest,
        *,
        budgets: BudgetLedger,
        evidence: EvidenceContext,
    ) -> BudgetLease:
        if budgets.journal is not self.journal:
            raise TransportPolicyError(
                "BUDGET_JOURNAL_MISMATCH",
                "adapter and budget ledger must share one evidence journal",
            )
        self._validate_capability(prepared, evidence=evidence)
        if budgets.policy_digest != prepared.budget_policy_digest:
            raise TransportPolicyError(
                "BUDGET_POLICY_MISMATCH",
                "budget ledger limits differ from the authorization policy",
            )
        return budgets.reserve(prepared.budget_cost(), evidence=evidence)

    def _capability_values(self, prepared: _PreparedSemanticRequest) -> dict[str, object]:
        return {
            "capability_id": prepared._capability_id,
            "observation_token": prepared._observation_token,
            "prepared_request_digest": prepared.prepared_request_digest,
            "authorization_request_fingerprint": prepared.authorization_request_fingerprint,
            "target_fingerprint": prepared.target_fingerprint,
            "origin_fingerprint": prepared.origin_fingerprint,
            "mutation_delta_digest": prepared.mutation_delta_digest,
            "arm": prepared.arm,
            "round_index": prepared.round_index,
            "attempt_kind": prepared.attempt_kind,
            "effective_risk": prepared.effective_risk,
            "redirect_depth": prepared.redirect_depth,
            "transport_timeout_ms": prepared.transport_timeout_ms,
            "budget_policy_digest": prepared.budget_policy_digest,
            "request_body_bytes": prepared.request_body_bytes,
            "represented_bytes": prepared.represented_bytes,
            "response_allowance": prepared.response_allowance,
            "allow_cookie_field": prepared.allow_cookie_field,
        }

    def _validate_capability(
        self,
        prepared: _PreparedSemanticRequest,
        *,
        evidence: EvidenceContext,
    ) -> tuple[httpx.Request, str, int]:
        if not self._entered:
            raise TransportPolicyError("TRANSPORT_NOT_ENTERED", "adapter context is not active")
        if not isinstance(prepared, _PreparedSemanticRequest):
            raise TransportPolicyError(
                "PREPARED_CAPABILITY_INVALID",
                "operation requires a capability issued by this adapter",
            )
        if evidence.run_id != self.journal.run_id:
            raise TransportPolicyError("EVIDENCE_RUN_MISMATCH", "evidence belongs to another run")
        if evidence.role != prepared.attempt_kind:
            raise TransportPolicyError(
                "EVIDENCE_ROLE_MISMATCH",
                "evidence role differs from the authorized attempt kind",
            )
        if evidence.round_index != prepared.round_index:
            raise TransportPolicyError(
                "EVIDENCE_ROUND_MISMATCH",
                "evidence round differs from the prepared attempt round",
            )
        if not hmac.compare_digest(
            self._seal_capability(self._capability_values(prepared)),
            prepared.capability_seal,
        ):
            raise TransportPolicyError(
                "PREPARED_CAPABILITY_INVALID",
                "prepared request capability metadata was altered or issued by another adapter",
            )
        if prepared._observation_token != self._active_observation_token:
            raise TransportPolicyError(
                "PREPARED_OBSERVATION_MISMATCH",
                "prepared request belongs to another observation session",
            )
        if prepared._capability_id in self._consumed_capabilities:
            raise TransportPolicyError(
                "PREPARED_CAPABILITY_CONSUMED",
                "prepared request capability has already been used",
            )
        request = prepared._request
        if not isinstance(request, httpx.Request):
            raise TransportPolicyError(
                "PREPARED_CAPABILITY_INVALID",
                "prepared capability does not contain an HTTPX request",
            )
        try:
            prepared_host, represented_bytes = _prepared_request_state(request)
            request_digest = _prepared_request_digest(
                request,
                effective_host=prepared_host,
                represented_bytes=represented_bytes,
            )
        except (
            TypeError,
            ValueError,
            UnicodeError,
            httpx.HTTPError,
            TransportPolicyError,
        ) as exc:
            raise TransportPolicyError(
                "PREPARED_REQUEST_MUTATED",
                "prepared HTTP request is no longer a valid buffered request",
            ) from exc
        if not hmac.compare_digest(request_digest, prepared.prepared_request_digest):
            raise TransportPolicyError(
                "PREPARED_REQUEST_MUTATED",
                "prepared HTTP request changed after authorization",
            )
        if (
            prepared.request_body_bytes != len(request.content)
            or prepared.represented_bytes != represented_bytes
        ):
            raise TransportPolicyError(
                "PREPARED_REQUEST_MUTATED",
                "prepared HTTP request accounting changed after authorization",
            )
        return request, prepared_host, represented_bytes

    def send_prepared(
        self,
        prepared: _PreparedSemanticRequest,
        *,
        authorization: AuthorizedRequestContext,
        lease: BudgetLease,
        evidence: EvidenceContext,
        body_storage: str,
    ) -> CapturedResponse:
        if not lease.active:
            raise TransportPolicyError("BUDGET_LEASE_REQUIRED", "budget lease is inactive")
        if lease.evidence != evidence:
            raise TransportPolicyError("EVIDENCE_CONTEXT_MISMATCH", "lease belongs to another attempt")
        if not authorization.decision.accepted:
            raise TransportPolicyError("AUTHORIZATION_REQUIRED", "authorization was not accepted")
        request, prepared_host, current_represented_bytes = self._validate_capability(
            prepared,
            evidence=evidence,
        )
        _enforce_prepared_authorization(request, prepared_host, authorization)
        if prepared.authorization_request_fingerprint != authorization.request_fingerprint:
            raise TransportPolicyError(
                "AUTHORIZATION_REQUEST_MISMATCH",
                "prepared request belongs to another authorization context",
            )
        if prepared.target_fingerprint != authorization.decision.target_fingerprint or (
            lease.proposed.target_fingerprint != authorization.decision.target_fingerprint
        ):
            raise TransportPolicyError("LEASE_TARGET_MISMATCH", "lease belongs to another target")
        if prepared.origin_fingerprint != _origin_fingerprint(
            authorization.decision.canonical_origin
        ) or lease.proposed.origin_fingerprint != prepared.origin_fingerprint:
            raise TransportPolicyError("LEASE_ORIGIN_MISMATCH", "lease belongs to another origin")
        if prepared.attempt_kind != authorization.decision.attempt_kind:
            raise TransportPolicyError(
                "PREPARED_ATTEMPT_KIND_MISMATCH",
                "prepared attempt kind differs from authorization",
            )
        if lease.proposed.kind != prepared.attempt_kind:
            raise TransportPolicyError(
                "LEASE_KIND_MISMATCH",
                "lease kind differs from the authorized attempt kind",
            )
        if prepared.effective_risk != authorization.decision.effective_risk:
            raise TransportPolicyError(
                "PREPARED_RISK_MISMATCH",
                "prepared attempt risk differs from authorization",
            )
        if lease.proposed.mutation_risk_level != prepared.effective_risk:
            raise TransportPolicyError(
                "LEASE_RISK_MISMATCH",
                "lease risk differs from the authorized effective risk",
            )
        if lease.proposed.redirect_depth != prepared.redirect_depth:
            raise TransportPolicyError(
                "LEASE_DEPTH_MISMATCH",
                "lease redirect depth differs from the prepared attempt",
            )
        actual_timeout_ms = int(self.options.timeout_s * 1000)
        if prepared.transport_timeout_ms != actual_timeout_ms:
            raise TransportPolicyError(
                "PREPARED_TIMEOUT_MISMATCH",
                "prepared timeout differs from the active transport timeout",
            )
        if lease.proposed.timeout_ms != prepared.transport_timeout_ms:
            raise TransportPolicyError(
                "LEASE_TIMEOUT_MISMATCH",
                "lease timeout differs from the active transport timeout",
            )
        if lease.policy_digest != prepared.budget_policy_digest:
            raise TransportPolicyError(
                "LEASE_BUDGET_POLICY_MISMATCH",
                "lease was issued under limits that differ from authorization",
            )
        expected_arm = (
            "mutation" if isinstance(authorization, AuthorizedMutationContext) else "control"
        )
        if prepared.arm != expected_arm:
            raise TransportPolicyError(
                "PREPARED_ARM_MISMATCH",
                "prepared request arm differs from its authorization capability",
            )
        if len(request.content) > lease.proposed.request_body_bytes:
            raise TransportPolicyError("LEASE_SEND_OVERRUN", "request body exceeds reservation")
        if current_represented_bytes > lease.proposed.request_bytes:
            raise TransportPolicyError(
                "LEASE_SEND_OVERRUN",
                "prepared request representation exceeds reservation",
            )
        if lease.proposed.response_bytes != prepared.response_allowance:
            raise TransportPolicyError(
                "LEASE_RESPONSE_MISMATCH",
                "lease response allowance differs from the prepared attempt",
            )
        if prepared.arm == "mutation":
            if not isinstance(authorization, AuthorizedMutationContext):
                raise TransportPolicyError(
                    "MUTATION_AUTHORIZATION_REQUIRED",
                    "mutation transport requires a validated mutation context",
                )
            if prepared.mutation_delta_digest != authorization.mutation.delta_digest:
                raise TransportPolicyError(
                    "MUTATION_AUTHORIZATION_MISMATCH",
                    "prepared request belongs to another mutation delta",
                )
        self._consumed_capabilities.add(prepared._capability_id)
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
                "state_field_forwarding": (
                    "allowed" if prepared.allow_cookie_field else "suppressed"
                ),
                "request_representation_bytes": current_represented_bytes,
                "mutation_delta_fingerprint": self._mutation_event_fingerprint(
                    prepared.mutation_delta_digest
                ),
            },
        )
        started = time.perf_counter()
        try:
            response = self._transport.capture_prepared(
                request,
                prepared.arm,
                max_response_bytes=lease.response_allowance,
                body_storage=body_storage,
                round_index=prepared.round_index,
            )
        except Exception as exc:
            elapsed_ms = int((time.perf_counter() - started) * 1000)
            lease.commit(
                bytes_sent=current_represented_bytes,
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
        charged_received = min(response.represented_bytes, lease.response_allowance)
        charged_body = max(
            0,
            charged_received - min(response.response_head_bytes, charged_received),
        )
        lease.commit(
            bytes_sent=current_represented_bytes,
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
                "body_bytes_charged": charged_body,
                "response_representation_bytes_observed": response.represented_bytes,
                "response_representation_bytes_charged": charged_received,
                "body_digest_complete": response.body_digest_complete,
                "duration_ms": elapsed_ms,
                "negotiated_http_version": response.http_version,
            },
        )
        return response

    def _seal_capability(self, values: Mapping[str, object]) -> str:
        payload = json.dumps(
            values,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("ascii")
        return "hmac-sha256:" + hmac.new(
            self._capability_key,
            payload,
            hashlib.sha256,
        ).hexdigest()

    def _mutation_event_fingerprint(self, delta_digest: str | None) -> str | None:
        if delta_digest is None:
            return None
        return "hmac-sha256:" + hmac.new(
            self._capability_key,
            b"journal-mutation-delta\0" + delta_digest.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()


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


def represented_request_bytes(request: httpx.Request) -> int:
    """Measure the final HTTPX request representation that will be sent."""
    request_target = request.url.raw_path
    request_line = (
        len(request.method.encode("ascii"))
        + 1
        + len(request_target)
        + 1
        + len(b"HTTP/1.1")
        + 2
    )
    fields = sum(len(name) + 2 + len(value) + 2 for name, value in request.headers.raw)
    return request_line + fields + 2 + len(request.content)


def _prepared_host_authority(request: httpx.Request) -> str:
    try:
        host_values = [
            value.decode("ascii")
            for name, value in request.headers.raw
            if name.lower() == b"host"
        ]
    except UnicodeDecodeError as exc:
        raise TransportPolicyError(
            "PREPARED_HOST_INVALID",
            "the prepared Host field is not ASCII",
        ) from exc
    if len(host_values) != 1:
        raise TransportPolicyError(
            "PREPARED_HOST_INVALID",
            "the prepared request must contain exactly one Host field",
        )
    try:
        return canonical_host_authority(host_values[0], request.url.scheme)
    except (AuthorizationError, ValueError) as exc:
        raise TransportPolicyError(
            "PREPARED_HOST_INVALID",
            "the prepared Host field is malformed",
        ) from exc


def _prepared_request_state(request: httpx.Request) -> tuple[str, int]:
    effective_host = _prepared_host_authority(request)
    represented_bytes = represented_request_bytes(request)
    return effective_host, represented_bytes


def _enforce_prepared_authorization(
    request: httpx.Request,
    effective_host: str,
    authorization: AuthorizedRequestContext,
) -> None:
    if request.method != authorization.decision.method:
        raise TransportPolicyError("PREPARED_METHOD_MISMATCH", "HTTPX changed the method")
    if str(request.url) != authorization.canonical_url:
        raise TransportPolicyError(
            "PREPARED_TARGET_MISMATCH",
            "HTTPX prepared a different target than the authorized canonical URL",
        )
    if effective_host != authorization.effective_host_authority:
        raise TransportPolicyError(
            "PREPARED_HOST_MISMATCH",
            "the prepared Host field differs from the authorized authority",
        )


def _prepared_request_digest(
    request: httpx.Request,
    *,
    effective_host: str,
    represented_bytes: int,
) -> str:
    body = request.content
    stream_length = 0
    stream_digest = hashlib.sha256()
    if not isinstance(request.stream, httpx.ByteStream):
        raise TypeError("prepared request body must remain a buffered HTTPX byte stream")
    for chunk in request.stream:
        if not isinstance(chunk, bytes):
            raise TypeError("prepared request stream yielded a non-byte chunk")
        stream_length += len(chunk)
        stream_digest.update(chunk)
    content_digest = hashlib.sha256(body).hexdigest()
    if stream_length != len(body) or not hmac.compare_digest(
        stream_digest.hexdigest(),
        content_digest,
    ):
        raise ValueError("prepared request content and send stream differ")
    document = {
        "method": request.method,
        "url": str(request.url),
        "headers": [
            [name.hex(), value.hex()]
            for name, value in request.headers.raw
        ],
        "content_length": len(body),
        "content_sha256": content_digest,
        "stream_length": stream_length,
        "stream_sha256": stream_digest.hexdigest(),
        "extensions": _fingerprintable_extension_value(request.extensions),
        "effective_host": effective_host,
        "represented_bytes": represented_bytes,
    }
    payload = json.dumps(
        document,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _fingerprintable_extension_value(value: object, *, depth: int = 0) -> object:
    if depth > 8:
        raise ValueError("prepared request extensions exceed the nesting limit")
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("prepared request extensions contain a non-finite number")
        return {"float_hex": value.hex()}
    if isinstance(value, bytes):
        return {"bytes_hex": value.hex()}
    if isinstance(value, Mapping):
        if len(value) > 64 or any(not isinstance(key, str) for key in value):
            raise ValueError("prepared request extension mappings must have bounded string keys")
        return {
            key: _fingerprintable_extension_value(item, depth=depth + 1)
            for key, item in sorted(value.items())
        }
    if isinstance(value, Sequence):
        if len(value) > 64:
            raise ValueError("prepared request extension sequences exceed the item limit")
        return [
            _fingerprintable_extension_value(item, depth=depth + 1)
            for item in value
        ]
    raise TypeError(
        f"prepared request extension value {type(value).__name__!r} is not fingerprintable"
    )
