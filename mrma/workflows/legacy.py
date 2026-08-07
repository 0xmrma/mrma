from __future__ import annotations

from dataclasses import dataclass

import httpx

from mrma.core.compare import EquivalenceConfig
from mrma.core.experiment import ExperimentConfig
from mrma.core.http_client import CapturedResponse, SendOptions
from mrma.core.privacy import EvidenceRedactor
from mrma.core.raw_request import RawRequest
from mrma.core.sender import SendPolicy, current_attempt_kind
from mrma.engine.oracle import ExperimentOracle
from mrma.engine.plan import ExperimentPlan
from mrma.evidence.journal import EvidenceJournal
from mrma.policy.authorization import ManifestAuthorizationPolicy
from mrma.policy.budget import BudgetError, BudgetLedger
from mrma.policy.comparison import ComparisonPolicy
from mrma.policy.method_risk import classify_method
from mrma.transport.semantic_http import SemanticHttpAdapter


@dataclass(frozen=True)
class GuardedResponse:
    status_code: int
    headers: httpx.Headers
    content: bytes
    http_version: str | None
    final_url: str | None


class LegacyAuthorizedDispatcher:
    """Route legacy exploratory sends through the v0.4 policy kernel."""

    def __init__(
        self,
        *,
        baseline: RawRequest,
        authorization: ManifestAuthorizationPolicy,
        budgets: BudgetLedger,
        evidence: EvidenceJournal,
        redactor: EvidenceRedactor,
    ) -> None:
        self.baseline = baseline
        self.authorization = authorization
        self.budgets = budgets
        self.evidence = evidence
        self.redactor = redactor
        self._adapter: SemanticHttpAdapter | None = None
        self._oracle: ExperimentOracle | None = None
        self._options: SendOptions | None = None
        self._sequence = 0

    def close(self) -> None:
        if self._adapter is not None:
            self._adapter.close()

    def _prepare(self, options: SendOptions) -> ExperimentOracle:
        if options.trust_env:
            raise BudgetError(
                "ENVIRONMENT_TRANSPORT_REJECTED",
                "legacy exploratory workflows require trust_env=false",
            )
        if self._adapter is None:
            self._options = options
            self._adapter = SemanticHttpAdapter(
                options,
                journal=self.evidence,
                state_mode="isolated",
                connection_mode="reuse",
            )
            self._adapter.__enter__()
            self._oracle = ExperimentOracle(
                authorization=self.authorization,
                budgets=self.budgets,
                transport=self._adapter,
                comparison=ComparisonPolicy(EquivalenceConfig()),
                evidence=self.evidence,
            )
        elif options != self._options:
            raise BudgetError(
                "TRANSPORT_CONFIGURATION_CHANGED",
                "one workflow cannot change transport configuration between attempts",
            )
        assert self._oracle is not None
        return self._oracle

    def __call__(self, request: RawRequest, base_url: str, options: SendOptions) -> object:
        oracle = self._prepare(options)
        self._sequence += 1
        risk = classify_method(request.method).risk_class
        config = ExperimentConfig(
            rounds=6,
            state_mode="isolated",
            connection_mode="reuse",
            max_response_bytes=self.budgets.limits.maximum_response_bytes,
            body_storage="full",
            assurance_preset="exploratory",
            redactor=self.redactor,
        )
        plan = ExperimentPlan(
            baseline=self.baseline,
            mutation=request,
            base_url=base_url,
            experiment=config,
            send=SendPolicy(retries=0),
            follow_redirects=options.follow_redirects,
            mutation_family="header",
            mutation_risk_class=risk,
            exploration_role="exploration",
        )
        outcome = oracle.send_observation(
            plan,
            arm="mutation",
            request=request,
            round_index=1,
            sequence=self._sequence,
            initial_role=current_attempt_kind() or "exploratory",
        )
        if not outcome.succeeded or not isinstance(outcome.response, CapturedResponse):
            if outcome.error is not None:
                raise outcome.error
            raise RuntimeError("guarded exploratory send produced no response")
        response = outcome.response
        if response.response_limit_exceeded:
            raise BudgetError(
                "RESPONSE_LIMIT_EXHAUSTED",
                "exploratory response exceeded the authorized body bound",
            )
        self.evidence.record(
            "OBSERVATION_COMPLETED",
            {
                "sequence": self._sequence,
                "role": "exploratory",
                "outcome": "HTTP_RESPONSE",
                "status": response.status_code,
                "body_digest_complete": response.body_digest_complete,
                "body_retained_complete": response.body_retained_complete,
            },
        )
        return GuardedResponse(
            status_code=response.status_code,
            headers=httpx.Headers(response.headers),
            content=response.content,
            http_version=response.http_version,
            final_url=response.final_url,
        )
