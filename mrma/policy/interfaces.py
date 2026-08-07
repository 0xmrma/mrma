from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol, runtime_checkable

from mrma.core.raw_request import RawRequest


@runtime_checkable
class AuthorizationPolicy(Protocol):
    digest: str

    def authorize(
        self,
        request: RawRequest,
        *,
        base_url: str,
        attempt_kind: str,
        mutation_family: str | None = None,
        risk_class: str | None = None,
        proxy_url: str | None = None,
    ) -> object: ...

    def authorize_mutation(
        self,
        baseline: RawRequest,
        mutation: RawRequest,
        outgoing_request: RawRequest,
        *,
        base_url: str,
        attempt_kind: str,
        mutation_family: str,
        risk_class: str | None = None,
        proxy_url: str | None = None,
    ) -> object: ...


@runtime_checkable
class BudgetLedgerProtocol(Protocol):
    def reserve(self, proposed: object, *, evidence: object) -> object: ...


@runtime_checkable
class EvidenceSink(Protocol):
    def record(self, event_type: str, data: Mapping[str, object] | None = None) -> object: ...


@runtime_checkable
class TransportAdapter(Protocol):
    def prepare(
        self,
        request: RawRequest,
        *,
        authorization: object,
        arm: str,
        round_index: int | None,
        response_allowance: int,
        redirect_depth: int = 0,
    ) -> object: ...

    def reserve(
        self,
        prepared: object,
        *,
        budgets: object,
        evidence: object,
    ) -> object: ...

    def send(
        self,
        request: RawRequest,
        *,
        authorization: object,
        lease: object,
        evidence: object,
        arm: str,
        round_index: int | None,
        body_storage: str,
    ) -> object: ...

    def send_prepared(
        self,
        prepared: object,
        *,
        authorization: object,
        lease: object,
        evidence: object,
        body_storage: str,
    ) -> object: ...


@runtime_checkable
class ComparisonPolicy(Protocol):
    version: str

    def compare(
        self,
        status_left: int,
        body_left: bytes,
        status_right: int,
        body_right: bytes,
    ) -> object: ...
