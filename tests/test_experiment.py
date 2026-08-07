import hashlib
from dataclasses import replace

import httpx
import pytest

from mrma.core.compare import EquivalenceConfig
from mrma.core.experiment import (
    DNS_ERROR,
    HTTP_RESPONSE,
    POLICY_ABORT,
    TIMEOUT,
    ExperimentConfig,
    classify_transport_error,
    operating_characteristics,
    run_experiment,
    wilson_interval,
)
from mrma.core.http_client import CapturedResponse, RedirectHop
from mrma.core.privacy import EvidenceRedactor
from mrma.core.raw_request import RawRequest
from mrma.core.sender import AttemptRecord, SendOutcome


class MultiHeaders:
    def __init__(self, values: list[tuple[str, str]]):
        self.values = values

    def multi_items(self):
        return list(self.values)


class FakeResponse:
    def __init__(
        self,
        body: bytes,
        headers: dict[str, str] | MultiHeaders | None = None,
        status: int = 200,
    ):
        self.content = body
        self.headers = headers or {"content-type": "text/plain"}
        self.status_code = status


def request(headers: list[tuple[str, str]] | None = None) -> RawRequest:
    return RawRequest("GET", "/", "HTTP/1.1", headers or [("Host", "example.test")], b"")


def has_probe(req: RawRequest) -> bool:
    return any(name.lower() == "x-probe" for name, _ in req.headers)


def mutation_pair() -> tuple[RawRequest, RawRequest]:
    baseline = request()
    return baseline, replace(baseline, headers=baseline.headers + [("X-Probe", "1")])


def test_fixed_sample_brackets_mutation_and_requires_confidence_bounds():
    baseline, mutated = mutation_pair()
    observed_arms: list[str] = []

    def sender(arm: str, req: RawRequest) -> FakeResponse:
        observed_arms.append(arm)
        return FakeResponse(b"mutation" if has_probe(req) else b"control")

    result = run_experiment(
        baseline,
        mutated,
        sender,
        ExperimentConfig(max_rounds=20, seed=19),
    )

    assert result.verdict == "INFLUENCE_DETECTED"
    assert result.rounds == 20
    assert result.mutation_change_interval_95[0] >= 0.8
    assert result.control_change_interval_95[1] <= 0.2
    assert result.stop_reason == "fixed_sample_complete"
    assert observed_arms.count("control_before") == result.rounds
    assert observed_arms.count("control_after") == result.rounds
    assert observed_arms.count("mutation") == result.rounds
    assert set(result.schedule) == {("control_before", "mutation", "control_after")}


def test_six_of_six_changes_remain_inconclusive():
    baseline, mutated = mutation_pair()

    def sender(arm: str, _req: RawRequest) -> FakeResponse:
        return FakeResponse(b"control" if arm.startswith("control") else b"mutation")

    result = run_experiment(
        baseline,
        mutated,
        sender,
        ExperimentConfig(rounds=6, seed=1),
    )

    assert result.verdict == "INCONCLUSIVE"
    assert result.mutation_change_rate == 1.0
    assert result.mutation_change_interval_95[0] < 0.8


def test_no_influence_requires_upper_confidence_bound():
    baseline, mutated = mutation_pair()

    result = run_experiment(
        baseline,
        mutated,
        lambda _arm, _req: FakeResponse(b"same"),
        ExperimentConfig(max_rounds=20, seed=2),
    )

    assert result.verdict == "NO_INFLUENCE_OBSERVED"
    assert result.rounds == 20
    assert result.mutation_change_interval_95[1] <= 0.2


def test_normalized_raw_body_differences_cannot_support_no_influence():
    baseline, mutated = mutation_pair()
    control = b'{"value":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}'
    changed = b'{"value":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}'

    result = run_experiment(
        baseline,
        mutated,
        lambda arm, _req: FakeResponse(control if arm.startswith("control") else changed),
        ExperimentConfig(
            max_rounds=20,
            equivalence=EquivalenceConfig(preset="dynamic"),
        ),
    )

    assert result.verdict == "INCONCLUSIVE"
    assert all(pair.classification == "INDETERMINATE" for pair in result.pairs)


def test_assurance_profile_does_not_compress_independent_dimensions():
    baseline, mutated = mutation_pair()
    result = run_experiment(
        baseline,
        mutated,
        lambda _arm, _req: FakeResponse(b"same"),
        ExperimentConfig(
            rounds=20,
            connection_mode="fresh-observation",
            state_mode="isolated",
            body_storage="full",
            assurance_preset="research",
        ),
    )
    exported = result.to_dict()
    profile = exported["assurance_profile"]

    assert "evidence_grade" not in exported
    assert profile["statistical_decisiveness"] == "strong"
    assert profile["control_stability"] == "strong"
    assert profile["connection_independence"] == "strong"
    assert profile["state_isolation"] == "strong"
    assert profile["body_completeness"] == "complete"
    assert profile["transport_integrity"] == "strong"
    assert profile["response_header_coverage"] == "limited"
    assert [item["code"] for item in exported["limitations"]] == [
        "SELECTIVE_RESPONSE_HEADER_SCOPE",
        "SEMANTIC_HTTP_TRANSPORT",
    ]


@pytest.mark.parametrize(
    ("mode", "expected", "limited"),
    [
        ("reuse", "limited", True),
        ("per-arm", "limited", True),
        ("per-round", "moderate", True),
        ("fresh-observation", "strong", False),
    ],
)
def test_connection_assurance_and_limitations_cover_every_mode(mode, expected, limited):
    baseline, mutated = mutation_pair()
    exported = run_experiment(
        baseline,
        mutated,
        lambda _arm, _req: FakeResponse(b"same"),
        ExperimentConfig(rounds=20, connection_mode=mode),
    ).to_dict()
    codes = {item["code"] for item in exported["limitations"]}

    assert exported["assurance_profile"]["connection_independence"] == expected
    assert ("CONNECTION_REUSE" in codes) is limited


@pytest.mark.parametrize(
    ("mode", "expected", "limited"),
    [
        ("isolated", "strong", False),
        ("per-arm", "moderate", True),
        ("shared-session", "limited", True),
    ],
)
def test_state_assurance_and_limitations_cover_every_mode(mode, expected, limited):
    baseline, mutated = mutation_pair()
    exported = run_experiment(
        baseline,
        mutated,
        lambda _arm, _req: FakeResponse(b"same"),
        ExperimentConfig(rounds=20, state_mode=mode),
    ).to_dict()
    codes = {item["code"] for item in exported["limitations"]}

    assert exported["assurance_profile"]["state_isolation"] == expected
    assert ("RESPONSE_STATE_REUSE" in codes) is limited


def test_ambiguous_cache_control_is_structured_as_a_run_limitation():
    baseline, mutated = mutation_pair()
    result = run_experiment(
        baseline,
        mutated,
        lambda _arm, _req: FakeResponse(
            b"same", {"cache-control": "max-age=0, max-age=3600"}
        ),
        ExperimentConfig(rounds=20),
    )

    assert result.verdict == "NO_INFLUENCE_OBSERVED"
    limitation = next(
        item
        for item in result.to_dict()["limitations"]
        if item["code"] == "AMBIGUOUS_CACHE_CONTROL"
    )
    assert limitation["severity"] == "moderate"
    assert limitation["scope"] == "response_header_equivalence"


@pytest.mark.parametrize(
    ("name", "control_value", "mutation_value"),
    [
        ("allow", "GET", "get"),
        (
            "cache-control",
            "max-age=0, max-age=3600",
            "max-age=3600, max-age=0",
        ),
    ],
)
def test_security_relevant_method_case_and_cache_order_affect_verdicts(
    name, control_value, mutation_value
):
    baseline, mutated = mutation_pair()

    def sender(arm: str, _req: RawRequest) -> FakeResponse:
        value = mutation_value if arm == "mutation" else control_value
        return FakeResponse(b"same", {name: value})

    result = run_experiment(baseline, mutated, sender, ExperimentConfig(rounds=20))

    assert result.verdict == "INFLUENCE_DETECTED"
    assert result.header_shift_counts == {name: 20}


def test_header_only_influence_preserves_duplicate_values_without_exporting_them():
    baseline, mutated = mutation_pair()

    def sender(arm: str, _req: RawRequest) -> FakeResponse:
        suffix = "mutation-secret" if arm == "mutation" else "control-secret"
        return FakeResponse(
            b"same",
            MultiHeaders(
                [
                    ("content-type", "text/plain"),
                    ("location", "/shared"),
                    ("location", f"/{suffix}"),
                ]
            ),
        )

    result = run_experiment(
        baseline,
        mutated,
        sender,
        ExperimentConfig(max_rounds=20, seed=3),
    )
    exported = result.to_dict()

    assert result.verdict == "INFLUENCE_DETECTED"
    assert result.header_shift_counts == {"location": result.rounds}
    assert "mutation-secret" not in str(exported)
    header_values = exported["observations"][0]["evidence_header_fingerprints"]["location"]
    assert len(header_values) == 2


def test_semantically_equivalent_vary_header_order_does_not_create_a_signal():
    baseline, mutated = mutation_pair()

    def sender(arm: str, _req: RawRequest) -> FakeResponse:
        vary = (
            MultiHeaders([("vary", "Origin"), ("vary", "Accept-Encoding")])
            if arm == "mutation"
            else MultiHeaders([("vary", "Accept-Encoding, Origin")])
        )
        return FakeResponse(b"same", vary)

    result = run_experiment(
        baseline,
        mutated,
        sender,
        ExperimentConfig(rounds=20),
    )

    assert result.verdict == "NO_INFLUENCE_OBSERVED"
    assert result.header_shift_counts == {}


def test_redirect_trace_is_decision_bearing_when_final_responses_match():
    baseline, mutated = mutation_pair()
    body = b"same final page"
    digest = hashlib.sha256(body).hexdigest()

    def response(arm: str) -> CapturedResponse:
        relay = "https://relay.test" if arm == "mutation" else "https://login.test"
        return CapturedResponse(
            status_code=200,
            headers=(("content-type", "text/plain"),),
            content=body,
            body_length=len(body),
            body_sha256=digest,
            body_digest_complete=True,
            body_retained_complete=True,
            response_limit_exceeded=False,
            redirect_chain=(
                RedirectHop(
                    status=302,
                    method="GET",
                    origin="https://entry.test",
                    target_origin=relay,
                    location=f"{relay}/next",
                    cross_origin=True,
                    method_changed=False,
                    credential_forwarding="stripped",
                    resolved_target=f"{relay}/next",
                ),
            ),
            final_origin="https://login.test",
            http_version="HTTP/2",
        )

    result = run_experiment(
        baseline,
        mutated,
        lambda arm, _req: response(arm),
        ExperimentConfig(rounds=20),
    )
    exported = result.to_dict()

    assert result.verdict == "INFLUENCE_DETECTED"
    assert result.redirect_shift_rounds == result.rounds
    assert set(result.pairs[0].redirect_diffs) == {
        "resolved-target-sequence",
        "target-origin-sequence",
    }
    assert exported["effect"]["redirect_shift_rounds"] == 20
    assert exported["observations"][1]["redirect_chain"][0][
        "raw_location_fingerprint"
    ].startswith("hmac-sha256:")


def test_raw_redirect_formatting_is_contextual_when_resolved_targets_match():
    baseline, mutated = mutation_pair()
    body = b"same"
    digest = hashlib.sha256(body).hexdigest()

    def response(arm: str) -> CapturedResponse:
        raw_location = (
            "https://EXAMPLE.test:443/a/../login" if arm == "mutation" else "/login"
        )
        return CapturedResponse(
            status_code=200,
            headers=(("content-type", "text/plain"),),
            content=body,
            body_length=len(body),
            body_sha256=digest,
            body_digest_complete=True,
            body_retained_complete=True,
            response_limit_exceeded=False,
            redirect_chain=(
                RedirectHop(
                    status=302,
                    method="GET",
                    origin="https://example.test",
                    target_origin="https://example.test",
                    location=raw_location,
                    cross_origin=False,
                    method_changed=False,
                    credential_forwarding="none",
                    resolved_target="https://example.test/login",
                ),
            ),
            final_origin="https://example.test",
            http_version="HTTP/2",
            final_url="https://example.test/login",
        )

    result = run_experiment(
        baseline,
        mutated,
        lambda arm, _req: response(arm),
        ExperimentConfig(rounds=20),
    )

    assert result.verdict == "NO_INFLUENCE_OBSERVED"
    assert result.redirect_shift_rounds == 0
    assert all(pair.redirect_diffs == () for pair in result.pairs)


def test_location_response_header_uses_resolved_uri_semantics():
    baseline, mutated = mutation_pair()
    body = b"same"
    digest = hashlib.sha256(body).hexdigest()

    def response(arm: str) -> CapturedResponse:
        location = "https://EXAMPLE.test:443/login" if arm == "mutation" else "/login"
        return CapturedResponse(
            status_code=302,
            headers=(("content-type", "text/plain"), ("location", location)),
            content=body,
            body_length=len(body),
            body_sha256=digest,
            body_digest_complete=True,
            body_retained_complete=True,
            response_limit_exceeded=False,
            redirect_chain=(),
            final_origin="https://example.test",
            final_url="https://example.test/start",
        )

    result = run_experiment(
        baseline,
        mutated,
        lambda arm, _req: response(arm),
        ExperimentConfig(rounds=20),
    )

    assert result.verdict == "NO_INFLUENCE_OBSERVED"
    assert result.header_shift_counts == {}


def test_mutation_only_intermediate_retries_are_decision_bearing():
    baseline, mutated = mutation_pair()

    def outcome(statuses: list[int]) -> SendOutcome:
        responses = [FakeResponse(b"same", status=status) for status in statuses]
        trace = tuple(
            AttemptRecord(
                attempt=index,
                response=response,
                error=None,
                elapsed_ms=10.0,
                retry_reason="configured-status" if index < len(responses) else None,
                backoff_ms=400.0 if index < len(responses) else None,
            )
            for index, response in enumerate(responses, start=1)
        )
        return SendOutcome(responses[-1], None, len(responses), trace)

    result = run_experiment(
        baseline,
        mutated,
        lambda arm, _req: outcome([503, 503, 200] if arm == "mutation" else [200]),
        ExperimentConfig(rounds=20),
    )

    assert result.verdict == "INFLUENCE_DETECTED"
    assert result.retry_shift_rounds == result.rounds
    assert "attempt-count" in result.pairs[0].attempt_diffs
    mutation = next(item for item in result.observations if item.arm == "mutation")
    assert [item.status for item in mutation.attempt_trace] == [503, 503, 200]


def test_stable_retry_error_subtype_is_decision_bearing():
    baseline, mutated = mutation_pair()

    def outcome(error: Exception) -> SendOutcome:
        response = FakeResponse(b"same")
        trace = (
            AttemptRecord(
                attempt=1,
                response=None,
                error=error,
                elapsed_ms=10.0,
                retry_reason="transport-error",
                backoff_ms=100.0,
            ),
            AttemptRecord(
                attempt=2,
                response=response,
                error=None,
                elapsed_ms=10.0,
                retry_reason=None,
                backoff_ms=None,
            ),
        )
        return SendOutcome(response, None, 2, trace)

    result = run_experiment(
        baseline,
        mutated,
        lambda arm, _req: outcome(
            httpx.ConnectTimeout("connect")
            if arm == "mutation"
            else httpx.ReadTimeout("read")
        ),
        ExperimentConfig(rounds=20),
    )

    assert result.verdict == "INFLUENCE_DETECTED"
    assert "error-type-sequence" in result.pairs[0].attempt_diffs
    assert result.outcome_counts[HTTP_RESPONSE] == 60


def test_retry_timing_is_quantitative_context_not_a_one_shot_binary_signal():
    baseline, mutated = mutation_pair()

    def outcome(arm: str) -> SendOutcome:
        response = FakeResponse(b"same")
        trace = (
            AttemptRecord(
                attempt=1,
                response=response,
                error=None,
                elapsed_ms=100.0 if arm == "mutation" else 10.0,
                retry_reason=None,
                backoff_ms=None,
            ),
        )
        return SendOutcome(response, None, 1, trace)

    result = run_experiment(
        baseline,
        mutated,
        lambda arm, _req: outcome(arm),
        ExperimentConfig(rounds=20),
    )
    timing = result.to_dict()["effect"]["retry_timing"]["attempt_elapsed"]

    assert result.verdict == "NO_INFLUENCE_OBSERVED"
    assert result.retry_shift_rounds == 0
    assert timing["samples"] == 20
    assert timing["median_delta"]["direction"] == "mutation-higher"
    assert timing["direction_consistency"] == 1.0
    assert timing["decision_role"] == "contextual"


def test_preset_header_ignores_are_effective_in_the_experiment():
    baseline, mutated = mutation_pair()
    sequence = 0

    def sender(_arm: str, _req: RawRequest) -> FakeResponse:
        nonlocal sequence
        sequence += 1
        return FakeResponse(b"same", {"x-vercel-id": f"secret-{sequence}"})

    result = run_experiment(
        baseline,
        mutated,
        sender,
        ExperimentConfig(
            max_rounds=20,
            seed=4,
            equivalence=EquivalenceConfig(preset="nextjs"),
        ),
    )

    assert result.verdict == "NO_INFLUENCE_OBSERVED"
    assert "x-vercel-id" in result.effective_policy.ignore_headers
    assert result.header_shift_counts == {}
    exported = result.to_dict()
    assert exported["assurance_profile"]["normalization_risk"] == "elevated"
    assert "ELEVATED_NORMALIZATION" in {
        item["code"] for item in exported["limitations"]
    }


def test_experiment_rejects_unstable_controls_early():
    baseline, mutated = mutation_pair()
    control_count = 0

    def sender(arm: str, _req: RawRequest) -> FakeResponse:
        nonlocal control_count
        if arm == "mutation":
            return FakeResponse(b"mutation")
        control_count += 1
        return FakeResponse(f"control-{control_count}".encode())

    result = run_experiment(
        baseline,
        mutated,
        sender,
        ExperimentConfig(
            max_rounds=20,
            seed=5,
            equivalence=EquivalenceConfig(min_similarity=0.999, max_len_delta_ratio=0.0),
        ),
    )

    assert result.verdict == "INCONCLUSIVE"
    assert result.stop_reason == "control_instability"
    assert result.control_change_interval_95[0] > 0.2
    design = result.to_dict()["design"]
    assert design["planned_rounds"] == 20
    assert design["completed_rounds"] == result.rounds
    assert design["operating_characteristics"]["rounds"] == 20


def test_local_control_drift_cannot_be_misattributed_to_mutation():
    baseline, mutated = mutation_pair()

    def sender(arm: str, _req: RawRequest) -> FakeResponse:
        if arm == "control_before":
            return FakeResponse(b"before")
        return FakeResponse(b"after")

    result = run_experiment(
        baseline,
        mutated,
        sender,
        ExperimentConfig(max_rounds=20, seed=50),
    )

    assert result.verdict == "INCONCLUSIVE"
    assert result.mutation_changes == 0
    assert result.mutation_indeterminate == result.rounds
    assert result.stop_reason == "control_instability"


def test_repeated_mutation_timeouts_can_be_signal_but_control_timeout_invalidates_run():
    baseline, mutated = mutation_pair()

    def mutation_timeout(arm: str, _req: RawRequest):
        if arm == "mutation":
            return SendOutcome(None, httpx.ReadTimeout("timed out"), 3)
        return SendOutcome(FakeResponse(b"control"), None, 1)

    mutation_result = run_experiment(
        baseline,
        mutated,
        mutation_timeout,
        ExperimentConfig(max_rounds=20, seed=6),
    )
    assert mutation_result.verdict == "INFLUENCE_DETECTED"
    assert mutation_result.to_dict()["assurance_profile"]["transport_reproducibility"] == (
        "moderate"
    )
    assert mutation_result.outcome_counts[TIMEOUT] == mutation_result.rounds
    assert all(item.attempts == 3 for item in mutation_result.observations if item.arm == "mutation")

    def control_timeout(arm: str, _req: RawRequest):
        if arm.startswith("control"):
            return SendOutcome(None, httpx.ReadTimeout("timed out"), 1)
        return FakeResponse(b"mutation")

    control_result = run_experiment(
        baseline,
        mutated,
        control_timeout,
        ExperimentConfig(max_rounds=20, seed=7),
    )
    assert control_result.verdict == "INCONCLUSIVE"
    assert control_result.stop_reason == "control_failure"


def test_response_policy_abort_is_typed_evidence_and_incomplete_bodies_stay_indeterminate():
    baseline, mutated = mutation_pair()

    def captured(digest: str, *, exceeded: bool = False) -> CapturedResponse:
        return CapturedResponse(
            status_code=200,
            headers=(("content-type", "text/plain"),),
            content=b"sample",
            body_length=1025 if exceeded else 100,
            body_sha256=digest,
            body_digest_complete=not exceeded,
            body_retained_complete=False,
            response_limit_exceeded=exceeded,
            redirect_chain=(),
            final_origin="https://example.test",
        )

    abort_result = run_experiment(
        baseline,
        mutated,
        lambda arm, _req: captured("mutation", exceeded=True)
        if arm == "mutation"
        else FakeResponse(b"control"),
        ExperimentConfig(max_rounds=20, seed=11),
    )
    assert abort_result.verdict == "INFLUENCE_DETECTED"
    assert abort_result.outcome_counts[POLICY_ABORT] == abort_result.rounds

    incomplete_result = run_experiment(
        baseline,
        mutated,
        lambda arm, _req: captured("mutation" if arm == "mutation" else "control"),
        ExperimentConfig(max_rounds=20, seed=12),
    )
    assert incomplete_result.verdict == "INCONCLUSIVE"
    assert incomplete_result.mutation_indeterminate == incomplete_result.rounds


def test_binary_and_encoded_bodies_do_not_use_text_similarity():
    baseline, mutated = mutation_pair()

    def binary_sender(arm: str, _req: RawRequest) -> FakeResponse:
        body = b"\x00mutation" if arm == "mutation" else b"\x00control"
        return FakeResponse(body, {"content-type": "application/octet-stream"})

    binary_result = run_experiment(
        baseline,
        mutated,
        binary_sender,
        ExperimentConfig(max_rounds=20, seed=13),
    )
    assert binary_result.verdict == "INCONCLUSIVE"
    assert binary_result.mutation_indeterminate == binary_result.rounds
    assert {pair.comparator for pair in binary_result.pairs} == {"bracketed:bounded-incomplete/bounded-incomplete"}

    def encoded_sender(arm: str, _req: RawRequest) -> FakeResponse:
        body = b"encoded-mutation" if arm == "mutation" else b"encoded-control"
        return FakeResponse(
            body,
            {"content-type": "text/plain", "content-encoding": "gzip"},
        )

    encoded_result = run_experiment(
        baseline,
        mutated,
        encoded_sender,
        ExperimentConfig(max_rounds=20, seed=14),
    )
    assert encoded_result.verdict == "INCONCLUSIVE"
    assert encoded_result.mutation_indeterminate == encoded_result.rounds


def test_missing_content_type_defaults_to_digest_only_evidence():
    baseline, mutated = mutation_pair()

    def changed_sender(arm: str, _req: RawRequest) -> FakeResponse:
        body = b"mutation" if arm == "mutation" else b"control"
        return FakeResponse(body, MultiHeaders([]))

    changed = run_experiment(
        baseline,
        mutated,
        changed_sender,
        ExperimentConfig(max_rounds=20, seed=15),
    )
    unchanged = run_experiment(
        baseline,
        mutated,
        lambda _arm, _req: FakeResponse(b"same", MultiHeaders([])),
        ExperimentConfig(max_rounds=20, seed=16),
    )

    assert changed.verdict == "INCONCLUSIVE"
    assert {pair.comparator for pair in changed.pairs} == {
        "bracketed:bounded-incomplete/bounded-incomplete"
    }
    assert all(not item.body_comparator_eligible for item in changed.observations)
    assert unchanged.verdict == "NO_INFLUENCE_OBSERVED"
    assert unchanged.to_dict()["design"]["missing_content_type_policy"] == "digest-only"


def test_missing_content_type_text_assumption_is_explicit_and_limited():
    baseline, mutated = mutation_pair()

    result = run_experiment(
        baseline,
        mutated,
        lambda arm, _req: FakeResponse(
            b"mutation" if arm == "mutation" else b"control", MultiHeaders([])
        ),
        ExperimentConfig(
            max_rounds=20,
            seed=17,
            assume_text_without_content_type=True,
        ),
    )
    exported = result.to_dict()

    assert result.verdict == "INFLUENCE_DETECTED"
    assert exported["design"]["missing_content_type_policy"] == "assume-text"
    assert "UNDECLARED_CONTENT_TYPE_TEXT_ASSUMPTION" in {
        item["code"] for item in exported["limitations"]
    }


def test_ambiguous_content_type_is_not_used_as_text_evidence():
    baseline, mutated = mutation_pair()

    result = run_experiment(
        baseline,
        mutated,
        lambda arm, _req: FakeResponse(
            b"mutation" if arm == "mutation" else b"control",
            MultiHeaders(
                [("content-type", "text/plain"), ("content-type", "application/json")]
            ),
        ),
        ExperimentConfig(max_rounds=20, seed=18),
    )

    assert result.verdict == "INCONCLUSIVE"
    assert all(not item.body_comparator_eligible for item in result.observations)
    assert "AMBIGUOUS_CONTENT_TYPE" in {
        item["code"] for item in result.to_dict()["limitations"]
    }


@pytest.mark.parametrize(
    ("content_type", "reason"),
    [
        ("text/plain; charset=utf 8", "invalid-parameter-value"),
        ("text/plain; charset", "missing-parameter-value"),
        ("text/plain; =utf-8", "invalid-parameter-name"),
        (
            "text/plain; charset=utf-8; charset=us-ascii",
            "conflicting-duplicate-parameter",
        ),
    ],
)
def test_invalid_content_type_parameters_are_digest_only_with_precise_reasons(
    content_type,
    reason,
):
    baseline, mutated = mutation_pair()

    result = run_experiment(
        baseline,
        mutated,
        lambda arm, _req: FakeResponse(
            b"mutation" if arm == "mutation" else b"control",
            {"content-type": content_type},
        ),
        ExperimentConfig(max_rounds=20, seed=22),
    )
    exported = result.to_dict()
    limitation = next(
        item for item in exported["limitations"] if item["code"] == "AMBIGUOUS_CONTENT_TYPE"
    )

    assert result.verdict == "INCONCLUSIVE"
    assert all(not item.body_comparator_eligible for item in result.observations)
    assert all(reason in item.body_comparator_reasons for item in result.observations)
    assert reason in limitation["message"]


def test_declared_charset_must_decode_every_retained_body_strictly():
    baseline, mutated = mutation_pair()

    result = run_experiment(
        baseline,
        mutated,
        lambda arm, _req: FakeResponse(
            b"\xffmutation" if arm == "mutation" else b"\xffcontrol",
            {"content-type": "text/plain; charset=us-ascii"},
        ),
        ExperimentConfig(max_rounds=20, seed=23),
    )
    exported = result.to_dict()

    assert result.verdict == "INCONCLUSIVE"
    assert all(
        item.body_comparator_reasons == ("invalid-body-encoding",)
        for item in result.observations
    )
    assert "INVALID_DECLARED_BODY_ENCODING" in {
        item["code"] for item in exported["limitations"]
    }


@pytest.mark.parametrize(
    ("content_type", "body"),
    [
        ("text/plain; charset=utf-8", "caf\u00e9".encode()),
        ("text/plain; charset=us-ascii", b"plain-ascii"),
    ],
)
def test_supported_declared_charsets_enable_strict_text_comparison(content_type, body):
    baseline, mutated = mutation_pair()

    result = run_experiment(
        baseline,
        mutated,
        lambda arm, _req: FakeResponse(
            body + (b"-mutation" if arm == "mutation" else b"-control"),
            {"content-type": content_type},
        ),
        ExperimentConfig(max_rounds=20, seed=24),
    )

    assert result.verdict == "INFLUENCE_DETECTED"
    assert all(item.body_comparator_eligible for item in result.observations)
    assert all(item.body_comparator_reasons == () for item in result.observations)


def test_exact_custom_response_header_can_be_made_decision_bearing():
    baseline, mutated = mutation_pair()

    def sender(arm: str, _req: RawRequest) -> FakeResponse:
        tenant = "mutation" if arm == "mutation" else "control"
        return FakeResponse(
            b"same",
            {"content-type": "text/plain", "x-tenant-route": tenant},
        )

    default_result = run_experiment(
        baseline,
        mutated,
        sender,
        ExperimentConfig(max_rounds=20, seed=21),
    )
    explicit_result = run_experiment(
        baseline,
        mutated,
        sender,
        ExperimentConfig(
            max_rounds=20,
            seed=21,
            response_header_scope="explicit",
            include_response_headers=("X-Tenant-Route",),
        ),
    )
    design = explicit_result.to_dict()["design"]["response_header_policy"]

    assert default_result.verdict == "NO_INFLUENCE_OBSERVED"
    assert explicit_result.verdict == "INFLUENCE_DETECTED"
    assert design["scope"] == "explicit"
    assert "x-tenant-route" in design["decision_headers"]
    assert design["omitted_headers_possible"] is True


def test_transport_assurance_records_environment_and_disabled_tls_limitations():
    baseline, mutated = mutation_pair()
    exported = run_experiment(
        baseline,
        mutated,
        lambda _arm, _req: FakeResponse(b"same"),
        ExperimentConfig(
            rounds=20,
            trust_environment=True,
            tls_verification="disabled",
            proxy_mode="environment",
        ),
    ).to_dict()
    codes = {item["code"] for item in exported["limitations"]}

    assert exported["assurance_profile"]["transport_integrity"] == "limited"
    assert exported["assurance_profile"]["transport_reproducibility"] == "moderate"
    assert "TLS_VERIFICATION_DISABLED" in codes
    assert "ENVIRONMENT_TRANSPORT_CONFIGURATION" in codes


def test_status_only_change_can_be_decisive_or_allowed():
    baseline, mutated = mutation_pair()

    def sender(arm: str, _req: RawRequest) -> FakeResponse:
        return FakeResponse(b"same", status=403 if arm == "mutation" else 200)

    decisive = run_experiment(
        baseline,
        mutated,
        sender,
        ExperimentConfig(max_rounds=20, seed=8),
    )
    allowed = run_experiment(
        baseline,
        mutated,
        sender,
        ExperimentConfig(
            max_rounds=20,
            seed=8,
            equivalence=EquivalenceConfig(require_same_status=False),
        ),
    )

    assert decisive.verdict == "INFLUENCE_DETECTED"
    assert allowed.verdict == "NO_INFLUENCE_OBSERVED"
    assert allowed.status_shift_rounds == allowed.rounds


def test_schedule_is_reproducible_and_requires_even_rounds():
    baseline, mutated = mutation_pair()

    def sender(arm: str, _req: RawRequest) -> FakeResponse:
        return FakeResponse(b"control" if arm.startswith("control") else b"mutation")

    config = ExperimentConfig(rounds=6, seed=99, schedule_mode="balanced")
    first = run_experiment(baseline, mutated, sender, config)
    second = run_experiment(baseline, mutated, sender, config)

    assert first.schedule == second.schedule
    with pytest.raises(ValueError, match="require even"):
        run_experiment(
            baseline,
            mutated,
            sender,
            ExperimentConfig(rounds=7, schedule_mode="balanced"),
        )


def test_observation_export_records_http_outcome_and_hides_raw_body_hash():
    baseline, mutated = mutation_pair()
    result = run_experiment(
        baseline,
        mutated,
        lambda _arm, _req: FakeResponse(b"same"),
        ExperimentConfig(rounds=6, seed=10),
    )
    exported = result.to_dict()["observations"][0]

    assert exported["outcome"] == HTTP_RESPONSE
    assert exported["body_fingerprint"].startswith("hmac-sha256:")
    assert "sha256" not in exported


def test_strict_observation_export_masks_all_response_header_names():
    baseline, mutated = mutation_pair()
    result = run_experiment(
        baseline,
        mutated,
        lambda _arm, _req: FakeResponse(
            b"same",
            MultiHeaders(
                [
                    ("content-type", "text/plain"),
                    ("server", "private-gateway"),
                ]
            ),
        ),
        ExperimentConfig(
            rounds=6,
            redactor=EvidenceRedactor(policy="strict", _key=b"a" * 32),
        ),
    )

    exported = result.to_dict()["observations"][0]
    names = exported["evidence_header_fingerprints"]
    assert names
    assert all(name.startswith("hmac-sha256:") for name in names)
    assert "content-type" not in str(names)
    assert "private-gateway" not in str(names)


def test_experiment_requires_six_rounds():
    with pytest.raises(ValueError, match="6-50 rounds"):
        run_experiment(
            request(),
            request(),
            lambda _arm, _req: FakeResponse(b"same"),
            ExperimentConfig(rounds=4),
        )


def test_wilson_interval_contains_observed_rate():
    low, high = wilson_interval(4, 5)
    assert 0.0 < low < 0.8 < high < 1.0


def test_default_operating_characteristics_are_explicit():
    characteristics = operating_characteristics(20, 0.8, 0.2, 0.2, 20)

    assert characteristics == {
        "rounds": 20,
        "control_comparisons": 20,
        "confidence": 0.95,
        "positive_min_changed": 20,
        "negative_max_changed": 0,
        "control_max_changed": 0,
    }


def test_nested_dns_error_is_classified_without_message_leakage():
    try:
        try:
            raise OSError("wrapper") from __import__("socket").gaierror("private host")
        except OSError as exc:
            raise httpx.ConnectError("connect failed") from exc
    except httpx.ConnectError as error:
        assert classify_transport_error(error) == DNS_ERROR
