from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Mutation:
    identifier: str
    path: str
    original: str
    replacement: str
    tests: tuple[str, ...]


MUTATIONS = (
    Mutation(
        "AUTH-EXPIRY-BOUNDARY",
        "mrma/policy/authorization.py",
        "if current >= self.manifest.expires_at:",
        "if current > self.manifest.expires_at:",
        ("tests/test_authorization.py::test_expiration_boundary_is_exclusive",),
    ),
    Mutation(
        "AUTH-ALL-DNS-ANSWERS",
        "mrma/policy/authorization.py",
        "if any(\n            not any(address in network for network in rule.cidrs)\n            for address in parsed_addresses\n        ):",
        "if all(\n            not any(address in network for network in rule.cidrs)\n            for address in parsed_addresses\n        ):",
        ("tests/test_authorization.py::test_every_a_and_aaaa_answer_must_be_authorized",),
    ),
    Mutation(
        "AUTH-PATH-SEGMENT",
        "mrma/policy/authorization.py",
        'path.startswith(normalized + "/")',
        "path.startswith(normalized)",
        ("tests/test_authorization.py::test_path_scope_is_segment_bounded",),
    ),
    Mutation(
        "AUTH-METHOD-CASE",
        "mrma/policy/authorization.py",
        "method = request.method",
        "method = request.method.upper()",
        ("tests/test_authorization.py::test_authorized_method_tokens_are_case_sensitive",),
    ),
    Mutation(
        "AUTH-DUPLICATE-HOST",
        "mrma/policy/authorization.py",
        "if len(host_fields) > 1:",
        "if len(host_fields) > 2:",
        ("tests/test_authorization.py::test_authorization_v2_binds_host_authority_and_rejects_duplicates",),
    ),
    Mutation(
        "AUTH-HOST-MATCH",
        "mrma/policy/authorization.py",
        'if policy.mode == "match-target" and effective_pair != target_pair:',
        'if policy.mode == "match-target" and effective_pair == target_pair:',
        ("tests/test_authorization.py::test_authorization_v2_binds_host_authority_and_rejects_duplicates",),
    ),
    Mutation(
        "AUTH-QUERY-POLICY",
        "mrma/policy/authorization.py",
        "and _query_allowed(parsed.query, rule.query_policy)",
        "and True",
        ("tests/test_authorization.py::test_authorization_v2_enforces_query_and_header_mutation_scope",),
    ),
    Mutation(
        "AUTH-REPETITION-BOUNDARY",
        "mrma/policy/authorization.py",
        "repetitions > maximum_repetitions",
        "repetitions >= maximum_repetitions",
        ("tests/test_authorization.py::test_repeated_post_requires_key_and_obeys_manifest_limit",),
    ),
    Mutation(
        "BUDGET-ATTEMPT-RESERVATION",
        "mrma/policy/budget.py",
        "combined.total_network_attempts + 1",
        "combined.total_network_attempts",
        ("tests/test_budget_journal.py::test_budget_exhaustion_occurs_before_a_lease_exists",),
    ),
    Mutation(
        "BUDGET-REQUEST-BYTES",
        "mrma/policy/budget.py",
        "combined.bytes_sent + proposed.request_bytes",
        "combined.bytes_sent + proposed.request_body_bytes",
        ("tests/test_budget_journal.py::test_request_byte_budget_uses_full_semantic_estimate",),
    ),
    Mutation(
        "BUDGET-WALL-DEADLINE",
        "mrma/policy/budget.py",
        "wall_elapsed_ms + proposed.timeout_ms > self.limits.total_duration_ms",
        "wall_elapsed_ms + proposed.timeout_ms >= self.limits.total_duration_ms",
        ("tests/test_budget_journal.py::test_exact_wall_clock_reservation_boundary_is_allowed",),
    ),
    Mutation(
        "VERDICT-INFLUENCE-BRANCH",
        "mrma/core/experiment.py",
        'elif control_confidently_stable and mutation_interval[0] >= cfg.min_reproducibility:\n        verdict = "INFLUENCE_DETECTED"',
        'elif control_confidently_stable and mutation_interval[0] >= cfg.min_reproducibility:\n        verdict = "INCONCLUSIVE"',
        ("tests/test_experiment.py::test_fixed_sample_brackets_mutation_and_requires_confidence_bounds",),
    ),
    Mutation(
        "VERDICT-NO-INFLUENCE-BRANCH",
        "mrma/core/experiment.py",
        'and mutation_interval[1] <= cfg.no_influence_threshold\n    ):\n        verdict = "NO_INFLUENCE_OBSERVED"',
        'and mutation_interval[1] <= cfg.no_influence_threshold\n    ):\n        verdict = "INCONCLUSIVE"',
        ("tests/test_experiment.py::test_no_influence_requires_upper_confidence_bound",),
    ),
    Mutation(
        "VERDICT-INDETERMINATE-GUARD",
        "mrma/core/experiment.py",
        "and mutation_indeterminate == 0\n        and mutation_interval[1]",
        "and mutation_indeterminate >= 0\n        and mutation_interval[1]",
        ("tests/test_experiment.py::test_missing_content_type_defaults_to_digest_only_evidence",),
    ),
    Mutation(
        "REDIRECT-CROSS-ORIGIN-FIELDS",
        "mrma/engine/oracle.py",
        "if cross_origin and not allow_all_cross_origin and lowered not in cross_origin_fields:",
        "if False and not allow_all_cross_origin and lowered not in cross_origin_fields:",
        ("tests/test_oracle.py::test_redirect_method_and_credential_policy_transformations",),
    ),
    Mutation(
        "OBSERVATION-SESSION-STATE",
        "mrma/core/http_client.py",
        "if active is None:\n            client, close_after = self._client_for(arm, round_index)\n            self._before_observation(client, arm)",
        "if active is not None:\n            client, close_after = self._client_for(arm, round_index)\n            self._before_observation(client, arm)",
        ("tests/test_oracle.py::test_isolated_observation_preserves_redirect_cookie_only_inside_chain",),
    ),
    Mutation(
        "PLAN-BODY-IDENTITY",
        "mrma/engine/plan.py",
        '"body_fingerprint": redactor.fingerprint(request.body, label="plan-request-body"),',
        '"body_fingerprint": "hmac-sha256:" + "0" * 64,',
        ("tests/test_oracle.py::test_plan_digest_binds_effective_request_and_decision_policy",),
    ),
    Mutation(
        "PARTIAL-COMPLETE-SAMPLING",
        "mrma/evidence/models.py",
        'result.status == "completed"\n        and result.completed_rounds',
        "result.completed_rounds",
        ("tests/test_oracle.py::test_partial_outcomes_are_valid_v8_evidence",),
    ),
    Mutation(
        "LEGACY-MUTATION-BASELINE",
        "mrma/workflows/legacy.py",
        "self.authorization.validate_mutation(\n            self.baseline,\n            request,",
        "self.authorization.validate_mutation(\n            request,\n            request,",
        (
            "tests/test_legacy_workflow.py::test_legacy_dispatcher_binds_allowed_forbidden_and_oversized_headers",
        ),
    ),
    Mutation(
        "REDIRECT-FINAL-COOKIE-FIELD",
        "mrma/core/http_client.py",
        'if not allow_cookie_field:\n        request.headers.pop("cookie", None)',
        'if allow_cookie_field:\n        request.headers.pop("cookie", None)',
        (
            "tests/test_http_client.py::test_final_built_request_suppresses_explicit_and_cookie_jar_fields",
        ),
    ),
    Mutation(
        "REDIRECT-CROSS-ORIGIN-STATE-RESET",
        "mrma/engine/oracle.py",
        "if cross_origin and not allow_cross_origin_cookie:\n"
        "                self.transport.clear_observation_cookies()",
        "if False:\n"
        "                self.transport.clear_observation_cookies()",
        (
            "tests/test_oracle.py::test_cross_origin_redirect_suppresses_domain_cookie_after_request_build",
        ),
    ),
    Mutation(
        "PLAN-DIGEST-RECOMPUTE",
        "mrma/evidence/bundle.py",
        'if plan["plan_digest"] != effective_plan_digest(effective_plan):',
        "if False:",
        ("tests/test_oracle.py::test_result_verifier_recomputes_effective_plan_digest",),
    ),
    Mutation(
        "JOURNAL-PLAN-BINDING",
        "mrma/evidence/bundle.py",
        "if not planned or any(value != expected for value in planned):",
        "if not planned and any(value != expected for value in planned):",
        (
            "tests/test_cli_integration.py::test_cli_emits_schema_valid_evidence_and_stable_influence_exit_code",
        ),
    ),
    Mutation(
        "VERSIONED-V7-BUILDER",
        "mrma/evidence/models.py",
        'document["schema_version"] = "mrma.experiment/v7"',
        'document["schema_version"] = "mrma.experiment/v8"',
        ("tests/test_oracle.py::test_versioned_v7_builder_emits_schema_valid_v7",),
    ),
)


def _mutated_workspace(root: Path, mutation: Mutation) -> tempfile.TemporaryDirectory[str]:
    temporary = tempfile.TemporaryDirectory(prefix="mrma-mutation-")
    destination = Path(temporary.name)
    shutil.copytree(root / "mrma", destination / "mrma")
    shutil.copytree(root / "tests", destination / "tests")
    shutil.copy2(root / "pyproject.toml", destination / "pyproject.toml")
    path = destination / mutation.path
    source = path.read_text(encoding="utf-8")
    count = source.count(mutation.original)
    if count != 1:
        temporary.cleanup()
        raise RuntimeError(
            f"{mutation.identifier}: expected one mutation site, found {count}"
        )
    path.write_text(source.replace(mutation.original, mutation.replacement), encoding="utf-8")
    return temporary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", type=Path, default=Path("tools/mutation-baseline.json"))
    parser.add_argument("--timeout", type=float, default=90.0)
    parser.add_argument("--json-output", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    baseline = json.loads((root / args.baseline).read_text(encoding="utf-8"))
    expected_ids = baseline["mutant_ids"]
    actual_ids = [mutation.identifier for mutation in MUTATIONS]
    if expected_ids != actual_ids or baseline["expected_mutants"] != len(MUTATIONS):
        raise RuntimeError("mutation catalog does not match the committed baseline")

    results: list[dict[str, object]] = []
    for mutation in MUTATIONS:
        with _mutated_workspace(root, mutation) as temporary_name:
            workspace = Path(temporary_name)
            environment = os.environ.copy()
            environment["PYTHONPATH"] = str(workspace)
            try:
                completed = subprocess.run(
                    [sys.executable, "-m", "pytest", "-q", *mutation.tests],
                    cwd=workspace,
                    env=environment,
                    capture_output=True,
                    text=True,
                    timeout=args.timeout,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                print(f"ERROR {mutation.identifier}: test timed out")
                return 2
        if completed.returncode not in {0, 1}:
            print(f"ERROR {mutation.identifier}: pytest exited {completed.returncode}")
            print(completed.stdout)
            print(completed.stderr)
            return 2
        killed = completed.returncode == 1
        results.append({"id": mutation.identifier, "killed": killed})
        print(f"{'KILLED' if killed else 'SURVIVED'} {mutation.identifier}")

    killed_count = sum(bool(item["killed"]) for item in results)
    report = {
        "schema_version": "mrma.semantic-mutation-result/v1",
        "catalog_version": baseline["catalog_version"],
        "mutants": len(results),
        "killed": killed_count,
        "survived": len(results) - killed_count,
        "score": round(killed_count / len(results), 6),
        "results": results,
    }
    if args.json_output:
        args.json_output.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    if killed_count < baseline["minimum_killed"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
