from __future__ import annotations

import json
import platform
import threading
import time
import tracemalloc
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event
from typing import Any, Callable, Iterator, cast

from mrma import __version__
from mrma.core.compare import EquivalenceConfig, equivalent_response
from mrma.core.experiment import ExperimentConfig
from mrma.core.http_client import SendOptions
from mrma.core.mutate import set_header
from mrma.core.privacy import EvidenceRedactor
from mrma.core.raw_request import RawRequest, parse_raw_http_request_bytes
from mrma.core.sender import SendPolicy
from mrma.engine import ExperimentOracle, ExperimentPlan, OracleRunResult
from mrma.evidence import EvidenceJournal
from mrma.policy.authorization import ManifestAuthorizationPolicy, load_authorization_manifest
from mrma.policy.budget import BudgetLedger, BudgetLimits
from mrma.policy.comparison import ComparisonPolicy
from mrma.transport import SemanticHttpAdapter

BENCHMARK_SCHEMA_VERSION = "mrma.benchmark/v1"
BENCHMARK_CORPUS_VERSION = "expert-loopback-corpus/1.0"


@dataclass(frozen=True)
class BenchmarkCase:
    name: str
    expected_verdict: str
    actual_verdict: str
    request_cost: int
    runtime_ms: float
    passed: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "expected_verdict": self.expected_verdict,
            "actual_verdict": self.actual_verdict,
            "request_cost": self.request_cost,
            "runtime_ms": self.runtime_ms,
            "passed": self.passed,
        }


class _BenchmarkHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    counters: dict[str, int] = {}
    lock = threading.Lock()

    def _count(self, key: str) -> int:
        with self.lock:
            value = self.counters.get(key, 0) + 1
            self.counters[key] = value
            return value

    def _send(
        self,
        status: int,
        body: bytes,
        *,
        content_type: str | None = "text/plain; charset=utf-8",
        headers: tuple[tuple[str, str], ...] = (),
    ) -> None:
        self.send_response_only(status)
        if content_type is not None:
            self.send_header("Content-Type", content_type)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        mutation = self.headers.get("X-Probe") == "1"
        if path == "/stable-no-influence":
            self._send(200, b"stable")
        elif path == "/body-influence":
            self._send(200, b"mutation" if mutation else b"control")
        elif path == "/status-influence":
            self._send(403 if mutation else 200, b"same")
        elif path == "/header-influence":
            value = "mutation" if mutation else "control"
            self._send(200, b"same", headers=(("X-Benchmark", value),))
        elif path == "/redirect-influence" and mutation:
            self._send(302, b"", headers=(("Location", "/redirect-final"),))
        elif path in {"/redirect-influence", "/redirect-final"}:
            self._send(200, b"same")
        elif path == "/retry-influence":
            attempt = self._count("retry-mutation") if mutation else 0
            self._send(503 if mutation and attempt % 2 else 200, b"same")
        elif path == "/unstable-controls":
            count = self._count("unstable-control") if not mutation else 0
            self._send(200, f"value-{count % 2}".encode() if not mutation else b"mutation")
        elif path == "/cookie-contamination":
            has_cookie = "session=1" in (self.headers.get("Cookie") or "")
            self._send(
                200,
                b"stateful" if has_cookie else b"fresh",
                headers=(("Set-Cookie", "session=1; Path=/"),),
            )
        elif path == "/connection-affinity":
            self._send(200, b"stable")
        elif path == "/missing-content-type":
            self._send(200, b"mutation" if mutation else b"control", content_type=None)
        elif path == "/malformed-content-type":
            self._send(
                200,
                b"mutation" if mutation else b"control",
                content_type='text/plain; charset="unterminated',
            )
        elif path == "/equivalent-content-type":
            content_type = (
                "text/plain;charset=utf-8"
                if mutation
                else 'Text/Plain; Charset="UTF-8"'
            )
            self._send(200, b"same", content_type=content_type)
        elif path == "/xml-encoding":
            if mutation:
                body = b'<?xml version="1.0" encoding="UTF-8"?><root>mutation</root>'
            else:
                body = b'<?xml version="1.0" encoding="UTF-8"?><root>control</root>'
            self._send(200, body, content_type="application/xml")
        elif path == "/binary-response":
            self._send(200, b"\x00\xff\x10\x80", content_type="application/octet-stream")
        elif path == "/truncated-body":
            self.send_response_only(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", "100")
            self.end_headers()
            self.wfile.write(b"short")
            self.wfile.flush()
            self.close_connection = True
        elif path == "/unauthorized-redirect":
            self._send(302, b"", headers=(("Location", "/outside-scope"),))
        else:
            self._send(404, b"not-found")

    def log_message(self, _format: str, *args: object) -> None:
        return


@contextmanager
def _local_server() -> Iterator[ThreadingHTTPServer]:
    _BenchmarkHandler.counters = {}
    server = ThreadingHTTPServer(("127.0.0.1", 0), _BenchmarkHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _authorization_payload(
    port: int,
    *,
    path_prefixes: list[str] | None = None,
    budget: dict[str, object] | None = None,
) -> dict[str, object]:
    now = datetime.now(timezone.utc)
    limits: dict[str, object] = {
        "total_network_attempts": 500,
        "controls": 100,
        "mutations": 100,
        "retries": 100,
        "redirects": 300,
        "setup_reset_attempts": 20,
        "attempts_per_origin": 500,
        "requests_per_target": 500,
        "bytes_sent": 2000000,
        "bytes_received": 4 * 1024 * 1024,
        "maximum_response_bytes": 4096,
        "maximum_request_body_bytes": 4096,
        "total_duration_ms": 500000,
        "per_attempt_timeout_ms": 1000,
        "concurrency": 1,
        "redirect_depth": 4,
        "mutation_risk_level": "safe",
    }
    if budget:
        limits.update(budget)
    return {
        "schema_version": "mrma.authorization/v1",
        "engagement_id": "mrma-local-benchmark",
        "issuer": "mrma-benchmark-runner",
        "subject": "local-process",
        "issued_at": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
        "rules": [
            {
                "schemes": ["http"],
                "hosts": ["127.0.0.1"],
                "ports": [port],
                "path_prefixes": path_prefixes or ["/"],
                "methods": ["GET"],
                "attempt_kinds": [
                    "control",
                    "mutation",
                    "retry",
                    "redirect",
                    "setup",
                    "reset",
                    "exploratory",
                ],
                "cidrs": ["127.0.0.0/8"],
                "maximum_request_body_bytes": 4096,
                "maximum_repetitions_by_method": {},
                "require_idempotency_key": [],
                "disposable_environment": True,
            }
        ],
        "proxy": {"mode": "deny", "hosts": [], "ports": [], "cidrs": []},
        "redirects": {
            "mode": "authorized-targets",
            "maximum_depth": 4,
            "forward_credentials_cross_origin": False,
        },
        "mutation_families": ["header"],
        "mutation_risk_classes": ["safe"],
        "budget": limits,
        "organizational_metadata": {},
    }


def _network_case(
    root: Path,
    port: int,
    path: str,
    *,
    retries: int = 0,
    follow_redirects: bool = False,
    state_mode: str = "isolated",
    connection_mode: str = "reuse",
    response_headers: tuple[str, ...] = (),
    path_prefixes: list[str] | None = None,
    budget: dict[str, object] | None = None,
    cancellation: Event | None = None,
) -> tuple[str, int, OracleRunResult]:
    manifest_path = root / f"manifest-{path.strip('/').replace('/', '-')}.json"
    manifest_path.write_text(
        json.dumps(
            _authorization_payload(
                port,
                path_prefixes=path_prefixes,
                budget=budget,
            )
        ),
        encoding="utf-8",
    )
    manifest = load_authorization_manifest(manifest_path)
    authorization = ManifestAuthorizationPolicy(
        manifest,
        resolver=lambda _host, _port: ("127.0.0.1",),
    )
    journal = EvidenceJournal(run_id=f"benchmark-{path.strip('/') or 'root'}")
    ledger = BudgetLedger(BudgetLimits.from_mapping(manifest.budget), journal)
    adapter = SemanticHttpAdapter(
        SendOptions(trust_env=False, timeout_s=1.0),
        journal=journal,
        state_mode=state_mode,
        connection_mode=connection_mode,
    )
    baseline = RawRequest("GET", path, "HTTP/1.1", [], b"")
    mutation = set_header(baseline, "X-Probe", "1", override=True)
    config = ExperimentConfig(
        rounds=20,
        schedule_mode="bracketed",
        state_mode=state_mode,
        connection_mode=connection_mode,
        max_response_bytes=4096,
        body_storage="full",
        response_header_scope="explicit" if response_headers else "known",
        include_response_headers=response_headers,
        assurance_preset="research",
        redactor=EvidenceRedactor(policy="standard"),
    )
    plan = ExperimentPlan(
        baseline=baseline,
        mutation=mutation,
        base_url=f"http://127.0.0.1:{port}",
        experiment=config,
        send=SendPolicy(retries=retries, retry_status=(503,)),
        follow_redirects=follow_redirects,
        mutation_family="header",
        mutation_risk_class="safe",
        exploration_role="confirmation",
    )
    oracle = ExperimentOracle(
        authorization=authorization,
        budgets=ledger,
        transport=adapter,
        comparison=ComparisonPolicy(config.equivalence),
        evidence=journal,
    )
    result = oracle.run(plan, cancellation=cancellation)
    return result.verdict, result.budget.total_network_attempts, result


def _timed_case(
    name: str,
    expected: str,
    operation: Callable[[], tuple[str, int]],
) -> BenchmarkCase:
    started = time.perf_counter()
    actual, request_cost = operation()
    elapsed = round((time.perf_counter() - started) * 1000, 3)
    return BenchmarkCase(name, expected, actual, request_cost, elapsed, actual == expected)


def run_benchmark() -> dict[str, object]:
    cases: list[BenchmarkCase] = []
    tracemalloc.start()
    started = time.perf_counter()
    with TemporaryDirectory(prefix="mrma-benchmark-") as temporary_name, _local_server() as server:
        root = Path(temporary_name)
        port = server.server_port

        network_specs: tuple[tuple[str, str, str, dict[str, Any]], ...] = (
            ("stable-no-influence", "NO_INFLUENCE_OBSERVED", "/stable-no-influence", {}),
            ("stable-body-influence", "INFLUENCE_DETECTED", "/body-influence", {}),
            ("status-only-influence", "INFLUENCE_DETECTED", "/status-influence", {}),
            (
                "custom-header-only-influence",
                "INFLUENCE_DETECTED",
                "/header-influence",
                {"response_headers": ("x-benchmark",)},
            ),
            (
                "redirect-only-influence",
                "INFLUENCE_DETECTED",
                "/redirect-influence",
                {"follow_redirects": True},
            ),
            (
                "retry-only-influence",
                "INFLUENCE_DETECTED",
                "/retry-influence",
                {"retries": 1},
            ),
            ("unstable-controls", "INCONCLUSIVE", "/unstable-controls", {}),
            (
                "cookie-contamination",
                "INCONCLUSIVE",
                "/cookie-contamination",
                {"state_mode": "shared-session", "connection_mode": "reuse"},
            ),
            (
                "missing-content-type",
                "INCONCLUSIVE",
                "/missing-content-type",
                {},
            ),
            (
                "malformed-content-type",
                "INCONCLUSIVE",
                "/malformed-content-type",
                {},
            ),
            (
                "equivalent-content-type-formatting",
                "NO_INFLUENCE_OBSERVED",
                "/equivalent-content-type",
                {},
            ),
            ("xml-encoding", "INFLUENCE_DETECTED", "/xml-encoding", {}),
            ("binary-response", "NO_INFLUENCE_OBSERVED", "/binary-response", {}),
            ("truncated-body", "INCONCLUSIVE", "/truncated-body", {}),
        )
        for name, expected, path, options in network_specs:
            def run_spec(
                path: str = path,
                options: dict[str, Any] = options,
            ) -> tuple[str, int]:
                return _network_case(root, port, path, **options)[:2]

            cases.append(
                _timed_case(
                    name,
                    expected,
                    run_spec,
                )
            )

        def connection_affinity() -> tuple[str, int]:
            _verdict, cost, result = _network_case(
                root,
                port,
                "/connection-affinity",
                connection_mode="reuse",
            )
            limitations = cast(
                list[dict[str, object]], result.experiment.to_dict()["limitations"]
            )
            actual = (
                "LIMITATION_RECORDED"
                if any(item["code"] == "CONNECTION_REUSE" for item in limitations)
                else "LIMITATION_MISSING"
            )
            return actual, cost

        cases.append(
            _timed_case(
                "connection-affinity",
                "LIMITATION_RECORDED",
                connection_affinity,
            )
        )

        cases.append(
            _timed_case(
                "unauthorized-initial-target",
                "INCONCLUSIVE",
                lambda: _network_case(
                    root,
                    port,
                    "/body-influence",
                    path_prefixes=["/allowed"],
                )[:2],
            )
        )
        cases.append(
            _timed_case(
                "unauthorized-redirect",
                "INCONCLUSIVE",
                lambda: _network_case(
                    root,
                    port,
                    "/unauthorized-redirect",
                    follow_redirects=True,
                    path_prefixes=["/unauthorized-redirect"],
                )[:2],
            )
        )
        cases.append(
            _timed_case(
                "budget-exhaustion",
                "INCONCLUSIVE",
                lambda: _network_case(
                    root,
                    port,
                    "/body-influence",
                    budget={"total_network_attempts": 1},
                )[:2],
            )
        )
        cancelled = Event()
        cancelled.set()
        cases.append(
            _timed_case(
                "cancellation-partial-evidence",
                "INCONCLUSIVE",
                lambda: _network_case(
                    root,
                    port,
                    "/body-influence",
                    cancellation=cancelled,
                )[:2],
            )
        )

    oversized_a = b"a" * (256 * 1024 + 1)
    oversized_b = b"b" * (256 * 1024 + 1)
    cases.append(
        _timed_case(
            "comparator-resource-limit",
            "INCONCLUSIVE",
            lambda: (
                "INCONCLUSIVE"
                if not equivalent_response(
                    200,
                    oversized_a,
                    200,
                    oversized_b,
                    EquivalenceConfig(),
                ).completed
                else "COMPLETED",
                0,
            ),
        )
    )
    cases.append(
        _timed_case(
            "normalization-timeout",
            "INCONCLUSIVE",
            lambda: (
                "INCONCLUSIVE"
                if not equivalent_response(
                    200,
                    b"a" * 10000 + b"!",
                    200,
                    b"a" * 10000 + b"?",
                    EquivalenceConfig(
                        ignore_body_regex=(r"(a+)+$",),
                        regex_rule_timeout_s=0.000001,
                    ),
                ).completed
                else "COMPLETED",
                0,
            ),
        )
    )

    def binary_raw() -> tuple[str, int]:
        body = b"\x00\xff\x10\x80"
        request = parse_raw_http_request_bytes(
            b"POST /binary HTTP/1.1\r\nHost: example.test\r\nContent-Length: 4\r\n\r\n"
            + body
        )
        return ("BINARY_PRESERVED" if request.body == body else "BINARY_CORRUPTED", 0)

    cases.append(
        _timed_case("binary-raw-request", "BINARY_PRESERVED", binary_raw)
    )
    total_runtime_ms = round((time.perf_counter() - started) * 1000, 3)
    _, peak_memory = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    false_positives = sum(
        item.expected_verdict == "NO_INFLUENCE_OBSERVED"
        and item.actual_verdict == "INFLUENCE_DETECTED"
        for item in cases
    )
    false_negatives = sum(
        item.expected_verdict == "INFLUENCE_DETECTED"
        and item.actual_verdict == "NO_INFLUENCE_OBSERVED"
        for item in cases
    )
    inconclusive = sum(item.actual_verdict == "INCONCLUSIVE" for item in cases)
    return {
        "schema_version": BENCHMARK_SCHEMA_VERSION,
        "corpus_version": BENCHMARK_CORPUS_VERSION,
        "mrma_version": __version__,
        "passed": all(item.passed for item in cases),
        "case_count": len(cases),
        "false_positive_count": false_positives,
        "false_negative_count": false_negatives,
        "inconclusive_count": inconclusive,
        "request_cost": sum(item.request_cost for item in cases),
        "runtime_ms": total_runtime_ms,
        "peak_memory_bytes": peak_memory,
        "platform": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "operating_system": platform.system(),
            "machine": platform.machine(),
        },
        "cases": [item.to_dict() for item in cases],
    }
