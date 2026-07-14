import json
import subprocess
import sys
import threading
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files

from jsonschema import Draft202012Validator


class ExperimentHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"mutation" if self.headers.get("X-Probe") == "1" else b"control"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *args):
        return


def test_cli_emits_schema_valid_evidence_and_stable_influence_exit_code():
    server = ThreadingHTTPServer(("127.0.0.1", 0), ExperimentHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/private/path?token=secret"
        process = subprocess.run(
            [
                sys.executable,
                "-c",
                "from mrma.cli import main; main()",
                "experiment",
                "--url",
                url,
                "--set-header",
                "X-Probe: 1",
                "--assurance",
                "research",
                "--ignore-header",
                "date",
                "--json",
                "--fail-on",
                "influence",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert process.returncode == 10, process.stderr
    payload = json.loads(process.stdout)
    schema = json.loads(
        files("mrma.schemas").joinpath("experiment-v5.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    validator.validate(payload)
    assert payload["schema_version"] == "mrma.experiment/v5"
    assert payload["result"]["verdict"] == "INFLUENCE_DETECTED"
    assert payload["result"]["design"]["control_observations"] == 40
    assert payload["run"]["started_at"].endswith(":00+00:00")
    assert payload["run"]["timestamp_precision"] == "minute"
    assert payload["run"]["duration"]["exact_ms"] is None
    assert isinstance(payload["run"]["duration"]["bucket"], str)
    assert payload["transport"]["retry_policy"]["max_retries"] == 0
    assert payload["transport"]["trust_environment"] is False
    assert payload["transport"]["tls"] == {
        "verification": "system",
        "ca_fingerprint": None,
    }
    assert payload["transport"]["proxy"] == {
        "mode": "none",
        "source": "none",
        "endpoint_fingerprint": None,
    }
    assert payload["evidence_storage"]["sink"] == "stdout"
    assert payload["evidence_storage"]["write_mode"] == "stdout"
    assert "evidence_grade" not in payload["result"]
    assert payload["result"]["design"]["assurance_preset"] == "research"
    assert payload["transport"]["connection_mode"] == "fresh-observation"
    assert payload["result"]["assurance_profile"]["connection_independence"] == "strong"
    assert payload["result"]["assurance_profile"]["transport_integrity"] == "strong"
    assert payload["result"]["design"]["missing_content_type_policy"] == "digest-only"
    assert payload["result"]["design"]["response_header_policy"][
        "omitted_headers_possible"
    ] is True
    assert all(
        item["code"] != "CONNECTION_REUSE" for item in payload["result"]["limitations"]
    )
    assert payload["result"]["design"]["operating_characteristics"][
        "positive_min_changed"
    ] == 20
    assert "private" not in str(payload["target"])
    assert "secret" not in str(payload)

    normal_file = deepcopy(payload)
    normal_file["evidence_storage"] = {
        "sink": "file",
        "write_mode": "normal",
        "file_sync": False,
        "directory_sync": "not-requested",
        "scope": "experiment-json-only",
    }
    assert validator.is_valid(normal_file)

    durable_file = deepcopy(payload)
    durable_file["evidence_storage"] = {
        "sink": "file",
        "write_mode": "durable",
        "file_sync": True,
        "directory_sync": "unsupported",
        "scope": "experiment-json-only",
    }
    assert validator.is_valid(durable_file)

    malformed = []
    extra_observation_field = deepcopy(payload)
    extra_observation_field["result"]["observations"][0]["raw_body"] = "leak"
    malformed.append(extra_observation_field)

    missing_attempt_outcome = deepcopy(payload)
    del missing_attempt_outcome["result"]["observations"][0]["attempt_trace"][0][
        "outcome"
    ]
    malformed.append(missing_attempt_outcome)

    invalid_interval = deepcopy(payload)
    invalid_interval["result"]["reproducibility"]["wilson_interval_95"] = [0, 1, 2]
    malformed.append(invalid_interval)

    invalid_round = deepcopy(payload)
    invalid_round["result"]["round_evidence"][0]["classification"] = "MAYBE"
    malformed.append(invalid_round)

    exact_standard_timestamp = deepcopy(payload)
    exact_standard_timestamp["run"]["started_at"] = "2026-07-14T15:38:47.123+00:00"
    malformed.append(exact_standard_timestamp)

    exact_standard_duration = deepcopy(payload)
    exact_standard_duration["run"]["duration"] = {"exact_ms": 123.456, "bucket": None}
    malformed.append(exact_standard_duration)

    resurrected_scalar_grade = deepcopy(payload)
    resurrected_scalar_grade["result"]["evidence_grade"] = "strong"
    malformed.append(resurrected_scalar_grade)

    incomplete_limitation = deepcopy(payload)
    del incomplete_limitation["result"]["limitations"][0]["remediation"]
    malformed.append(incomplete_limitation)

    false_durable_claim = deepcopy(payload)
    false_durable_claim["evidence_storage"] = {
        "sink": "file",
        "write_mode": "durable",
        "file_sync": False,
        "directory_sync": "not-requested",
        "scope": "experiment-json-only",
    }
    malformed.append(false_durable_claim)

    hidden_environment_transport = deepcopy(payload)
    hidden_environment_transport["transport"]["proxy"] = {
        "mode": "environment",
        "source": "environment",
        "endpoint_fingerprint": "hmac-sha256:0123456789",
    }
    malformed.append(hidden_environment_transport)

    missing_custom_ca_fingerprint = deepcopy(payload)
    missing_custom_ca_fingerprint["transport"]["tls"] = {
        "verification": "custom-ca",
        "ca_fingerprint": None,
    }
    malformed.append(missing_custom_ca_fingerprint)

    weakened_research_environment = deepcopy(payload)
    weakened_research_environment["transport"]["trust_environment"] = True
    malformed.append(weakened_research_environment)

    assert all(not validator.is_valid(document) for document in malformed)
