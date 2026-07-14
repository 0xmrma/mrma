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
                "--rounds",
                "20",
                "--body-storage",
                "full",
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
        files("mrma.schemas").joinpath("experiment-v3.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    validator.validate(payload)
    assert payload["schema_version"] == "mrma.experiment/v3"
    assert payload["result"]["verdict"] == "INFLUENCE_DETECTED"
    assert payload["result"]["design"]["control_observations"] == 40
    assert payload["run"]["started_at"].endswith(":00+00:00")
    assert payload["run"]["timestamp_precision"] == "minute"
    assert payload["run"]["duration"]["exact_ms"] is None
    assert isinstance(payload["run"]["duration"]["bucket"], str)
    assert payload["transport"]["retry_policy"]["max_retries"] == 0
    assert payload["result"]["design"]["operating_characteristics"][
        "positive_min_changed"
    ] == 20
    assert "private" not in str(payload["target"])
    assert "secret" not in str(payload)

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

    assert all(not validator.is_valid(document) for document in malformed)
