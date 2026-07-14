import json
import subprocess
import sys
import threading
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
        files("mrma.schemas").joinpath("experiment-v2.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator(schema).validate(payload)
    assert payload["result"]["verdict"] == "INFLUENCE_DETECTED"
    assert payload["result"]["design"]["control_observations"] == 40
    assert "private" not in str(payload["target"])
    assert "secret" not in str(payload)
