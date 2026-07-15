from __future__ import annotations

import json
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest


@pytest.fixture
def authorization_payload() -> dict[str, object]:
    now = datetime.now(timezone.utc)
    return {
        "schema_version": "mrma.authorization/v1",
        "engagement_id": "local-test",
        "issuer": "test-suite",
        "subject": "researcher",
        "issued_at": (now - timedelta(minutes=5)).isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
        "rules": [
            {
                "schemes": ["http", "https"],
                "hosts": ["example.test", "127.0.0.1"],
                "ports": [80, 443],
                "path_prefixes": ["/"],
                "methods": ["GET", "POST"],
                "attempt_kinds": [
                    "control",
                    "mutation",
                    "retry",
                    "redirect",
                    "setup",
                    "reset",
                    "exploratory",
                ],
                "cidrs": ["127.0.0.0/8", "2001:db8::/32"],
                "maximum_request_body_bytes": 4096,
                "maximum_repetitions_by_method": {"POST": 4},
                "require_idempotency_key": ["POST"],
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
        "mutation_risk_classes": [
            "safe",
            "idempotent-destructive",
            "non-idempotent",
        ],
        "budget": {
            "total_network_attempts": 200,
            "controls": 100,
            "mutations": 100,
            "retries": 50,
            "redirects": 100,
            "setup_reset_attempts": 10,
            "attempts_per_origin": 200,
            "requests_per_target": 200,
            "bytes_sent": 1000000,
            "bytes_received": 100000000,
            "maximum_response_bytes": 1048576,
            "maximum_request_body_bytes": 4096,
            "total_duration_ms": 1000000,
            "per_attempt_timeout_ms": 20000,
            "concurrency": 8,
            "redirect_depth": 4,
            "mutation_risk_level": "non-idempotent",
        },
        "organizational_metadata": {"environment": "local-lab"},
    }


@pytest.fixture
def write_authorization(tmp_path: Path) -> Callable[[dict[str, object]], Path]:
    def write(payload: dict[str, object]) -> Path:
        path = tmp_path / "authorization.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    return write
