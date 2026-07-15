from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

from mrma.cli import (
    build_parser,
    cmd_diff,
    cmd_discover,
    cmd_impact,
    cmd_isolate,
    cmd_isolate_remove,
    cmd_profile_host_routing,
    cmd_profile_proxy_trust,
    cmd_profile_security_headers,
    cmd_report,
    cmd_run,
)
from mrma.core.http_client import (
    NetworkPolicyError,
    SemanticHttpTransport,
    SendOptions,
    send_raw_request,
)
from mrma.core.raw_request import RawRequest
from mrma.evidence import EvidenceJournal
from mrma.transport import SemanticHttpAdapter
from mrma.transport.semantic_http import TransportPolicyError


def test_no_cli_or_workflow_constructs_httpx_clients_or_low_level_transport():
    forbidden = []
    for root in (Path("mrma/workflows"), Path("mrma/engine"), Path("mrma/cli.py")):
        paths = [root] if root.is_file() else sorted(root.rglob("*.py"))
        for path in paths:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    rendered = ast.unparse(node.func)
                    if rendered in {
                        "httpx.Client",
                        "httpx.AsyncClient",
                        "SemanticHttpTransport",
                    }:
                        forbidden.append((str(path), node.lineno, rendered))
    assert forbidden == []


def test_production_transport_requires_all_three_policy_contexts():
    signature = inspect.signature(SemanticHttpAdapter.send)
    required = {"authorization", "lease", "evidence"}
    assert required.issubset(signature.parameters)
    assert all(signature.parameters[name].default is inspect.Parameter.empty for name in required)


def test_low_level_legacy_send_refuses_network_without_guarded_scope():
    request = RawRequest("GET", "/", "HTTP/1.1", [], b"")
    with pytest.raises(NetworkPolicyError, match="authorization-first dispatch scope"):
        send_raw_request(
            request,
            base_url="http://127.0.0.1:9",
            opts=SendOptions(trust_env=False, timeout_s=0.01),
        )

    with pytest.raises(NetworkPolicyError, match="authorization kernel capability"):
        SemanticHttpTransport(SendOptions(trust_env=False))


def test_authorization_first_adapter_rejects_ambient_transport_configuration():
    journal = EvidenceJournal(run_id="ambient")
    with pytest.raises(TransportPolicyError, match="AMBIENT_TRANSPORT_CONFIGURATION_REJECTED"):
        SemanticHttpAdapter(SendOptions(trust_env=True), journal=journal)


def test_every_network_cli_handler_requires_authorization_and_journal():
    parser = build_parser()
    network_handlers = {
        cmd_run,
        cmd_diff,
        cmd_discover,
        cmd_isolate,
        cmd_isolate_remove,
        cmd_impact,
        cmd_profile_security_headers,
        cmd_profile_proxy_trust,
        cmd_profile_host_routing,
        cmd_report,
    }
    discovered: dict[object, object] = {}
    pending = [parser]
    while pending:
        current = pending.pop()
        defaults = current._defaults
        if defaults.get("func") in network_handlers:
            discovered[defaults["func"]] = defaults.get("_requires_authorization")
            destinations = {action.dest for action in current._actions}
            assert {"authorization", "journal"}.issubset(destinations)
        for action in current._actions:
            choices = getattr(action, "choices", None)
            if isinstance(choices, dict):
                pending.extend(choices.values())
    assert set(discovered) == network_handlers
    assert all(discovered.values())
