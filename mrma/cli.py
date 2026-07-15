from __future__ import annotations

import argparse
import hashlib
import json
import os
import ssl
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator
from uuid import uuid4

from rich import box
from rich.panel import Panel
from rich.table import Table

from . import __version__
from .benchmark import run_benchmark
from .core.compare import EquivalenceConfig, equivalent_response, resolve_equivalence_policy
from .core.config import cfg_defaults, default_config_paths, load_config
from .core.discover import discover_required_headers
from .core.experiment import ExperimentConfig, operating_characteristics
from .core.export import to_curl, to_raw
from .core.fingerprint import fingerprint_response
from .core.header_sets import common_headers
from .core.http_client import (
    SendOptions,
    authorized_http_dispatch,
    send_raw_request,
    ssl_context_from_ca_bytes,
)
from .core.impact import run_impact
from .core.isolate import isolate_added_headers
from .core.isolate_remove import isolate_removed_headers
from .core.jsonout import print_json
from .core.mutate import remove_header, set_header
from .core.mutations import default_mutations
from .core.pack_file import parse_pack_file
from .core.packs import list_packs, mutations_for_pack
from .core.privacy import EvidenceRedactor
from .core.quick_request import build_request_from_url
from .core.raw_request import RawRequest, parse_raw_http_request_bytes
from .core.render import render_raw_request
from .core.report import render_md_report, utc_now_iso
from .core.sender import RateGate, SendPolicy, send_with_policy
from .core.stability import measure_stability
from .engine import ExperimentOracle, ExperimentPlan
from .evidence import (
    EvidenceIntegrityError,
    EvidenceJournal,
    create_evidence_bundle,
    verify_evidence,
)
from .evidence.models import build_experiment_v7
from .policy.authorization import (
    AuthorizationError,
    ManifestAuthorizationPolicy,
    load_authorization_manifest,
)
from .policy.budget import BudgetError, BudgetLedger, BudgetLimits
from .policy.comparison import ComparisonPolicy
from .profiles.host_routing import default_host_routing_cases, run_host_routing_profile
from .profiles.proxy_trust import default_proxy_trust_cases, run_proxy_trust_profile
from .profiles.security_headers import audit_security_headers
from .transport import SemanticHttpAdapter
from .ui import console, print_home, verdict_style
from .workflows import (
    CandidateManifestError,
    LegacyAuthorizedDispatcher,
    build_candidate_manifest,
    load_candidate,
    request_identity,
    write_candidate_manifest,
)

_PROXY_ENVIRONMENT_VARIABLES = (
    "ALL_PROXY",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "NO_PROXY",
    "all_proxy",
    "https_proxy",
    "http_proxy",
    "no_proxy",
)
_TLS_ENVIRONMENT_VARIABLES = (
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "ssl_cert_file",
    "ssl_cert_dir",
)

EXIT_AUTHORIZATION_REJECTED = 20
EXIT_BUDGET_EXHAUSTED = 21
EXIT_PARTIAL_RUN = 22
EXIT_EVIDENCE_INTEGRITY = 23
EXIT_COMPARATOR_RESOURCE = 24


def _load_cfg_for_args(args):
    # args.no_config may not exist on some parsers; handle safely
    use_cfg = not getattr(args, "no_config", False)
    cfg_path = getattr(args, "config", None)
    return load_config(explicit_path=cfg_path, use_config=use_cfg)
    
def apply_cfg_list_default(args, key: str, cfg_value):
    """
    If args.<key> is empty ([], None), replace it with cfg_value (list).
    Preserves explicit CLI values.
    """
    if not hasattr(args, key):
        return
    cur = getattr(args, key)
    if cur is None:
        cur = []
    if isinstance(cur, list) and len(cur) == 0 and cfg_value:
        # ensure list
        if isinstance(cfg_value, (list, tuple)):
            setattr(args, key, list(cfg_value))
        else:
            setattr(args, key, [str(cfg_value)])


def apply_cfg_default(args, key: str, hard_default, cfg_value):
    """
    If args.<key> is still the hard_default, replace it with cfg_value.
    This preserves explicit CLI overrides.
    """
    if not hasattr(args, key):
        return
    if getattr(args, key) == hard_default and cfg_value is not None:
        setattr(args, key, cfg_value)

def _load_request(args) -> tuple[str, RawRequest]:
    """
    Returns (base_url, RawRequest)
    Priority:
      - if --request is provided: use it + --base-url
      - else use --url (and auto-derive base_url)
    """
    if getattr(args, "request", None):
        req = parse_raw_http_request_bytes(Path(args.request).read_bytes())
        if not getattr(args, "base_url", None):
            raise SystemExit("Error: when using --request, you must provide --base-url")
        return args.base_url, req

    if getattr(args, "url", None):
        extra_headers = []
        if getattr(args, "header", None):
            for hv in args.header:
                if ":" not in hv:
                    raise SystemExit(f"-H must be like 'Name: value' (got {hv!r})")
                k, v = hv.split(":", 1)
                extra_headers.append((k.strip(), v.lstrip()))

        body = b""
        if getattr(args, "data", None):
            body = args.data.encode("utf-8", errors="replace")

        method = getattr(args, "method", "GET")
        return build_request_from_url(args.url, method=method, headers=extra_headers, body=body)

    raise SystemExit("Error: provide either --request + --base-url OR --url")

def _emit_json_if_requested(args, payload) -> bool:
    if not getattr(args, "json", False):
        return False

    if isinstance(payload, dict) and getattr(args, "_network_role", None) == "exploration":
        payload.setdefault(
            "execution_policy",
            {
                "role": "exploration",
                "confirmatory": False,
                "selection_affects_statistical_interpretation": True,
                "authorization_digest": args._authorization_digest,
                "journal_head_digest": args._journal.head_digest,
            },
        )
        target = payload.get("target")
        if isinstance(target, dict) and {"base_url", "method", "path"}.issubset(target):
            redactor = args._redactor
            payload["target"] = redactor.target_metadata(
                str(target["base_url"]),
                RawRequest(str(target["method"]), str(target["path"]), "HTTP/1.1", [], b""),
            )
        if "pack_file" in payload:
            payload["pack_file_supplied"] = bool(payload.pop("pack_file"))

    # If --out is set, write JSON to file; else print to stdout
    out_path = getattr(args, "out_json", None)
    if out_path:
        _write_json_atomic(
            Path(out_path),
            payload,
            durable=getattr(args, "evidence_write", "normal") == "durable",
        )
    else:
        print_json(payload)

    return True


def _directory_sync_supported() -> bool:
    return os.name == "posix" and hasattr(os, "O_DIRECTORY")


def _write_json_atomic(destination: Path, payload: object, *, durable: bool) -> None:
    temporary = destination.with_name(f".{destination.name}.{uuid4().hex}.tmp")
    serialized = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as output:
            output.write(serialized)
            if durable:
                output.flush()
                os.fsync(output.fileno())
        os.replace(temporary, destination)
        if durable and _directory_sync_supported():
            directory_fd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def _source_commit() -> str | None:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=Path(__file__).resolve().parent.parent,
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    value = completed.stdout.strip().lower()
    return value if completed.returncode == 0 and len(value) == 40 else None


def _load_authorization_policy(path: str) -> ManifestAuthorizationPolicy:
    try:
        return ManifestAuthorizationPolicy(load_authorization_manifest(path))
    except (OSError, AuthorizationError, ValueError) as exc:
        raise SystemExit(f"Authorization rejected: {exc}") from exc


@contextmanager
def _legacy_network_scope(args: argparse.Namespace) -> Iterator[None]:
    run_id = uuid4().hex
    policy = _load_authorization_policy(args.authorization)
    try:
        limits = BudgetLimits.from_mapping(policy.manifest.budget)
        journal = EvidenceJournal(
            run_id=run_id,
            privacy="standard",
            path=args.journal,
            mode=args.evidence_write,
        )
    except (OSError, BudgetError, ValueError) as exc:
        raise SystemExit(f"Unable to initialize policy evidence: {exc}") from exc
    ledger = BudgetLedger(limits, journal)
    redactor = EvidenceRedactor(policy="standard")
    dispatcher = LegacyAuthorizedDispatcher(
        authorization=policy,
        budgets=ledger,
        evidence=journal,
        redactor=redactor,
    )
    args._network_role = "exploration"
    args._authorization_digest = policy.digest
    args._journal = journal
    args._redactor = redactor
    journal.record(
        "RUN_PLANNED",
        {
            "workflow": args.cmd,
            "role": "exploration",
            "manifest_digest": policy.digest,
        },
    )
    if not getattr(args, "json", False):
        console.print(
            "[warning]Exploratory workflow: candidate ranking is not confirmatory evidence.[/warning]"
        )
    try:
        with authorized_http_dispatch(dispatcher):
            yield
    except BaseException as exc:
        journal.record(
            "RUN_FAILED",
            {"stop_reason": "workflow-failure", "error_type": type(exc).__name__},
        )
        raise
    else:
        journal.record(
            "RUN_COMPLETED",
            {"verdict": "EXPLORATORY_OUTPUT", "stop_reason": "workflow-complete"},
        )
    finally:
        dispatcher.close()
        journal.close()


def cmd_authorization_validate(args: argparse.Namespace) -> int:
    policy = _load_authorization_policy(args.path)
    payload = {
        "valid": True,
        "authorization": policy.manifest.public_summary(),
        "budget": dict(policy.manifest.budget),
    }
    if args.json:
        print_json(payload)
    else:
        console.print("[success]Authorization manifest is valid.[/success]")
        console.print(f"Digest: {policy.digest}")
        console.print(f"Rules: {len(policy.manifest.rules)}")
        console.print(f"Expires: {policy.manifest.expires_at.isoformat()}")
    return 0


def cmd_evidence_verify(args: argparse.Namespace) -> int:
    result = verify_evidence(args.path)
    if args.json:
        print_json(result)
    else:
        console.print("[success]Evidence integrity and schema verification passed.[/success]")
        console.print(f"Type: {result['schema_version']}")
        if result.get("bundle_sha256"):
            console.print(f"Bundle: {result['bundle_sha256']}")
    return 0


def cmd_benchmark(args: argparse.Namespace) -> int:
    result = run_benchmark()
    if args.out_json:
        _write_json_atomic(Path(args.out_json), result, durable=False)
    if args.json:
        print_json(result)
    else:
        style = "success" if result["passed"] else "error"
        console.print(
            f"[{style}]Benchmark {'passed' if result['passed'] else 'failed'}:[/{style}] "
            f"{result['case_count']} cases, {result['request_cost']} authorized attempts"
        )
        for item in result["cases"]:
            marker = "PASS" if item["passed"] else "FAIL"
            console.print(
                f"{marker:4}  {item['name']}: {item['actual_verdict']} "
                f"(expected {item['expected_verdict']})"
            )
    return 0 if result["passed"] else 1


def _add_authorization_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--authorization",
        required=True,
        help="Path to a strict mrma.authorization/v1 manifest",
    )
    parser.add_argument(
        "--journal",
        required=True,
        help="New path for the append-only observation journal",
    )
    if not any(action.dest == "evidence_write" for action in parser._actions):
        parser.add_argument(
            "--evidence-write",
            choices=["normal", "durable"],
            default="normal",
            help="Journal write mode",
        )
    parser.set_defaults(_requires_authorization=True)


def _apply_assurance_preset(args: argparse.Namespace) -> str:
    preset = getattr(args, "assurance", None)
    if preset is None:
        return "custom"
    if preset == "exploratory":
        args.connection_mode = "reuse"
        args.state_mode = "isolated"
        args.retries = 0
        args.redaction_policy = "standard"
        args.body_storage = "sample"
    elif preset in {"research", "forensic"}:
        args.connection_mode = "fresh-observation"
        args.state_mode = "isolated"
        args.retries = 0
        args.redaction_policy = "forensic" if preset == "forensic" else "standard"
        args.body_storage = "full"
        args.schedule = "bracketed"
        args.rounds = 20
        args.trust_environment = False
    return preset


def _environment_snapshot(names: tuple[str, ...]) -> tuple[tuple[str, str | None], ...]:
    return tuple((name, os.environ.get(name)) for name in names)


def _present_environment(
    snapshot: tuple[tuple[str, str | None], ...],
    names: tuple[str, ...],
) -> dict[str, str]:
    selected = set(names)
    return {name: value for name, value in snapshot if name in selected and value}


def _transport_configuration(
    args: argparse.Namespace,
    redactor: EvidenceRedactor,
) -> tuple[
    str,
    str,
    dict[str, object],
    ssl.SSLContext | None,
    tuple[tuple[str, str | None], ...] | None,
]:
    environment_names = tuple(
        dict.fromkeys((*_PROXY_ENVIRONMENT_VARIABLES, *_TLS_ENVIRONMENT_VARIABLES))
    )
    environment_snapshot = (
        _environment_snapshot(environment_names) if args.trust_environment else None
    )
    proxy_environment = (
        _present_environment(environment_snapshot, _PROXY_ENVIRONMENT_VARIABLES)
        if environment_snapshot is not None
        else {}
    )
    tls_environment = (
        _present_environment(environment_snapshot, _TLS_ENVIRONMENT_VARIABLES)
        if environment_snapshot is not None
        else {}
    )
    ssl_context: ssl.SSLContext | None = None

    if args.insecure:
        tls_verification = "disabled"
        ca_fingerprint = None
    elif args.ca_bundle:
        ca_bytes = Path(args.ca_bundle).read_bytes()
        tls_verification = "custom-ca"
        ca_fingerprint = f"sha256:{hashlib.sha256(ca_bytes).hexdigest()}"
        ssl_context = ssl_context_from_ca_bytes(ca_bytes)
    elif tls_environment:
        tls_verification = "environment"
        ca_fingerprint = redactor.fingerprint(
            json.dumps(tls_environment, sort_keys=True),
            label="tls-environment",
        )
    else:
        tls_verification = "system"
        ca_fingerprint = None

    if args.proxy:
        proxy_mode = "explicit"
        proxy_source = "cli"
        endpoint_fingerprint = redactor.fingerprint(args.proxy, label="proxy-endpoint")
    elif proxy_environment:
        proxy_mode = "environment"
        proxy_source = "environment"
        endpoint_fingerprint = redactor.fingerprint(
            json.dumps(proxy_environment, sort_keys=True),
            label="proxy-environment",
        )
    else:
        proxy_mode = "none"
        proxy_source = "none"
        endpoint_fingerprint = None

    return (
        tls_verification,
        proxy_mode,
        {
            "trust_environment": args.trust_environment,
            "tls": {
                "verification": tls_verification,
                "ca_fingerprint": ca_fingerprint,
            },
            "proxy": {
                "mode": proxy_mode,
                "source": proxy_source,
                "endpoint_fingerprint": endpoint_fingerprint,
            },
        },
        ssl_context,
        environment_snapshot,
    )

def _apply_add_common(req, add_common: bool):
    if not add_common:
        return req
    out = req
    for k, v in common_headers():
        out = set_header(out, k, v, override=False)
    return out


def _apply_header_mutations(req: RawRequest, args) -> tuple[RawRequest, list[str], list[str]]:
    mutated = req
    removed = getattr(args, "remove_header", None) or []
    if isinstance(removed, str):
        removed = [removed]
    for name in removed:
        mutated = remove_header(mutated, name)

    set_names: list[str] = []
    for header in getattr(args, "set_header", None) or []:
        if ":" not in header:
            raise SystemExit(f"--set-header must be like 'Name: value' (got {header!r})")
        name, value = header.split(":", 1)
        name = name.strip()
        if not name:
            raise SystemExit("--set-header requires a non-empty header name")
        mutated = set_header(mutated, name, value.lstrip(), override=True)
        set_names.append(name)

    return mutated, list(removed), set_names


def _redacted_target_metadata(
    base_url: str,
    req: RawRequest,
    redactor: EvidenceRedactor | None = None,
) -> dict[str, object]:
    return (redactor or EvidenceRedactor()).target_metadata(base_url, req)


def _experiment_exit_code(verdict: str, fail_on: str) -> int:
    if fail_on in {"influence", "any-signal"} and verdict == "INFLUENCE_DETECTED":
        return 10
    if fail_on in {"inconclusive", "any-signal"} and verdict == "INCONCLUSIVE":
        return 11
    return 0

def cmd_config_show(args: argparse.Namespace) -> int:
    CFG = _load_cfg_for_args(args)
    paths = default_config_paths()
    payload = {
        "local_path": str(paths["local"]),
        "global_path": str(paths["global"]),
        "config": CFG,
    }

    if getattr(args, "json", False):
        print_json(payload)
        return 0

    console.print("[bold]Config paths[/bold]")
    console.print(f"local : {paths['local']}")
    console.print(f"global: {paths['global']}\n")
    console.print("[bold]Merged config[/bold]")
    console.print(payload["config"])
    return 0

def cmd_report(args: argparse.Namespace) -> int:
    # Always uses quick URL mode for v1
    if not args.url:
        raise SystemExit("Error: report requires --url")

    base_url, req = _load_request(args)

    # Apply config defaults like impact/run
    CFG = _load_cfg_for_args(args)
    rep_def = cfg_defaults(CFG, "impact")

    apply_cfg_default(args, "preset", "default", rep_def.get("preset"))
    apply_cfg_default(args, "min_similarity", 0.985, rep_def.get("min_similarity"))
    apply_cfg_default(args, "max_len_delta_ratio", 0.02, rep_def.get("max_len_delta_ratio"))
    apply_cfg_default(args, "delay", 0.0, rep_def.get("delay"))
    apply_cfg_default(args, "timeout", 15.0, rep_def.get("timeout"))
    ignore_headers = tuple(args.ignore_header or [])
    ignore_body_regex = tuple(args.ignore_body_regex or [])

    console.print(
        f"[dim]effective preset={args.preset} min_similarity={args.min_similarity} "
        f"max_len_delta_ratio={args.max_len_delta_ratio} delay={args.delay} timeout={args.timeout} "
        f"ignore_headers={len(ignore_headers)} ignore_body_regex={len(ignore_body_regex)}[/dim]"
    )

    opts = SendOptions(
        trust_env=False,
        timeout_s=args.timeout,
        follow_redirects=args.follow_redirects,
        verify_tls=(not args.insecure),
    )

    gate = RateGate()

    retry_status = tuple(
        int(x.strip())
        for x in (args.retry_status.split(",") if getattr(args, "retry_status", None) else [])
        if x.strip().isdigit()
    )

    policy = SendPolicy(
        delay_s=getattr(args, "delay", 0.0) or 0.0,
        rps=getattr(args, "rps", 0.0) or 0.0,
        retries=getattr(args, "retries", 0) or 0,
        retry_status=retry_status or (429, 502, 503, 504),
    )

    def sender(rq):
        return send_with_policy(
            lambda: send_raw_request(rq, base_url=base_url, opts=opts),
            policy=policy,
            gate=gate,
        )

    # Baseline
    resp = sender(req)
    fp = fingerprint_response(resp, ignore_headers=ignore_headers, ignore_body_regex=ignore_body_regex)

    baseline = {
        "status": fp.status_code,
        "body_length": fp.body_len,
        "body_sha256": fp.body_sha256,
        "important_headers": fp.headers,
    }

    # Impact (top-deltas)
    cfg = EquivalenceConfig(
        min_similarity=args.min_similarity,
        preset=args.preset,
        max_len_delta_ratio=args.max_len_delta_ratio,
        require_same_status=True,
        ignore_headers=ignore_headers,
        ignore_body_regex=ignore_body_regex,
    )
    muts = default_mutations()
    rows = run_impact(req, sender, cfg, muts)
    rows_sorted = sorted(rows, key=lambda r: r.similarity)[: args.top_deltas]

    impact = {
        "preset": args.preset,
        "thresholds": {
            "min_similarity": args.min_similarity,
            "max_len_delta_ratio": args.max_len_delta_ratio,
        },
        "rows": [
            {
                "mutation": r.name,
                "detail": r.detail,
                "verdict": "EQUIV" if r.equivalent else "CHANGED",
                "similarity": r.similarity,
                "status_base": r.status_base,
                "status_mut": r.status_mut,
                "len_base": r.len_base,
                "len_mut": r.len_mut,
            }
            for r in rows_sorted
        ],
    }

    # Profiles
    sec_findings = audit_security_headers({k.lower(): v for k, v in resp.headers.items()})
    ok = sum(1 for f in sec_findings if f.status == "OK")
    weak = sum(1 for f in sec_findings if f.status == "WEAK")
    missing = sum(1 for f in sec_findings if f.status == "MISSING")
    score = (weak * 1) + (missing * 2)

    security_headers = {
        "summary": {"ok": ok, "weak": weak, "missing": missing, "total": len(sec_findings), "score": score},
        "findings": [{"header": f.header, "status": f.status, "note": f.note} for f in sec_findings],
    }

    # proxy-trust
    cfg_profile = EquivalenceConfig(
        min_similarity=args.min_similarity,
        preset=args.preset,
        max_len_delta_ratio=args.max_len_delta_ratio,
        require_same_status=False,
        ignore_headers=ignore_headers,
        ignore_body_regex=ignore_body_regex,
    )
    proxy_cases = default_proxy_trust_cases(fake_host=args.fake_host)
    proxy_results = run_proxy_trust_profile(req, sender, cfg_profile, proxy_cases)
    proxy_trust = {
        "results": [
            {
                "case": r.name,
                "verdict": "EQUIV" if r.equivalent else "CHANGED",
                "similarity": r.similarity,
                "status_base": r.status_base,
                "status_case": r.status_case,
                "len_base": r.len_base,
                "len_case": r.len_case,
                "location_base": r.location_base,
                "location_case": r.location_case,
            }
            for r in proxy_results
        ]
    }

    # host-routing
    host_cases = default_host_routing_cases(fake_host=args.fake_host)
    host_results = run_host_routing_profile(req, sender, cfg_profile, host_cases)
    host_routing = {
        "results": [
            {
                "case": r.name,
                "verdict": "EQUIV" if r.equivalent else "CHANGED",
                "similarity": r.similarity,
                "status_base": r.status_base,
                "status_case": r.status_case,
                "len_base": r.len_base,
                "len_case": r.len_case,
                "location_base": r.location_base,
                "location_case": r.location_case,
            }
            for r in host_results
        ]
    }

    # Keep observed dimensions separate. These counts are not severity or exploitability.
    signals: list[str] = []
    if weak or missing:
        signals.append(f"security headers: {weak} weak, {missing} missing")

    changed_rows = [r for r in rows_sorted if not r.equivalent]
    if changed_rows:
        signals.append(f"impact: {len(changed_rows)} mutation(s) changed")
        for r in changed_rows[:5]:
            signals.append(f"impact changed: {r.name} sim={r.similarity:.4f} status={r.status_base}->{r.status_mut}")

    px_changed = [r for r in proxy_results if not r.equivalent]
    if px_changed:
        signals.append(f"proxy trust: {len(px_changed)} case(s) changed")
        for r in px_changed[:5]:
            loc = " loc-change" if (r.location_base != r.location_case) else ""
            signals.append(f"proxy-trust changed: {r.name} sim={r.similarity:.4f} status={r.status_base}->{r.status_case}{loc}")

    hr_changed = [r for r in host_results if not r.equivalent]
    if hr_changed:
        signals.append(f"host routing: {len(hr_changed)} case(s) changed")
        for r in hr_changed[:5]:
            loc = " loc-change" if (r.location_base != r.location_case) else ""
            signals.append(f"host-routing changed: {r.name} sim={r.similarity:.4f} status={r.status_base}->{r.status_case}{loc}")

    signal_summary = {
        "summary": (
            "Observed dimensions are reported separately. They are not a severity score, "
            "proof of exploitability, or proof of which infrastructure component made a decision."
        ),
        "signals": signals,
        "breakdown": {
            "security_headers_weak": weak,
            "security_headers_missing": missing,
            "impact_changed": len(changed_rows),
            "proxy_trust_changed": len(px_changed),
            "host_routing_changed": len(hr_changed),
        },
    }

    report = {
        "schema_version": "mrma.report/v2",
        "tool": {"name": "mrma", "version": __version__},
        "generated_at": utc_now_iso(),
        "target": {"url": args.url, "base_url": base_url, "method": req.method, "path": req.path},
        "signal_summary": signal_summary,
        "baseline": baseline,
        "impact": impact,
        "security_headers": security_headers,
        "proxy_trust": proxy_trust,
        "host_routing": host_routing,
    }

    # Write files
    out_json = args.out_json
    out_md = args.out_md
    Path(out_json).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8", errors="replace")
    Path(out_md).write_text(render_md_report(report), encoding="utf-8", errors="replace")

    console.print(f"[green]Wrote:[/green] {out_json}")
    console.print(f"[green]Wrote:[/green] {out_md}")
    return 0

def cmd_run(args: argparse.Namespace) -> int:

    base_url, req = _load_request(args)
    CFG = _load_cfg_for_args(args)
    run_def = cfg_defaults(CFG, "run")

    # apply config defaults only if user didn't override
    apply_cfg_default(args, "preset", "default", run_def.get("preset"))
    apply_cfg_default(args, "timeout", 15.0, run_def.get("timeout"))
    apply_cfg_default(args, "repeat", 1, run_def.get("repeat"))
    req = _apply_add_common(req, args.add_common)

    opts = SendOptions(
        trust_env=False,
        timeout_s=args.timeout,
        follow_redirects=args.follow_redirects,
        verify_tls=(not args.insecure),
    )

    def fetch_once():
        r = send_raw_request(req, base_url=base_url, opts=opts)
        return r.status_code, (r.content or b"")

    if args.repeat and args.repeat > 1:
        rep = measure_stability(fetch_once, repeats=args.repeat, preset=args.preset)
        payload = {
            "command": "run",
            "mode": "stability",
            "target": {"base_url": base_url, "method": req.method, "path": req.path},
            "preset": args.preset,
            "repeats": rep.repeats,
            "status_counts": rep.status_counts,
            "length_min": rep.min_len,
            "length_max": rep.max_len,
            "similarity_min": rep.sim_min,
            "similarity_avg": rep.sim_avg,
        }
        if _emit_json_if_requested(args, payload):
            return 0
            
        console.print(f"[bold]Stability[/bold] repeats={rep.repeats} preset={args.preset}")
        t = Table(show_header=True, header_style="bold")
        t.add_column("Metric")
        t.add_column("Value", overflow="fold")
        t.add_row("Status counts", str(rep.status_counts))
        t.add_row("Length min/max", f"{rep.min_len} / {rep.max_len}")
        t.add_row("Similarity min", f"{rep.sim_min:.4f}")
        t.add_row("Similarity avg", f"{rep.sim_avg:.4f}")
        console.print(t)
        return 0

    resp = send_raw_request(req, base_url=base_url, opts=opts)
    fp = fingerprint_response(resp, ignore_headers=tuple(getattr(args, "ignore_header", []) or []),
                              ignore_body_regex=tuple(getattr(args, "ignore_body_regex", []) or []))
    payload = {
        "command": "run",
        "mode": "baseline",
        "target": {"base_url": base_url, "method": req.method, "path": req.path},
        "status": fp.status_code,
        "body_length": fp.body_len,
        "body_sha256": fp.body_sha256,
        "important_headers": fp.headers,
    }
    if _emit_json_if_requested(args, payload):
        return 0

    console.print(f"[bold]Baseline[/bold] {req.method} {req.path}")
    table = Table(show_header=True, header_style="bold")
    table.add_column("Field")
    table.add_column("Value", overflow="fold")

    table.add_row("Status", str(fp.status_code))
    table.add_row("Body length", str(fp.body_len))
    table.add_row("Body sha256", fp.body_sha256)

    if fp.headers:
        for k, v in fp.headers.items():
            table.add_row(f"Header: {k}", v)

    console.print(table)
    return 0


def cmd_experiment(args: argparse.Namespace) -> int:
    base_url, req = _load_request(args)
    setup_hooks = tuple(
        parse_raw_http_request_bytes(Path(path).read_bytes())
        for path in args.setup_request
    )
    reset_hooks = tuple(
        parse_raw_http_request_bytes(Path(path).read_bytes())
        for path in args.reset_request
    )
    cfg_data = _load_cfg_for_args(args)
    defaults = cfg_defaults(cfg_data, "experiment")
    if args.rounds is None and defaults.get("rounds") is not None:
        args.rounds = int(defaults["rounds"])
    apply_cfg_default(args, "min_rounds", 6, defaults.get("min_rounds"))
    apply_cfg_default(args, "max_rounds", 20, defaults.get("max_rounds"))
    apply_cfg_default(args, "preset", "default", defaults.get("preset"))
    apply_cfg_default(args, "timeout", 15.0, defaults.get("timeout"))
    apply_cfg_default(
        args,
        "max_response_bytes",
        1024 * 1024,
        defaults.get("max_response_bytes"),
    )
    apply_cfg_default(args, "body_storage", "sample", defaults.get("body_storage"))
    apply_cfg_default(args, "state_mode", "isolated", defaults.get("state_mode"))
    apply_cfg_default(args, "connection_mode", "reuse", defaults.get("connection_mode"))
    apply_cfg_default(args, "schedule", "bracketed", defaults.get("schedule"))
    apply_cfg_default(args, "redaction_policy", "standard", defaults.get("redaction_policy"))
    apply_cfg_default(args, "min_similarity", 0.985, defaults.get("min_similarity"))
    apply_cfg_default(
        args,
        "max_len_delta_ratio",
        0.02,
        defaults.get("max_len_delta_ratio"),
    )
    apply_cfg_default(
        args,
        "min_reproducibility",
        0.8,
        defaults.get("min_reproducibility"),
    )
    apply_cfg_default(
        args,
        "no_influence_threshold",
        0.2,
        defaults.get("no_influence_threshold"),
    )
    apply_cfg_default(
        args,
        "max_control_change_rate",
        0.2,
        defaults.get("max_control_change_rate"),
    )
    apply_cfg_list_default(args, "ignore_header", defaults.get("ignore_headers"))
    apply_cfg_list_default(args, "ignore_body_regex", defaults.get("ignore_body_regex"))
    assurance_preset = _apply_assurance_preset(args)

    if args.trust_environment:
        raise SystemExit(
            "Error: v0.4 authorization-first transport rejects ambient HTTPX proxy/CA "
            "configuration; use explicit --proxy or --ca-bundle"
        )

    if args.rounds is not None and (
        args.rounds < 6
        or args.rounds > 50
        or (args.schedule == "balanced" and args.rounds % 2)
    ):
        raise SystemExit("Error: --rounds must be 6-50 and even for a balanced schedule")
    if args.rounds is None and (
        args.min_rounds < 6
        or args.max_rounds > 50
        or args.min_rounds > args.max_rounds
        or (args.schedule == "balanced" and args.min_rounds % 2)
        or (args.schedule == "balanced" and args.max_rounds % 2)
    ):
        raise SystemExit(
            "Error: round limits must be within 6-50 and even for a balanced schedule"
        )
    if args.schedule not in {"bracketed", "balanced"}:
        raise SystemExit("Error: schedule must be bracketed or balanced")
    if args.state_mode not in {"isolated", "per-arm", "shared-session"}:
        raise SystemExit("Error: state_mode must be isolated, per-arm, or shared-session")
    if args.connection_mode not in {"reuse", "per-arm", "per-round", "fresh-observation"}:
        raise SystemExit(
            "Error: connection_mode must be reuse, per-arm, per-round, or fresh-observation"
        )
    if args.body_storage not in {"none", "sample", "full"}:
        raise SystemExit("Error: body_storage must be none, sample, or full")
    if args.redaction_policy not in {"standard", "strict", "forensic"}:
        raise SystemExit("Error: redaction_policy must be standard, strict, or forensic")
    if args.insecure and args.ca_bundle:
        raise SystemExit("Error: --insecure cannot be combined with --ca-bundle")
    if args.allow_insecure_research and not args.insecure:
        raise SystemExit("Error: --allow-insecure-research requires --insecure")
    if (
        assurance_preset in {"research", "forensic"}
        and args.insecure
        and not args.allow_insecure_research
    ):
        raise SystemExit(
            "Error: research and forensic assurance reject --insecure; "
            "repeat with --allow-insecure-research to record an explicit exception"
        )
    if not 0.0 <= args.min_similarity <= 1.0:
        raise SystemExit("Error: --min-similarity must be between 0 and 1")
    if args.max_len_delta_ratio < 0.0:
        raise SystemExit("Error: --max-len-delta-ratio cannot be negative")
    if not 0.5 < args.min_reproducibility <= 1.0:
        raise SystemExit("Error: --min-reproducibility must be greater than 0.5 and at most 1")
    if not 0.0 <= args.no_influence_threshold < 0.5:
        raise SystemExit("Error: --no-influence-threshold must be at least 0 and less than 0.5")
    if args.no_influence_threshold >= args.min_reproducibility:
        raise SystemExit("Error: --no-influence-threshold must be below --min-reproducibility")
    if not 0.0 <= args.max_control_change_rate < 0.5:
        raise SystemExit("Error: --max-control-change-rate must be at least 0 and less than 0.5")
    if (
        args.timeout <= 0
        or args.delay < 0
        or args.rps < 0
        or args.retries < 0
        or args.max_response_bytes <= 0
    ):
        raise SystemExit("Error: timeout must be positive; delay, rps, and retries cannot be negative")
    if args.out_json and not args.json:
        raise SystemExit("Error: --out-json requires --json")
    if args.evidence_write == "durable" and not args.out_json:
        raise SystemExit("Error: --evidence-write durable requires --out-json")

    selected_candidate = None
    if args.candidate_manifest:
        if not args.candidate_id:
            raise SystemExit("Error: --candidate-manifest requires --candidate-id")
        if args.set_header or args.remove_header:
            raise SystemExit(
                "Error: candidate confirmation cannot be combined with ad hoc mutation flags"
            )
        try:
            selected_candidate = load_candidate(args.candidate_manifest, args.candidate_id)
        except CandidateManifestError as exc:
            raise SystemExit(f"Error: {exc}") from exc
        if selected_candidate.baseline_request_digest != request_identity(req):
            raise SystemExit("Error: candidate manifest does not bind to this baseline request")
        if assurance_preset not in {"research", "forensic"}:
            raise SystemExit("Error: candidate confirmation requires research or forensic assurance")
        if selected_candidate.remove_header is not None:
            args.remove_header = [selected_candidate.remove_header]
        else:
            assert selected_candidate.set_header is not None
            name, value = selected_candidate.set_header
            args.set_header = [f"{name}: {value}"]
    elif args.candidate_id:
        raise SystemExit("Error: --candidate-id requires --candidate-manifest")

    baseline = _apply_add_common(req, args.add_common)
    mutated, removed_headers, set_headers = _apply_header_mutations(baseline, args)
    if not removed_headers and not set_headers:
        raise SystemExit("Error: experiment requires --set-header and/or --remove-header")

    equivalence = EquivalenceConfig(
        min_similarity=args.min_similarity,
        max_len_delta_ratio=args.max_len_delta_ratio,
        require_same_status=(not args.allow_status_change),
        preset=args.preset,
        ignore_headers=tuple(args.ignore_header or []),
        ignore_body_regex=tuple(args.ignore_body_regex or []),
    )
    try:
        resolve_equivalence_policy(equivalence)
    except ValueError as exc:
        raise SystemExit(f"Error: {exc}") from exc
    redactor = EvidenceRedactor(policy=args.redaction_policy)
    try:
        (
            tls_verification,
            proxy_mode,
            transport_provenance,
            ssl_context,
            environment_snapshot,
        ) = _transport_configuration(args, redactor)
    except (OSError, ValueError) as exc:
        raise SystemExit(f"Error: unable to prepare --ca-bundle: {exc}") from exc
    if not args.json and args.redaction_policy == "forensic":
        console.print(
            "[warning]Forensic evidence preserves clear target paths and exact size/timing metadata.[/warning]"
        )
    if not args.json and args.state_mode == "shared-session":
        console.print(
            "[warning]Shared-session mode intentionally allows response cookies to cross observations.[/warning]"
        )
    experiment_cfg = ExperimentConfig(
        min_rounds=args.min_rounds,
        max_rounds=args.max_rounds,
        rounds=args.rounds,
        min_reproducibility=args.min_reproducibility,
        no_influence_threshold=args.no_influence_threshold,
        max_control_change_rate=args.max_control_change_rate,
        equivalence=equivalence,
        seed=args.seed,
        schedule_mode=args.schedule,
        state_mode=args.state_mode,
        connection_mode=args.connection_mode,
        max_response_bytes=args.max_response_bytes,
        body_storage=args.body_storage,
        response_header_scope=args.response_header_scope,
        include_response_headers=tuple(args.include_response_header),
        include_response_header_patterns=tuple(args.include_response_header_pattern),
        exclude_response_headers=tuple(args.exclude_response_header),
        response_header_profile=args.response_header_profile,
        stable_header_control_observations=args.stable_header_controls,
        assume_text_without_content_type=args.assume_text_without_content_type,
        trust_environment=args.trust_environment,
        tls_verification=tls_verification,
        proxy_mode=proxy_mode,
        assurance_preset=assurance_preset,
        redactor=redactor,
    )
    opts = SendOptions(
        timeout_s=args.timeout,
        follow_redirects=args.follow_redirects,
        verify_tls=(not args.insecure),
        trust_env=args.trust_environment,
        proxy=args.proxy,
        ssl_context=ssl_context,
        environment_snapshot=environment_snapshot,
    )
    retry_values = [value.strip() for value in args.retry_status.split(",") if value.strip()]
    if any(not value.isdigit() for value in retry_values):
        raise SystemExit("Error: --retry-status must be a comma-separated list of HTTP statuses")
    retry_status = tuple(int(value) for value in retry_values)
    send_policy = SendPolicy(
        delay_s=args.delay,
        rps=args.rps,
        retries=args.retries,
        retry_status=retry_status or (429, 502, 503, 504),
    )
    run_id = uuid4().hex
    started_at = utc_now_iso()
    timer = time.perf_counter()
    authorization = _load_authorization_policy(args.authorization)
    if (
        selected_candidate is not None
        and selected_candidate.authorization_digest != authorization.digest
    ):
        raise SystemExit("Error: candidate manifest was selected under different authorization")

    total_rounds = args.rounds or args.max_rounds
    requests_per_round = 3 if args.schedule == "bracketed" else 2
    characteristics = operating_characteristics(
        total_rounds,
        args.min_reproducibility,
        args.no_influence_threshold,
        args.max_control_change_rate,
        total_rounds if args.schedule == "bracketed" else total_rounds - 1,
    )
    if not args.json:
        positive = characteristics["positive_min_changed"]
        negative = characteristics["negative_max_changed"]
        console.print(
            f"[muted]Design preview:[/muted] {total_rounds} rounds / "
            f"{total_rounds * requests_per_round} requests; decisive influence requires "
            f"{positive}/{total_rounds} changed, no influence requires at most "
            f"{negative}/{total_rounds} changed."
        )

    journal = EvidenceJournal(
        run_id=run_id,
        privacy=args.redaction_policy,
        path=args.journal,
        mode=args.evidence_write,
    )
    budgets = BudgetLedger(BudgetLimits.from_mapping(authorization.manifest.budget), journal)
    transport = SemanticHttpAdapter(
        opts,
        journal=journal,
        state_mode=args.state_mode,
        connection_mode=args.connection_mode,
    )
    exploration_role = "confirmation" if assurance_preset in {"research", "forensic"} else "exploration"
    plan = ExperimentPlan(
        baseline=baseline,
        mutation=mutated,
        base_url=base_url,
        experiment=experiment_cfg,
        send=send_policy,
        follow_redirects=args.follow_redirects,
        mutation_family="header",
        mutation_risk_class="safe",
        exploration_role=exploration_role,
        candidate_manifest_digest=(
            selected_candidate.manifest_digest if selected_candidate is not None else None
        ),
        setup_hooks=setup_hooks,
        reset_hooks=reset_hooks,
    )
    oracle = ExperimentOracle(
        authorization=authorization,
        budgets=budgets,
        transport=transport,
        comparison=ComparisonPolicy(equivalence),
        evidence=journal,
    )

    if args.dry_run:
        try:
            summary = oracle.dry_run(plan)
            journal.record(
                "RUN_COMPLETED",
                {"verdict": "DRY_RUN_VALIDATED", "stop_reason": "plan-validation-complete"},
            )
        finally:
            journal.close()
        dry_payload = {
            "schema_version": "mrma.plan/v1",
            "valid": True,
            "network_attempts": 0,
            "authorization": authorization.manifest.public_summary(),
            "plan": summary.to_dict(),
            "journal": {
                "head_digest": journal.head_digest,
                "event_count": len(journal.events),
            },
        }
        if _emit_json_if_requested(args, dry_payload):
            return 0
        console.print("[success]Plan validated without networking.[/success]")
        console.print(f"Plan digest: {summary.plan_digest}")
        console.print(f"Maximum network attempts: {summary.maximum_attempts_with_redirects}")
        console.print(f"Maximum estimated request bytes: {summary.maximum_request_bytes}")
        console.print(f"Maximum response bytes: {summary.maximum_response_bytes}")
        return 0

    if args.json:
        oracle_result = oracle.run(plan)
    else:
        with console.status(
            "[signal]Running authorization-enforced control/mutation experiment[/signal]",
            spinner="dots12",
        ) as status:

            def update_progress(done: int, total: int, arm: str) -> None:
                status.update(
                    f"[signal]Collecting evidence[/signal]  {done}/{total}  [muted]{arm}[/muted]"
                )

            oracle_result = oracle.run(plan, on_progress=update_progress)
    journal.close()
    result = oracle_result.experiment

    duration_ms = round((time.perf_counter() - timer) * 1000, 3)
    completed_at = utc_now_iso()
    target_metadata = _redacted_target_metadata(base_url, baseline, redactor)
    result_payload = result.to_dict()
    payload = build_experiment_v7(
        oracle_result,
        plan=plan,
        authorization=authorization,
        budgets=budgets,
        journal=journal,
        run_id=run_id,
        started_at=started_at,
        completed_at=completed_at,
        duration_ms=duration_ms,
        transport_configuration=transport_provenance,
        source_commit=_source_commit(),
        insecure_exception=bool(args.insecure and args.allow_insecure_research),
    )
    if args.bundle:
        create_evidence_bundle(
            args.bundle,
            result=payload,
            journal_path=args.journal,
        )
    comparator_failed = any(pair.comparator_resource_limit for pair in result.pairs)
    if comparator_failed:
        exit_code = EXIT_COMPARATOR_RESOURCE
    elif oracle_result.status != "completed":
        exit_code = EXIT_PARTIAL_RUN
    else:
        exit_code = _experiment_exit_code(result.verdict, args.fail_on)
    if _emit_json_if_requested(args, payload):
        return exit_code

    style = verdict_style(result.verdict)
    heading = result.verdict.replace("_", " ")
    mutation_names = [f"set {name}" for name in set_headers]
    mutation_names.extend(f"remove {name}" for name in removed_headers)
    summary = Table.grid(expand=True)
    summary.add_column()
    summary.add_column(justify="right")
    summary.add_row(
        f"[{style}]{heading}[/{style}]",
        f"[bold]{assurance_preset.upper()} ASSURANCE POLICY[/bold]",
    )
    summary.add_row(
        f"[muted]{baseline.method} {target_metadata['path']}[/muted]",
        f"[muted]{', '.join(mutation_names)}[/muted]",
    )
    console.print(
        Panel(
            summary,
            title="[brand]MRMA EXPERIMENT[/brand]",
            border_style=style,
            box=box.SQUARE,
            padding=(0, 1),
        )
    )

    evidence = Table(box=box.SIMPLE_HEAD, show_edge=False, pad_edge=False, expand=True)
    evidence.add_column("SIGNAL", style="muted", width=24)
    evidence.add_column("OBSERVED", style="bold white", width=23)
    evidence.add_column("INTERPRETATION")
    low, high = result.mutation_change_interval_95
    evidence.add_row(
        "Mutation reproducibility",
        f"{result.mutation_changes}/{result.rounds} ({result.mutation_change_rate:.0%})",
        f"95% interval {low:.0%}-{high:.0%}; lower bound >= {args.min_reproducibility:.0%}",
    )
    control_low, control_high = result.control_change_interval_95
    evidence.add_row(
        "Control instability",
        f"{result.control_changes}/{result.control_comparisons} ({result.control_change_rate:.0%})",
        f"95% interval {control_low:.0%}-{control_high:.0%}; upper bound <= {args.max_control_change_rate:.0%}",
    )
    evidence.add_row(
        "Similarity contrast",
        f"{result.similarity_contrast:+.4f}" if result.similarity_contrast is not None else "n/a",
        "control median minus mutation median",
    )
    evidence.add_row(
        "Status shifts",
        f"{result.status_shift_rounds}/{result.rounds}",
        "paired control vs mutation",
    )
    evidence.add_row(
        "Incomplete body pairs",
        str(result.mutation_indeterminate),
        "never silently classified as equivalent",
    )
    console.print(evidence)

    assurance = Table(box=box.SIMPLE_HEAD, show_edge=False, pad_edge=False, expand=True)
    assurance.add_column("ASSURANCE DIMENSION", style="muted", width=28)
    assurance.add_column("ASSESSMENT", style="bold white")
    for name, value in result_payload["assurance_profile"].items():
        if name == "effect_types":
            value = ", ".join(value) if value else "none"
        assurance.add_row(name.replace("_", " ").title(), str(value))
    console.print(assurance)

    limitations = result_payload["limitations"]
    if limitations:
        codes = ", ".join(item["code"] for item in limitations)
        console.print(f"[warning]Declared limitations:[/warning] {codes}")

    if result.header_shift_counts:
        shifts = ", ".join(
            f"{name} {count}/{result.rounds}"
            for name, count in sorted(
                result.header_shift_counts.items(), key=lambda item: (-item[1], item[0])
            )
        )
        console.print(f"[muted]Response header evidence:[/muted] {shifts}")
    schedule_detail = (
        f"seed: {result.schedule_seed}" if result.schedule_seed is not None else "local brackets"
    )
    console.print(
        f"[muted]Stop: {result.stop_reason}  |  state: {args.state_mode}  |  "
        f"{schedule_detail}[/muted]"
    )
    console.print(f"[muted]Run {run_id[:12]}  |  mrma.experiment/v7  |  {duration_ms:.0f} ms[/muted]")
    return exit_code


def cmd_export(args: argparse.Namespace) -> int:
    base_url, req = _load_request(args)
    req = _apply_add_common(req, args.add_common)

    if args.format == "curl":
        out = to_curl(base_url, req)
    elif args.format == "raw":
        out = to_raw(req).rstrip()
    else:
        raise SystemExit(f"Unknown format: {args.format}")

    console.print(out)
    return 0
    
def cmd_pack_list(args: argparse.Namespace) -> int:
    packs = list_packs()
    console.print("[bold]Available packs[/bold]")
    t = Table(show_header=True, header_style="bold")
    t.add_column("Pack")
    t.add_column("Description", overflow="fold")
    for p in packs:
        t.add_row(p.name, p.description)
    console.print(t)
    return 0

def cmd_diff(args: argparse.Namespace) -> int:
    base_url, req = _load_request(args)
    CFG = _load_cfg_for_args(args)
    diff_def = cfg_defaults(CFG, "diff")
    apply_cfg_list_default(args, "ignore_header", diff_def.get("ignore_headers"))
    apply_cfg_list_default(args, "ignore_body_regex", diff_def.get("ignore_body_regex"))

    apply_cfg_default(args, "preset", "default", diff_def.get("preset"))
    apply_cfg_default(args, "min_similarity", 0.985, diff_def.get("min_similarity"))
    apply_cfg_default(args, "max_len_delta_ratio", 0.02, diff_def.get("max_len_delta_ratio"))
    opts = SendOptions(
        trust_env=False,
        timeout_s=args.timeout,
        follow_redirects=args.follow_redirects,
        verify_tls=(not args.insecure),
    )

    # Baseline
    base_resp = send_raw_request(req, base_url=base_url, opts=opts)
    base_body = base_resp.content or b""

    # Mutate (starting from the baseline request)
    mut = req
    mut = _apply_add_common(mut, args.add_common)

    if args.remove_header:
        mut = remove_header(mut, args.remove_header)

    if args.set_header:
        # supports repeated --set-header
        for hv in args.set_header:
            if ":" not in hv:
                raise SystemExit(f"--set-header must be like 'Name: value' (got {hv!r})")
            k, v = hv.split(":", 1)
            mut = set_header(mut, k.strip(), v.lstrip(), override=True)

    mut_resp = send_raw_request(mut, base_url=base_url, opts=opts)
    mut_body = mut_resp.content or b""

    base_sha = hashlib.sha256(base_body).hexdigest()
    mut_sha = hashlib.sha256(mut_body).hexdigest()

    cfg = EquivalenceConfig(
        min_similarity=args.min_similarity,
        preset=args.preset,
        max_len_delta_ratio=args.max_len_delta_ratio,
        require_same_status=(not args.allow_status_change),
        ignore_headers=tuple(args.ignore_header or []),
        ignore_body_regex=tuple(args.ignore_body_regex or []),
    )

    res = equivalent_response(
        base_resp.status_code,
        base_body,
        mut_resp.status_code,
        mut_body,
        cfg,
    )
    changed_headers = []
    for k in ["content-type", "cache-control", "vary", "location", "set-cookie", "server"]:
        bval = (base_resp.headers.get(k) or base_resp.headers.get(k.title()) or "")
        mval = (mut_resp.headers.get(k) or mut_resp.headers.get(k.title()) or "")
        if str(bval) != str(mval):
            changed_headers.append({"header": k, "baseline": str(bval), "mutated": str(mval)})

    payload = {
        "command": "diff",
        "target": {"base_url": base_url, "method": req.method, "path": req.path},
        "preset": args.preset,
        "thresholds": {
            "min_similarity": args.min_similarity,
            "max_len_delta_ratio": args.max_len_delta_ratio,
            "allow_status_change": bool(args.allow_status_change),
        },
        "verdict": "EQUIVALENT" if res.equivalent else "CHANGED",
        "baseline": {"status": res.status_a, "length": res.len_a, "sha256": base_sha},
        "mutated": {"status": res.status_b, "length": res.len_b, "sha256": mut_sha},
        "similarity": res.sim,
        "important_header_diffs": changed_headers,
    }
    if _emit_json_if_requested(args, payload):
        return 0

    verdict = "[green]EQUIVALENT[/green]" if res.equivalent else "[red]CHANGED[/red]"
    console.print(
        f"[dim]effective preset={args.preset} min_similarity={args.min_similarity} "
        f"max_len_delta_ratio={args.max_len_delta_ratio} "
        f"ignore_headers={len(getattr(args,'ignore_header',[]) or [])} "
        f"ignore_body_regex={len(getattr(args,'ignore_body_regex',[]) or [])}[/dim]"
    )
    console.print(f"[bold]Diff[/bold] {verdict}")

    table = Table(show_header=True, header_style="bold")
    table.add_column("Metric")
    table.add_column("Baseline")
    table.add_column("Mutated")

    table.add_row("Status", str(res.status_a), str(res.status_b))
    table.add_row("Body length", str(res.len_a), str(res.len_b))
    table.add_row("Body sha256", base_sha, mut_sha)
    table.add_row("Similarity", f"{res.sim:.4f}", f"{res.sim:.4f}")

    console.print(table)

    important = ["content-type", "cache-control", "vary", "location", "server"]
    if args.show_set_cookie:
        important.append("set-cookie")

    bh = {k.lower(): v for k, v in base_resp.headers.items()}
    mh = {k.lower(): v for k, v in mut_resp.headers.items()}

    ht = Table(title="Important response headers (baseline vs mutated)", show_header=True, header_style="bold")
    ht.add_column("Header")
    ht.add_column("Baseline", overflow="fold")
    ht.add_column("Mutated", overflow="fold")

    for k in important:
        bval = bh.get(k, "")
        mval = mh.get(k, "")
        if bval != mval:
            ht.add_row(k, bval, mval)

    console.print(ht)

    return 0


def cmd_discover(args: argparse.Namespace) -> int:
    base_url, req = _load_request(args)
    CFG = _load_cfg_for_args(args)
    disc_def = cfg_defaults(CFG, "discover")

    apply_cfg_default(args, "preset", "default", disc_def.get("preset"))
    apply_cfg_default(args, "min_similarity", 0.985, disc_def.get("min_similarity"))
    apply_cfg_default(args, "max_len_delta_ratio", 0.02, disc_def.get("max_len_delta_ratio"))
    apply_cfg_default(args, "timeout", 15.0, disc_def.get("timeout"))

    opts = SendOptions(
        trust_env=False,
        timeout_s=args.timeout,
        follow_redirects=args.follow_redirects,
        verify_tls=(not args.insecure),
    )

    gate = RateGate()

    retry_status = tuple(
        int(x.strip())
        for x in (args.retry_status.split(",") if getattr(args, "retry_status", None) else [])
        if x.strip().isdigit()
    )

    policy = SendPolicy(
        delay_s=getattr(args, "delay", 0.0) or 0.0,
        rps=getattr(args, "rps", 0.0) or 0.0,
        retries=getattr(args, "retries", 0) or 0,
        retry_status=retry_status or (429, 502, 503, 504),
    )

    def sender(rq):
        return send_with_policy(
            lambda: send_raw_request(rq, base_url=base_url, opts=opts),
            policy=policy,
            gate=gate,
        )

    protected = set()
    if not args.include_auth:
        protected |= {"cookie", "authorization", "x-csrf-token", "x-xsrf-token"}

    cfg = EquivalenceConfig(
        min_similarity=args.min_similarity,
        preset=args.preset,
        max_len_delta_ratio=args.max_len_delta_ratio,
        require_same_status=True,
    )

    result = discover_required_headers(
        original=req,
        sender=sender,
        cfg=cfg,
        protected_names=protected,
        chunk_start=args.chunk_start,
    )
    payload = {
        "command": "discover",
        "target": {"base_url": base_url, "method": req.method, "path": req.path},
        "preset": args.preset,
        "requests_sent": result.requests_sent,
        "implicit": [{"header": k, "value": v} for k, v in result.implicit],
        "required": [{"header": k, "value": v} for k, v in result.required],
        "optional": [{"header": k, "value": v} for k, v in result.optional],
    }

    if args.print_minimal_request or args.out:
        minimal_headers = []
        minimal_headers.extend(result.implicit)
        minimal_headers.extend(result.required)
        payload["minimal_request"] = render_raw_request(
            req.method, req.path, minimal_headers, body=None
        ).rstrip()

    if _emit_json_if_requested(args, payload):
        # If --out is set, still write the file
        if args.out:
            Path(args.out).write_text(
                payload.get("minimal_request", "") + "\n",
                encoding="utf-8",
                errors="replace",
            )
        return 0

    console.print(f"[dim]effective preset={args.preset} min_similarity={args.min_similarity} max_len_delta_ratio={args.max_len_delta_ratio} timeout={args.timeout}[/dim]")
    console.print(f"[bold]Discover[/bold] requests_sent={result.requests_sent}")

    # Print implicit first
    if result.implicit:
        t0 = Table(
            title="Implicit headers (client will auto-send)",
            show_header=True,
            header_style="bold",
        )
        t0.add_column("Header")
        t0.add_column("Value", overflow="fold")
        for k, v in result.implicit:
            t0.add_row(k, v)
        console.print(t0)

    t1 = Table(title="Required headers", show_header=True, header_style="bold")
    t1.add_column("Header")
    t1.add_column("Value", overflow="fold")
    for k, v in result.required:
        t1.add_row(k, v)
    console.print(t1)

    t2 = Table(title="Optional headers (removable)", show_header=True, header_style="bold")
    t2.add_column("Header")
    t2.add_column("Value", overflow="fold")
    for k, v in result.optional:
        t2.add_row(k, v)
    console.print(t2)

    # Minimal raw request rendering / output
    if args.print_minimal_request or args.out:
        minimal_headers = []
        # Always include Host (implicit), if present
        minimal_headers.extend(result.implicit)
        # Include required headers (explicit)
        minimal_headers.extend(result.required)

        raw = render_raw_request(req.method, req.path, minimal_headers, body=None)

        if args.print_minimal_request:
            console.print("\n[bold]Minimal request[/bold]")
            console.print(raw.rstrip())

        if args.out:
            Path(args.out).write_text(raw, encoding="utf-8", errors="replace")
            console.print(f"[green]Wrote:[/green] {args.out}")

    return 0

def cmd_isolate(args: argparse.Namespace) -> int:
    base_url, req = _load_request(args)
    CFG = _load_cfg_for_args(args)
    iso_def = cfg_defaults(CFG, "isolate")

    apply_cfg_default(args, "preset", "default", iso_def.get("preset"))
    apply_cfg_default(args, "min_similarity", 0.985, iso_def.get("min_similarity"))
    apply_cfg_default(args, "max_len_delta_ratio", 0.02, iso_def.get("max_len_delta_ratio"))
    apply_cfg_default(args, "timeout", 15.0, iso_def.get("timeout"))

    opts = SendOptions(
        trust_env=False,
        timeout_s=args.timeout,
        follow_redirects=args.follow_redirects,
        verify_tls=(not args.insecure),
    )

    gate = RateGate()

    retry_status = tuple(
        int(x.strip())
        for x in (args.retry_status.split(",") if getattr(args, "retry_status", None) else [])
        if x.strip().isdigit()
    )

    policy = SendPolicy(
        delay_s=getattr(args, "delay", 0.0) or 0.0,
        rps=getattr(args, "rps", 0.0) or 0.0,
        retries=getattr(args, "retries", 0) or 0,
        retry_status=retry_status or (429, 502, 503, 504),
    )

    def sender(rq):
        return send_with_policy(
            lambda: send_raw_request(rq, base_url=base_url, opts=opts),
            policy=policy,
            gate=gate,
        )

    cfg = EquivalenceConfig(
        min_similarity=args.min_similarity,
        preset=args.preset,
        max_len_delta_ratio=args.max_len_delta_ratio,
        require_same_status=True,
    )

    to_add = []
    if args.pack_file_mode == "remove":
        raise SystemExit("Error: isolate currently supports --pack-file-mode set only (adding headers). Use impact with --pack-file-mode remove.")

    if args.pack_file:
        muts = parse_pack_file(args.pack_file, mode=args.pack_file_mode)
        for m in muts:
            if m.set_header:
                to_add.append(m.set_header)
    else:
        if args.pack:
            # Convert pack mutations into headers-to-add (only those that set headers)
            muts = mutations_for_pack(args.pack, depth=args.depth, ipset=args.ip_set)
            for m in muts:
                if m.set_header:
                    to_add.append(m.set_header)

        elif args.add_common:
            to_add = common_headers()

    if args.add_header:
        # allow repeating --add-header "Name: value"
        for hv in args.add_header:
            if ":" not in hv:
                raise SystemExit(f"--add-header must be like 'Name: value' (got {hv!r})")
            k, v = hv.split(":", 1)
            to_add.append((k.strip(), v.lstrip()))

    res = isolate_added_headers(
        baseline_req=req,
        sender=sender,
        cfg=cfg,
        headers_to_add=to_add,
        ddmin_start=args.ddmin_start,
    )
    payload = {
        "command": "isolate",
        "mode": "add",
        "target": {"base_url": base_url, "method": req.method, "path": req.path},
        "preset": args.preset,
        "requests_sent": res.requests_sent,
        "culprit_headers": [{"header": k, "value": v} for k, v in res.culprit_headers],
    }
    if _emit_json_if_requested(args, payload):
        return 0

    console.print(f"[dim]effective preset={args.preset} min_similarity={args.min_similarity} max_len_delta_ratio={args.max_len_delta_ratio} timeout={args.timeout}[/dim]")
    console.print(f"[bold]Isolate[/bold] requests_sent={res.requests_sent}")
    if not res.culprit_headers:
        console.print("[green]Result:[/green] No header subset caused a change (all tested headers were equivalent).")
        return 0

    t = Table(title="Minimal header subset that causes change", show_header=True, header_style="bold")
    t.add_column("Header")
    t.add_column("Value", overflow="fold")
    for k, v in res.culprit_headers:
        t.add_row(k, v)

    console.print(t)
    return 0

def cmd_isolate_remove(args: argparse.Namespace) -> int:
    base_url, req = _load_request(args)
    CFG = _load_cfg_for_args(args)
    isr_def = cfg_defaults(CFG, "isolate_remove")

    apply_cfg_default(args, "preset", "default", isr_def.get("preset"))
    apply_cfg_default(args, "min_similarity", 0.985, isr_def.get("min_similarity"))
    apply_cfg_default(args, "max_len_delta_ratio", 0.02, isr_def.get("max_len_delta_ratio"))
    apply_cfg_default(args, "timeout", 15.0, isr_def.get("timeout"))
    apply_cfg_default(args, "delay", 0.0, isr_def.get("delay"))

    opts = SendOptions(
        trust_env=False,
        timeout_s=args.timeout,
        follow_redirects=args.follow_redirects,
        verify_tls=(not args.insecure),
    )

    gate = RateGate()

    retry_status = tuple(
        int(x.strip())
        for x in (args.retry_status.split(",") if getattr(args, "retry_status", None) else [])
        if x.strip().isdigit()
    )

    policy = SendPolicy(
        delay_s=getattr(args, "delay", 0.0) or 0.0,
        rps=getattr(args, "rps", 0.0) or 0.0,
        retries=getattr(args, "retries", 0) or 0,
        retry_status=retry_status or (429, 502, 503, 504),
    )

    def sender(rq):
        return send_with_policy(
            lambda: send_raw_request(rq, base_url=base_url, opts=opts),
            policy=policy,
            gate=gate,
        )

    cfg = EquivalenceConfig(
        min_similarity=args.min_similarity,
        preset=args.preset,
        max_len_delta_ratio=args.max_len_delta_ratio,
        require_same_status=True,
        ignore_headers=tuple(args.ignore_header or []),
        ignore_body_regex=tuple(args.ignore_body_regex or []),
    )

    # Build headers_to_remove from pack-file (required)
    if not args.pack_file:
        raise SystemExit("Error: isolate-remove requires --pack-file containing header names (or Header: value lines).")

    muts = parse_pack_file(args.pack_file, mode="remove")
    headers_to_remove = [m.remove for m in muts if m.remove]

    res = isolate_removed_headers(
        baseline_req=req,
        sender=sender,
        cfg=cfg,
        headers_to_remove=headers_to_remove,
        ddmin_start=args.ddmin_start,
    )
    payload = {
        "command": "isolate-remove",
        "mode": "remove",
        "target": {"base_url": base_url, "method": req.method, "path": req.path},
        "preset": args.preset,
        "requests_sent": res.requests_sent,
        "culprit_removals": res.culprit_removals,
    }
    if _emit_json_if_requested(args, payload):
        return 0

    console.print(f"[dim]effective preset={args.preset} min_similarity={args.min_similarity} max_len_delta_ratio={args.max_len_delta_ratio} timeout={args.timeout} delay={args.delay}[/dim]")
    console.print(f"[bold]Isolate-remove[/bold] requests_sent={res.requests_sent}")

    if not res.culprit_removals:
        console.print("[green]Result:[/green] Removing the provided headers did NOT cause a change.")
        return 0

    t = Table(title="Minimal header removals that cause change", show_header=True, header_style="bold")
    t.add_column("Header")
    for h in res.culprit_removals:
        t.add_row(h)

    console.print(t)
    return 0

def cmd_impact(args: argparse.Namespace) -> int:
    base_url, req = _load_request(args)
    CFG = _load_cfg_for_args(args)
    imp_def = cfg_defaults(CFG, "impact")
    apply_cfg_list_default(args, "ignore_header", imp_def.get("ignore_headers"))
    apply_cfg_list_default(args, "ignore_body_regex", imp_def.get("ignore_body_regex"))

    apply_cfg_default(args, "preset", "default", imp_def.get("preset"))
    apply_cfg_default(args, "min_similarity", 0.985, imp_def.get("min_similarity"))
    apply_cfg_default(args, "max_len_delta_ratio", 0.02, imp_def.get("max_len_delta_ratio"))
    apply_cfg_default(args, "delay", 0.0, imp_def.get("delay"))
    apply_cfg_default(args, "ip_set", "basic", imp_def.get("ip_set"))
    apply_cfg_default(args, "depth", "basic", imp_def.get("depth"))
    apply_cfg_default(args, "pack_file_mode", "set", imp_def.get("pack_file_mode"))

    opts = SendOptions(
        trust_env=False,
        timeout_s=args.timeout,
        follow_redirects=args.follow_redirects,
        verify_tls=(not args.insecure),
    )

    gate = RateGate()

    # parse retry statuses
    retry_status = tuple(int(x.strip()) for x in (args.retry_status.split(",") if args.retry_status else []) if x.strip().isdigit())

    policy = SendPolicy(
        delay_s=args.delay,
        rps=getattr(args, "rps", 0.0) or 0.0,
        retries=getattr(args, "retries", 0) or 0,
        retry_status=retry_status or (429, 502, 503, 504),
    )

    def sender(rq):
        return send_with_policy(
            lambda: send_raw_request(rq, base_url=base_url, opts=opts),
            policy=policy,
            gate=gate,
        )

    cfg = EquivalenceConfig(
        min_similarity=args.min_similarity,
        preset=args.preset,
        max_len_delta_ratio=args.max_len_delta_ratio,
        require_same_status=(not args.allow_status_change),
        ignore_headers=tuple(args.ignore_header or []),
        ignore_body_regex=tuple(args.ignore_body_regex or []),
    )

    if args.pack_file:
        muts = parse_pack_file(args.pack_file, mode=args.pack_file_mode)
    elif args.pack:
        muts = mutations_for_pack(args.pack, depth=args.depth, ipset=args.ip_set)
    else:
        muts = default_mutations()

    rows = run_impact(req, sender, cfg, muts)
    rank_by_name = {row.name: rank for rank, row in enumerate(rows, start=1)}
    candidate_manifest = build_candidate_manifest(
        req,
        muts,
        authorization_digest=args._authorization_digest,
        rank_by_name=rank_by_name,
    )
    candidate_path = Path(args.candidate_out) if args.candidate_out else Path(
        args.journal
    ).with_suffix(".candidates.json")
    try:
        write_candidate_manifest(candidate_path, candidate_manifest)
    except (OSError, CandidateManifestError) as exc:
        raise SystemExit(f"Error: unable to write candidate manifest: {exc}") from exc
    candidate_summary = {
        "schema_version": candidate_manifest["schema_version"],
        "digest": candidate_manifest["digest"],
        "candidate_count": len(candidate_manifest["candidates"]),
        "selection_affects_statistical_interpretation": True,
        "confirmatory": False,
    }
    if not args.json:
        console.print(
            f"[muted]Candidate manifest: {candidate_path} ({candidate_manifest['digest']})[/muted]"
        )

    def _impact_rows_to_json(rows_):
        return [
            {
                "mutation": r.name,
                "detail": r.detail,
                "verdict": "EQUIV" if r.equivalent else "CHANGED",
                "similarity": r.similarity,
                "status_base": r.status_base,
                "status_mut": r.status_mut,
                "len_base": r.len_base,
                "len_mut": r.len_mut,
            }
            for r in rows_
        ]
    
    # If user wants top deltas, sort by lowest similarity first and show N
    if args.top_deltas and args.top_deltas > 0:
        rows_sorted = sorted(rows, key=lambda r: r.similarity)
        rows = rows_sorted[: args.top_deltas]
        
        payload = {
            "command": "impact",
            "target": {"base_url": base_url, "method": req.method, "path": req.path},
            "preset": args.preset,
            "pack": args.pack,
            "depth": getattr(args, "depth", None),
            "ip_set": getattr(args, "ip_set", None),
            "pack_file": getattr(args, "pack_file", None),
            "pack_file_mode": getattr(args, "pack_file_mode", None),
            "mode": "top-deltas",
            "thresholds": {
                "min_similarity": args.min_similarity,
                "max_len_delta_ratio": args.max_len_delta_ratio,
                "allow_status_change": bool(args.allow_status_change),
            },
            "candidate_manifest": candidate_summary,
            "rows": _impact_rows_to_json(rows),
        }
        if _emit_json_if_requested(args, payload):
            return 0
        console.print(
            f"[dim]effective preset={args.preset} min_similarity={args.min_similarity} "
            f"max_len_delta_ratio={args.max_len_delta_ratio} delay={args.delay} "
            f"ignore_headers={len(getattr(args,'ignore_header',[]) or [])} "
            f"ignore_body_regex={len(getattr(args,'ignore_body_regex',[]) or [])}[/dim]"
        )
        # Print table and exit (ignores --only-changed)
        console.print("[bold]Impact (top deltas)[/bold] (showing most different even if equivalent)")
        t = Table(show_header=True, header_style="bold")
        t.add_column("Mutation")
        t.add_column("Detail", overflow="fold")
        t.add_column("Verdict")
        t.add_column("Similarity")
        t.add_column("Status")
        t.add_column("Len (base→mut)")

        for r in rows:
            verdict = "[green]EQUIV[/green]" if r.equivalent else "[red]CHANGED[/red]"
            t.add_row(
                r.name,
                r.detail,
                verdict,
                f"{r.similarity:.4f}",
                f"{r.status_base}->{r.status_mut}",
                f"{r.len_base}->{r.len_mut}",
            )

        console.print(t)
        status_flips = [r for r in rows if r.status_base != r.status_mut]
        if status_flips:
            console.print(f"[red]Warning:[/red] {len(status_flips)} mutation(s) changed HTTP status (possible WAF/CDN behavior or trust).")
        waf_like = [r for r in rows if r.status_mut in (401, 403, 406, 429)]
        if waf_like:
            console.print("[yellow]Note:[/yellow] Some status changes look like WAF/challenge responses (401/403/406/429). Treat as detection signal, not a bypass.")
        return 0
  
    if args.only_changed:
        rows = [r for r in rows if not r.equivalent]
    
    if args.only_changed and not rows:
        console.print("[yellow]No mutations produced a CHANGED verdict with current thresholds.[/yellow]")
        console.print("Try: --min-similarity 0.95  --max-len-delta-ratio 0.10")
        return 0

    if args.top and args.top > 0:
        rows = rows[: args.top]
    
    payload = {
        "command": "impact",
        "target": {"base_url": base_url, "method": req.method, "path": req.path},
        "preset": args.preset,
        "pack": args.pack,
        "depth": getattr(args, "depth", None),
        "ip_set": getattr(args, "ip_set", None),
        "pack_file": getattr(args, "pack_file", None),
        "pack_file_mode": getattr(args, "pack_file_mode", None),
        "mode": "only-changed" if args.only_changed else "all",
        "thresholds": {
            "min_similarity": args.min_similarity,
            "max_len_delta_ratio": args.max_len_delta_ratio,
            "allow_status_change": bool(args.allow_status_change),
        },
        "candidate_manifest": candidate_summary,
        "rows": _impact_rows_to_json(rows),
    }
    if _emit_json_if_requested(args, payload):
        return 0

    console.print("[bold]Impact[/bold] (sorted: most changed first)")
    t = Table(show_header=True, header_style="bold")
    t.add_column("Mutation")
    t.add_column("Detail", overflow="fold")
    t.add_column("Verdict")
    t.add_column("Similarity")
    t.add_column("Status")
    t.add_column("Len (base→mut)")

    for r in rows:
        verdict = "[green]EQUIV[/green]" if r.equivalent else "[red]CHANGED[/red]"
        t.add_row(
            r.name,
            r.detail,
            verdict,
            f"{r.similarity:.4f}",
            f"{r.status_base}->{r.status_mut}",
            f"{r.len_base}->{r.len_mut}",
        )

    console.print(t)
    status_flips = [r for r in rows if r.status_base != r.status_mut]
    if status_flips:
        console.print(f"[red]Warning:[/red] {len(status_flips)} mutation(s) changed HTTP status (possible WAF/CDN behavior or trust).")
    waf_like = [r for r in rows if r.status_mut in (401, 403, 406, 429)]
    if waf_like:
        console.print("[yellow]Note:[/yellow] Some status changes look like WAF/challenge responses (401/403/406/429). Treat as detection signal, not a bypass.")
    return 0

def cmd_profile_security_headers(args: argparse.Namespace) -> int:
    base_url, req = _load_request(args)
    CFG = _load_cfg_for_args(args)
    sec_def = cfg_defaults(CFG, "security_headers")

    apply_cfg_default(args, "preset", "default", sec_def.get("preset"))
    apply_cfg_default(args, "timeout", 15.0, sec_def.get("timeout"))
    req = _apply_add_common(req, args.add_common)

    opts = SendOptions(
        trust_env=False,
        timeout_s=args.timeout,
        follow_redirects=args.follow_redirects,
        verify_tls=(not args.insecure),
    )

    resp = send_raw_request(req, base_url=base_url, opts=opts)

    # Normalize headers to lowercase dict
    norm = {k.lower(): v for k, v in resp.headers.items()}

    findings = audit_security_headers(norm)

    # Compute summary counts + score (needed for JSON payload)
    ok = weak = missing = 0
    for f in findings:
        if f.status == "OK":
            ok += 1
        elif f.status == "WEAK":
            weak += 1
        else:
            missing += 1
    score = (weak * 1) + (missing * 2)

    # JSON output (if requested) before any human-oriented printing
    payload = {
        "command": "profile",
        "profile": "security-headers",
        "target": {"base_url": base_url, "method": req.method, "path": req.path},
        "status": resp.status_code,
        "summary": {
            "ok": ok,
            "weak": weak,
            "missing": missing,
            "total": len(findings),
            "score": score,
        },
        "findings": [{"header": f.header, "status": f.status, "note": f.note} for f in findings],
    }
    if _emit_json_if_requested(args, payload):
        return 0
    console.print(f"[dim]effective preset={args.preset} timeout={args.timeout}[/dim]")
    console.print(f"[bold]Profile: security-headers[/bold] status={resp.status_code}")

    t = Table(show_header=True, header_style="bold")
    t.add_column("Header")
    t.add_column("Status")
    t.add_column("Note", overflow="fold")

    for f in findings:
        if f.status == "OK":
            s = "[green]OK[/green]"
        elif f.status == "WEAK":
            s = "[yellow]WEAK[/yellow]"
        else:
            s = "[red]MISSING[/red]"
        t.add_row(f.header, s, f.note)

    console.print(t)
    console.print(f"[bold]Summary[/bold] ok={ok} weak={weak} missing={missing} total={len(findings)}")
    console.print(f"[bold]Score[/bold] {score} (0 is best)")
    return 0

def cmd_profile_proxy_trust(args: argparse.Namespace) -> int:
    base_url, req = _load_request(args)
    CFG = _load_cfg_for_args(args)
    px_def = cfg_defaults(CFG, "proxy_trust")

    apply_cfg_default(args, "preset", "default", px_def.get("preset"))
    apply_cfg_default(args, "min_similarity", 0.985, px_def.get("min_similarity"))
    apply_cfg_default(args, "max_len_delta_ratio", 0.02, px_def.get("max_len_delta_ratio"))
    apply_cfg_default(args, "timeout", 15.0, px_def.get("timeout"))

    opts = SendOptions(
        trust_env=False,
        timeout_s=args.timeout,
        follow_redirects=args.follow_redirects,
        verify_tls=(not args.insecure),
    )

    gate = RateGate()

    retry_status = tuple(
        int(x.strip())
        for x in (args.retry_status.split(",") if getattr(args, "retry_status", None) else [])
        if x.strip().isdigit()
    )

    policy = SendPolicy(
        delay_s=getattr(args, "delay", 0.0) or 0.0,
        rps=getattr(args, "rps", 0.0) or 0.0,
        retries=getattr(args, "retries", 0) or 0,
        retry_status=retry_status or (429, 502, 503, 504),
    )

    def sender(rq):
        return send_with_policy(
            lambda: send_raw_request(rq, base_url=base_url, opts=opts),
            policy=policy,
            gate=gate,
        )

    cfg = EquivalenceConfig(
        min_similarity=args.min_similarity,
        preset=args.preset,
        max_len_delta_ratio=args.max_len_delta_ratio,
        require_same_status=False,  # proxy influence might legitimately change status
        ignore_headers=tuple(args.ignore_header or []),
        ignore_body_regex=tuple(args.ignore_body_regex or []),
    )

    cases = default_proxy_trust_cases(fake_host=args.fake_host)
    results = run_proxy_trust_profile(req, sender, cfg, cases)
    payload = {
        "command": "profile",
        "profile": "proxy-trust",
        "target": {"base_url": base_url, "method": req.method, "path": req.path},
        "preset": args.preset,
        "results": [
            {
                "case": r.name,
                "verdict": "EQUIV" if r.equivalent else "CHANGED",
                "similarity": r.similarity,
                "status_base": r.status_base,
                "status_case": r.status_case,
                "len_base": r.len_base,
                "len_case": r.len_case,
                "location_base": r.location_base,
                "location_case": r.location_case,
                "changed_headers": [
                    {"header": h, "baseline": b, "case": c}
                    for (h, b, c) in r.changed_headers
                ],
            }
            for r in results
        ],
    }
    if _emit_json_if_requested(args, payload):
        return 0
    
    console.print(
        f"[dim]effective preset={args.preset} min_similarity={args.min_similarity} "
        f"max_len_delta_ratio={args.max_len_delta_ratio} timeout={args.timeout} "
        f"ignore_headers={len(getattr(args,'ignore_header',[]) or [])} "
        f"ignore_body_regex={len(getattr(args,'ignore_body_regex',[]) or [])}[/dim]"
    )
    console.print("[bold]Profile: proxy-trust[/bold]")
    t = Table(show_header=True, header_style="bold")
    t.add_column("Case")
    t.add_column("Verdict")
    t.add_column("Similarity")
    t.add_column("Status")
    t.add_column("Location change")
    t.add_column("Len (base→case)")

    for r in results:
        verdict = "[green]EQUIV[/green]" if r.equivalent else "[red]CHANGED[/red]"
        loc_change = "no"
        if (r.location_base or r.location_case) and (r.location_base != r.location_case):
            loc_change = "[yellow]yes[/yellow]"
        t.add_row(
            r.name,
            verdict,
            f"{r.similarity:.4f}",
            f"{r.status_base}->{r.status_case}",
            loc_change,
            f"{r.len_base}->{r.len_case}",
        )

    console.print(t)

    # Show details for suspicious cases only (only if something meaningful remains)
    for r in results:
        suspicious = (not r.equivalent) or (r.location_base != r.location_case)
        if not suspicious:
            continue

        ignore = {h.lower() for h in (getattr(args, "ignore_header", []) or [])}

        # Compute non-ignored header diffs
        kept_headers = []
        for k, bval, mval in (r.changed_headers or []):
            if k.lower() in ignore:
                continue
            kept_headers.append((k, bval, mval))

        has_loc_change = bool((r.location_base or r.location_case) and (r.location_base != r.location_case))
        has_status_change = (r.status_base != r.status_case)

        # If nothing meaningful remains, skip printing Details entirely
        if not has_loc_change and not has_status_change and len(kept_headers) == 0:
            continue

        console.print(f"\n[bold]Details: {r.name}[/bold]")

        if has_status_change:
            console.print(f"Status baseline: {r.status_base}")
            console.print(f"Status case:     {r.status_case}")

        if has_loc_change:
            console.print(f"Location baseline: {r.location_base!r}")
            console.print(f"Location case:     {r.location_case!r}")

        if kept_headers:
            ht = Table(show_header=True, header_style="bold")
            ht.add_column("Header")
            ht.add_column("Baseline", overflow="fold")
            ht.add_column("Case", overflow="fold")
            for k, bval, mval in kept_headers:
                ht.add_row(k, bval, mval)
            console.print(ht)

    return 0

def cmd_profile_host_routing(args: argparse.Namespace) -> int:
    base_url, req = _load_request(args)
    CFG = _load_cfg_for_args(args)
    hr_def = cfg_defaults(CFG, "host_routing")

    apply_cfg_default(args, "preset", "default", hr_def.get("preset"))
    apply_cfg_default(args, "min_similarity", 0.985, hr_def.get("min_similarity"))
    apply_cfg_default(args, "max_len_delta_ratio", 0.02, hr_def.get("max_len_delta_ratio"))
    apply_cfg_default(args, "timeout", 15.0, hr_def.get("timeout"))

    opts = SendOptions(
        trust_env=False,
        timeout_s=args.timeout,
        follow_redirects=args.follow_redirects,
        verify_tls=(not args.insecure),
    )

    gate = RateGate()

    retry_status = tuple(
        int(x.strip())
        for x in (args.retry_status.split(",") if getattr(args, "retry_status", None) else [])
        if x.strip().isdigit()
    )

    policy = SendPolicy(
        delay_s=getattr(args, "delay", 0.0) or 0.0,
        rps=getattr(args, "rps", 0.0) or 0.0,
        retries=getattr(args, "retries", 0) or 0,
        retry_status=retry_status or (429, 502, 503, 504),
    )

    def sender(rq):
        return send_with_policy(
            lambda: send_raw_request(rq, base_url=base_url, opts=opts),
            policy=policy,
            gate=gate,
        )

    cfg = EquivalenceConfig(
        min_similarity=args.min_similarity,
        preset=args.preset,
        max_len_delta_ratio=args.max_len_delta_ratio,
        require_same_status=False,
        ignore_headers=tuple(args.ignore_header or []),
        ignore_body_regex=tuple(args.ignore_body_regex or []),
    )

    cases = default_host_routing_cases(fake_host=args.fake_host)
    results = run_host_routing_profile(req, sender, cfg, cases)
    payload = {
        "command": "profile",
        "profile": "host-routing",
        "target": {"base_url": base_url, "method": req.method, "path": req.path},
        "preset": args.preset,
        "results": [
            {
                "case": r.name,
                "verdict": "EQUIV" if r.equivalent else "CHANGED",
                "similarity": r.similarity,
                "status_base": r.status_base,
                "status_case": r.status_case,
                "len_base": r.len_base,
                "len_case": r.len_case,
                "location_base": r.location_base,
                "location_case": r.location_case,
                "changed_headers": [
                    {"header": h, "baseline": b, "case": c}
                    for (h, b, c) in r.changed_headers
                ],
            }
            for r in results
        ],
    }
    if _emit_json_if_requested(args, payload):
        return 0

    console.print(
        f"[dim]effective preset={args.preset} min_similarity={args.min_similarity} "
        f"max_len_delta_ratio={args.max_len_delta_ratio} timeout={args.timeout} "
        f"ignore_headers={len(getattr(args,'ignore_header',[]) or [])} "
        f"ignore_body_regex={len(getattr(args,'ignore_body_regex',[]) or [])}[/dim]"
    )
    console.print("[bold]Profile: host-routing[/bold]")
    t = Table(show_header=True, header_style="bold")
    t.add_column("Case")
    t.add_column("Verdict")
    t.add_column("Similarity")
    t.add_column("Status")
    t.add_column("Location change")
    t.add_column("Len (base→case)")

    for r in results:
        verdict = "[green]EQUIV[/green]" if r.equivalent else "[red]CHANGED[/red]"
        loc_change = "no"
        if (r.location_base or r.location_case) and (r.location_base != r.location_case):
            loc_change = "[yellow]yes[/yellow]"
        t.add_row(
            r.name,
            verdict,
            f"{r.similarity:.4f}",
            f"{r.status_base}->{r.status_case}",
            loc_change,
            f"{r.len_base}->{r.len_case}",
        )

    console.print(t)

    # Show details for suspicious cases only (only if something meaningful remains)
    for r in results:
        suspicious = (not r.equivalent) or (r.location_base != r.location_case)
        if not suspicious:
            continue

        ignore = {h.lower() for h in (getattr(args, "ignore_header", []) or [])}

        kept_headers = []
        for k, bval, mval in (r.changed_headers or []):
            if k.lower() in ignore:
                continue
            kept_headers.append((k, bval, mval))

        has_loc_change = bool((r.location_base or r.location_case) and (r.location_base != r.location_case))
        has_status_change = (r.status_base != r.status_case)

        if not has_loc_change and not has_status_change and len(kept_headers) == 0:
            continue

        console.print(f"\n[bold]Details: {r.name}[/bold]")

        if has_status_change:
            console.print(f"Status baseline: {r.status_base}")
            console.print(f"Status case:     {r.status_case}")

        if has_loc_change:
            console.print(f"Location baseline: {r.location_base!r}")
            console.print(f"Location case:     {r.location_case!r}")

        if kept_headers:
            ht = Table(show_header=True, header_style="bold")
            ht.add_column("Header")
            ht.add_column("Baseline", overflow="fold")
            ht.add_column("Case", overflow="fold")
            for k, bval, mval in kept_headers:
                ht.add_row(k, bval, mval)
            console.print(ht)
    return 0

def add_global_flags(p: argparse.ArgumentParser) -> None:
    p.add_argument("--config", help="Path to a config TOML file")
    p.add_argument("--no-config", action="store_true", help="Ignore config files")
    

def add_redirect_flags(p: argparse.ArgumentParser, default_follow: bool) -> None:
    grp = p.add_mutually_exclusive_group()
    grp.add_argument("--follow-redirects", dest="follow_redirects", action="store_true", help="Follow redirects")
    grp.add_argument("--no-follow-redirects", dest="follow_redirects", action="store_false", help="Do not follow redirects")
    p.set_defaults(follow_redirects=default_follow)

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mrma",
        description="Evidence-driven HTTP trust-boundary experimentation (authorized testing only)",
    )
    p.add_argument("--version", action="version", version=f"mrma {__version__}")
    sub = p.add_subparsers(dest="cmd", required=False)

    authorization = sub.add_parser("authorization", help="Validate authorization manifests")
    authorization_sub = authorization.add_subparsers(dest="authorization_cmd", required=True)
    authorization_validate = authorization_sub.add_parser(
        "validate", help="Validate a strict mrma.authorization/v1 manifest"
    )
    authorization_validate.add_argument("path", help="Authorization manifest path")
    authorization_validate.add_argument("--json", action="store_true", help="Output JSON")
    authorization_validate.set_defaults(func=cmd_authorization_validate)

    evidence = sub.add_parser("evidence", help="Verify evidence documents and bundles")
    evidence_sub = evidence.add_subparsers(dest="evidence_cmd", required=True)
    evidence_verify = evidence_sub.add_parser(
        "verify", help="Verify a result, journal, or deterministic evidence bundle"
    )
    evidence_verify.add_argument("path", help="Evidence JSON, journal, or bundle path")
    evidence_verify.add_argument("--json", action="store_true", help="Output JSON")
    evidence_verify.set_defaults(func=cmd_evidence_verify)

    benchmark = sub.add_parser(
        "benchmark", help="Run the deterministic loopback-only expert benchmark corpus"
    )
    benchmark.add_argument("--json", action="store_true", help="Output JSON")
    benchmark.add_argument("--out-json", help="Write benchmark JSON to a file")
    benchmark.set_defaults(func=cmd_benchmark)

    cfgp = sub.add_parser("config", help="Show config paths and merged config")
    cfgp.add_argument("--json", action="store_true", help="Output JSON")
    cfgp.add_argument("--config", help="Path to a config TOML file")
    cfgp.add_argument("--no-config", action="store_true", help="Ignore config files")
    cfgp.set_defaults(func=cmd_config_show)
    
    pk = sub.add_parser("pack", help="List and use mutation packs")
    pk_sub = pk.add_subparsers(dest="pack_cmd", required=True)

    pk_list = pk_sub.add_parser("list", help="List available packs")
    pk_list.set_defaults(func=cmd_pack_list)
    
    
    runp = sub.add_parser("run", help="Replay a raw HTTP request and print baseline fingerprint")
    runp.add_argument("--config", help="Path to a config TOML file")
    runp.add_argument("--no-config", action="store_true", help="Ignore config files")
    runp.add_argument("--request", "-r", help="Path to raw HTTP request file")
    runp.add_argument("--base-url", "-u", help="Base URL when using --request (e.g. https://example.com)")
    runp.add_argument("--url", help="Quick mode: full URL (e.g. https://example.com/path)")
    runp.add_argument("--method", default="GET", help="Quick mode: HTTP method (default GET)")
    runp.add_argument("-H", "--header", action="append", help="Quick mode: add header 'Name: value' (repeatable)")
    runp.add_argument("--data", help="Quick mode: request body (string)")
    runp.add_argument("--repeat", type=int, default=1, help="Run the request N times and report stability")
    runp.add_argument("--preset", choices=["default", "dynamic", "nextjs", "api-json"], default="default", help="Normalization preset for stability")
    runp.add_argument("--timeout", type=float, default=15.0)
    runp.add_argument("--follow-redirects", action="store_true")
    runp.add_argument("--insecure", action="store_true", help="Disable TLS verification")
    runp.add_argument("--json", action="store_true", help="Output JSON instead of tables")
    runp.add_argument("--out-json", help="Write JSON output to a file (works with --json)")
    runp.add_argument(
        "--add-common",
        action="store_true",
        help="Append common headers (User-Agent/Accept/Connection) unless already present",
    )
    _add_authorization_args(runp)
    runp.set_defaults(func=cmd_run)

    experiment = sub.add_parser(
        "experiment",
        help="Test one mutation with confidence-bounded, balanced controls",
        description=(
            "Bracket each mutation with local controls, isolate response-cookie state by default, "
            "and require fixed-sample confidence bounds for positive or negative verdicts."
        ),
    )
    experiment.add_argument("--config", help="Path to a config TOML file")
    experiment.add_argument("--no-config", action="store_true", help="Ignore config files")
    experiment.add_argument("--request", "-r", help="Path to a raw HTTP request file")
    experiment.add_argument("--base-url", "-u", help="Base URL when using --request")
    experiment.add_argument("--url", help="Quick mode: full URL")
    experiment.add_argument("--method", default="GET", help="Quick mode: HTTP method")
    experiment.add_argument(
        "-H",
        "--header",
        action="append",
        help="Quick mode: add baseline header 'Name: value' (repeatable)",
    )
    experiment.add_argument("--data", help="Quick mode: request body")
    experiment.add_argument(
        "--setup-request",
        action="append",
        default=[],
        help="Authorized semantic request executed once before sampling (repeatable)",
    )
    experiment.add_argument(
        "--reset-request",
        action="append",
        default=[],
        help="Authorized semantic request executed before each round (repeatable)",
    )
    experiment.add_argument(
        "--set-header",
        action="append",
        help="Set a mutation header 'Name: value' (repeatable)",
    )
    experiment.add_argument(
        "--remove-header",
        action="append",
        help="Remove a mutation header by name (repeatable)",
    )
    experiment.add_argument(
        "--candidate-manifest",
        help="Exploratory candidate manifest to bind into an independent confirmation",
    )
    experiment.add_argument(
        "--candidate-id",
        help="One predeclared candidate ID from --candidate-manifest",
    )
    experiment.add_argument(
        "--rounds",
        type=int,
        help="Fixed paired rounds from 6-50; balanced schedules require an even value",
    )
    experiment.add_argument(
        "--min-rounds",
        type=int,
        default=6,
        help="Earliest round for rejecting invalid or unstable controls",
    )
    experiment.add_argument(
        "--max-rounds",
        type=int,
        default=20,
        help="Predeclared sample size for positive and negative decisions",
    )
    experiment.add_argument(
        "--seed",
        type=int,
        help="Balanced-schedule seed; generated and recorded when omitted",
    )
    experiment.add_argument(
        "--schedule",
        choices=["bracketed", "balanced"],
        default="bracketed",
        help="Bracket each mutation with local controls (default) or use seeded AB/BA blocks",
    )
    experiment.add_argument(
        "--preset",
        choices=["default", "dynamic", "nextjs", "api-json"],
        default="default",
        help="Body normalization preset",
    )
    experiment.add_argument("--min-similarity", type=float, default=0.985)
    experiment.add_argument("--max-len-delta-ratio", type=float, default=0.02)
    experiment.add_argument(
        "--min-reproducibility",
        type=float,
        default=0.8,
        help="Influence verdict requires the 95%% lower bound to reach this value",
    )
    experiment.add_argument(
        "--no-influence-threshold",
        type=float,
        default=0.2,
        help="No-influence verdict requires the 95%% upper bound below this value",
    )
    experiment.add_argument(
        "--max-control-change-rate",
        type=float,
        default=0.2,
        help="Reject evidence when repeated controls change more often",
    )
    experiment.add_argument(
        "--allow-status-change",
        action="store_true",
        help="Do not make an HTTP status change decisive by itself",
    )
    experiment.add_argument(
        "--ignore-header",
        action="append",
        default=[],
        help="Ignore a response evidence header (repeatable)",
    )
    experiment.add_argument(
        "--ignore-body-regex",
        action="append",
        default=[],
        help="Scrub a body regex before comparison (repeatable)",
    )
    experiment.add_argument(
        "--response-header-scope",
        choices=["known", "explicit", "all-stable"],
        default="known",
        help="Use known, explicit, or control-qualified all-stable response fields",
    )
    experiment.add_argument(
        "--include-response-header",
        action="append",
        default=[],
        help="Add an exact response header to decision evidence (repeatable)",
    )
    experiment.add_argument(
        "--include-response-header-pattern",
        action="append",
        default=[],
        help="Select stable response fields with a bounded token glob (repeatable)",
    )
    experiment.add_argument(
        "--exclude-response-header",
        action="append",
        default=[],
        help="Exclude an exact response field from all-stable evidence (repeatable)",
    )
    experiment.add_argument(
        "--response-header-profile",
        choices=["routing", "security", "cache"],
        help="Force a documented response-field profile into decision evidence",
    )
    experiment.add_argument(
        "--stable-header-controls",
        type=int,
        default=3,
        help="Budgeted setup controls used by all-stable mode (3-10)",
    )
    experiment.add_argument(
        "--assume-text-without-content-type",
        action="store_true",
        help="Explicitly allow undeclared response bodies into text comparison",
    )
    experiment.add_argument("--timeout", type=float, default=15.0)
    experiment.add_argument(
        "--state-mode",
        choices=["isolated", "per-arm", "shared-session"],
        default="isolated",
        help="Response-cookie state model; isolated preserves only explicit request state",
    )
    experiment.add_argument(
        "--connection-mode",
        choices=["reuse", "per-arm", "per-round", "fresh-observation"],
        default="reuse",
        help="Connection-pool scope; fresh-observation provides strongest isolation",
    )
    experiment.add_argument(
        "--max-response-bytes",
        type=int,
        default=1024 * 1024,
        help="Hard streaming read bound per response",
    )
    experiment.add_argument(
        "--body-storage",
        choices=["none", "sample", "full"],
        default="sample",
        help="In-memory body retention within the hard response bound",
    )
    experiment.add_argument(
        "--redaction-policy",
        choices=["standard", "strict", "forensic"],
        default="standard",
        help="Evidence redaction; forensic preserves target path and exact size/timing metadata",
    )
    experiment.add_argument(
        "--assurance",
        choices=["exploratory", "research", "forensic"],
        default="research",
        help="Apply a coherent experiment policy preset; preset settings are authoritative",
    )
    experiment.add_argument(
        "--evidence-write",
        choices=["normal", "durable"],
        default="normal",
        help="Atomic evidence write mode; durable also syncs file and supported directories",
    )
    add_redirect_flags(experiment, default_follow=False)
    experiment.add_argument("--insecure", action="store_true", help="Disable TLS verification")
    experiment.add_argument(
        "--allow-insecure-research",
        action="store_true",
        help="Allow and record disabled TLS under research or forensic assurance",
    )
    experiment.add_argument(
        "--trust-environment",
        action="store_true",
        help="Rejected by v0.4 policy; use explicit proxy and CA inputs",
    )
    experiment.add_argument("--proxy", help="Explicit proxy URL; evidence stores only a keyed fingerprint")
    experiment.add_argument("--ca-bundle", help="Explicit CA bundle; evidence stores only its SHA-256 digest")
    experiment.add_argument("--delay", type=float, default=0.0, help="Delay between requests")
    experiment.add_argument("--rps", type=float, default=0.0, help="Requests per second; 0 disables")
    experiment.add_argument("--retries", type=int, default=0, help="Retries for transient statuses")
    experiment.add_argument("--retry-status", default="429,502,503,504")
    experiment.add_argument(
        "--add-common",
        action="store_true",
        help="Add stable browser-like headers to both experiment arms",
    )
    experiment.add_argument("--json", action="store_true", help="Emit versioned JSON evidence")
    experiment.add_argument("--out-json", help="Write JSON evidence to a file")
    experiment.add_argument("--bundle", help="Create a deterministic expert-review ZIP bundle")
    experiment.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate authorization and the maximum plan without networking",
    )
    experiment.add_argument(
        "--fail-on",
        choices=["none", "influence", "inconclusive", "any-signal"],
        default="none",
        help="Automation exit policy (influence=10, inconclusive=11)",
    )
    _add_authorization_args(experiment)
    experiment.set_defaults(func=cmd_experiment)

    exp = sub.add_parser("export", help="Export current request as curl or raw HTTP")
    exp.add_argument("--request", "-r", help="Raw HTTP request file")
    exp.add_argument("--base-url", "-u", help="Base URL when using --request")
    exp.add_argument("--url", help="Quick mode URL")
    exp.add_argument("--method", default="GET", help="Quick mode method")
    exp.add_argument("-H", "--header", action="append", help="Quick mode header 'Name: value'")
    exp.add_argument("--data", help="Quick mode body (string)")
    exp.add_argument("--add-common", action="store_true", help="Append common headers")
    exp.add_argument("--format", choices=["curl", "raw"], default="curl")
    exp.add_argument("--json", action="store_true", help="Output JSON instead of tables")
    exp.set_defaults(func=cmd_export)

    diffp = sub.add_parser("diff", help="Send baseline + mutated request and compare responses")
    diffp.add_argument("--config", help="Path to a config TOML file")
    diffp.add_argument("--no-config", action="store_true", help="Ignore config files")
    diffp.add_argument("--request", "-r", help="Path to raw HTTP request file")
    diffp.add_argument("--base-url", "-u", help="Base URL when using --request (e.g. https://example.com)")
    diffp.add_argument("--url", help="Quick mode: full URL (e.g. https://example.com/path)")
    diffp.add_argument("--method", default="GET", help="Quick mode: HTTP method (default GET)")
    diffp.add_argument("-H", "--header", action="append", help="Quick mode: add header 'Name: value' (repeatable)")
    diffp.add_argument("--data", help="Quick mode: request body (string)")
    diffp.add_argument("--preset", choices=["default", "dynamic", "nextjs", "api-json"], default="default", help="Normalization preset for comparisons")
    diffp.add_argument("--timeout", type=float, default=15.0)
    diffp.add_argument("--follow-redirects", action="store_true")
    diffp.add_argument("--insecure", action="store_true", help="Disable TLS verification")
    diffp.add_argument("--json", action="store_true", help="Output JSON instead of tables")
    diffp.add_argument("--show-set-cookie", action="store_true", help="Include Set-Cookie in header diffs (noisy)")
    diffp.add_argument("--out-json", help="Write JSON output to a file (works with --json)")
    diffp.add_argument(
        "--add-common",
        action="store_true",
        help="Append common headers (User-Agent/Accept/Connection) unless already present",
    )

    diffp.add_argument("--remove-header", help="Remove a header by name (case-insensitive)")
    diffp.add_argument("--set-header", action="append", help="Set header like 'Name: value' (can repeat)")

    diffp.add_argument("--min-similarity", type=float, default=0.985)
    diffp.add_argument("--max-len-delta-ratio", type=float, default=0.02)
    diffp.add_argument("--allow-status-change", action="store_true")
    diffp.add_argument("--ignore-header", action="append", default=[], help="Ignore response header (repeatable), e.g. set-cookie")
    diffp.add_argument("--ignore-body-regex", action="append", default=[], help="Regex to scrub from body before compare (repeatable)")


    _add_authorization_args(diffp)
    diffp.set_defaults(func=cmd_diff)

    disc = sub.add_parser("discover", help="Find minimal required header set (delta debugging)")
    disc.add_argument("--request", "-r", help="Path to raw HTTP request file")
    disc.add_argument("--base-url", "-u", help="Base URL when using --request (e.g. https://example.com)")
    disc.add_argument("--url", help="Quick mode: full URL (e.g. https://example.com/path)")
    disc.add_argument("--method", default="GET", help="Quick mode: HTTP method (default GET)")
    disc.add_argument("-H", "--header", action="append", help="Quick mode: add header 'Name: value' (repeatable)")
    disc.add_argument("--data", help="Quick mode: request body (string)")
    disc.add_argument("--preset", choices=["default", "dynamic", "nextjs", "api-json"], default="default", help="Normalization preset for comparisons")
    disc.add_argument("--timeout", type=float, default=15.0)
    disc.add_argument("--follow-redirects", action="store_true")
    disc.add_argument("--insecure", action="store_true", help="Disable TLS verification")
    disc.add_argument("--config", help="Path to a config TOML file")
    disc.add_argument("--no-config", action="store_true", help="Ignore config files")

    disc.add_argument("--min-similarity", type=float, default=0.985)
    disc.add_argument("--max-len-delta-ratio", type=float, default=0.02)
    disc.add_argument("--json", action="store_true", help="Output JSON instead of tables")
    disc.add_argument("--out-json", help="Write JSON output to a file (works with --json)")
    disc.add_argument("--rps", type=float, default=0.0, help="Requests per second (rate limit). 0 = off")
    disc.add_argument("--retries", type=int, default=0, help="Retry on transient statuses (e.g. 429/503)")
    disc.add_argument("--retry-status", default="429,502,503,504", help="Comma list of HTTP statuses to retry")
    disc.add_argument("--delay", type=float, default=0.0, help="Sleep N seconds between requests")

    disc.add_argument(
        "--include-auth",
        action="store_true",
        help="Allow removing Cookie/Authorization/CSRF headers (unsafe)",
    )
    disc.add_argument(
        "--chunk-start",
        type=int,
        default=8,
        help="Initial chunk count for ddmin (higher may reduce requests)",
    )

    disc.add_argument(
        "--print-minimal-request",
        action="store_true",
        help="Print minimal raw request (Host + required headers)",
    )
    disc.add_argument("--out", help="Write minimal raw request to file")

    _add_authorization_args(disc)
    disc.set_defaults(func=cmd_discover)

    iso = sub.add_parser("isolate", help="Find which added headers cause response to change")
    iso.add_argument("--request", "-r", help="Path to raw HTTP request file")
    iso.add_argument("--base-url", "-u", help="Base URL when using --request (e.g. https://example.com)")
    iso.add_argument("--url", help="Quick mode: full URL (e.g. https://example.com/path)")
    iso.add_argument("--method", default="GET", help="Quick mode: HTTP method (default GET)")
    iso.add_argument("-H", "--header", action="append", help="Quick mode: add header 'Name: value' (repeatable)")
    iso.add_argument("--data", help="Quick mode: request body (string)")
    iso.add_argument("--preset", choices=["default", "dynamic", "nextjs", "api-json"], default="default", help="Normalization preset for comparisons")
    iso.add_argument("--timeout", type=float, default=15.0)
    iso.add_argument("--follow-redirects", action="store_true")
    iso.add_argument("--insecure", action="store_true")
    iso.add_argument("--pack", default="", help="Use a predefined pack as the headers-to-add set")
    iso.add_argument("--depth", choices=["basic", "extended"], default="basic")

    iso.add_argument("--add-common", action="store_true", help="Use common_headers() as the headers-to-add set")
    iso.add_argument("--add-header", action="append", help="Add a single header like 'Name: value' (repeatable)")

    iso.add_argument("--min-similarity", type=float, default=0.985)
    iso.add_argument("--max-len-delta-ratio", type=float, default=0.02)
    iso.add_argument("--ddmin-start", type=int, default=4)
    iso.add_argument("--ip-set", choices=["basic", "extended"], default="basic")
    iso.add_argument("--pack-file", default="", help="Load headers-to-add from a file (lines: 'Header: value' or 'HeaderName')")
    iso.add_argument("--pack-file-mode", choices=["set", "remove"], default="set", help="How to use --pack-file (isolate supports set only for now)")
    iso.add_argument("--json", action="store_true", help="Output JSON instead of tables")
    iso.add_argument("--config", help="Path to a config TOML file")
    iso.add_argument("--no-config", action="store_true", help="Ignore config files")
    iso.add_argument("--out-json", help="Write JSON output to a file (works with --json)")
    iso.add_argument("--rps", type=float, default=0.0, help="Requests per second (rate limit). 0 = off")
    iso.add_argument("--retries", type=int, default=0, help="Retry on transient statuses (e.g. 429/503)")
    iso.add_argument("--retry-status", default="429,502,503,504", help="Comma list of HTTP statuses to retry")
    iso.add_argument("--delay", type=float, default=0.0, help="Sleep N seconds between requests")

    _add_authorization_args(iso)
    iso.set_defaults(func=cmd_isolate)
    isr = sub.add_parser("isolate-remove", help="Find which header removals cause response to change (ddmin)")
    isr.add_argument("--ignore-header", action="append", default=[], help="Ignore response header (repeatable), e.g. set-cookie")
    isr.add_argument("--ignore-body-regex", action="append", default=[], help="Regex to scrub from body before compare (repeatable)")
    isr.add_argument("--request", "-r", help="Path to raw HTTP request file")
    isr.add_argument("--base-url", "-u", help="Base URL when using --request")
    isr.add_argument("--url", help="Quick mode URL")
    isr.add_argument("--method", default="GET")
    isr.add_argument("-H", "--header", action="append")
    isr.add_argument("--data")

    isr.add_argument("--pack-file", required=True, help="File containing headers to remove (Header or Header: value)")
    isr.add_argument("--preset", choices=["default", "dynamic", "nextjs", "api-json"], default="default")
    isr.add_argument("--timeout", type=float, default=15.0)
    isr.add_argument("--follow-redirects", action="store_true")
    isr.add_argument("--insecure", action="store_true")
    isr.add_argument("--delay", type=float, default=0.0, help="Sleep N seconds between requests")

    isr.add_argument("--min-similarity", type=float, default=0.985)
    isr.add_argument("--max-len-delta-ratio", type=float, default=0.02)
    isr.add_argument("--ddmin-start", type=int, default=4)
    isr.add_argument("--json", action="store_true", help="Output JSON instead of tables")
    isr.add_argument("--config", help="Path to a config TOML file")
    isr.add_argument("--no-config", action="store_true", help="Ignore config files")
    isr.add_argument("--out-json", help="Write JSON output to a file (works with --json)")
    isr.add_argument("--rps", type=float, default=0.0, help="Requests per second (rate limit). 0 = off")
    isr.add_argument("--retries", type=int, default=0, help="Retry on transient statuses (e.g. 429/503)")
    isr.add_argument("--retry-status", default="429,502,503,504", help="Comma list of HTTP statuses to retry")

    _add_authorization_args(isr)
    isr.set_defaults(func=cmd_isolate_remove)
    
    imp = sub.add_parser(
        "impact", help="Run a conservative mutation set and rank response changes"
    )
    imp.add_argument("--config", help="Path to a config TOML file")
    imp.add_argument("--no-config", action="store_true", help="Ignore config files")
    imp.add_argument("--request", "-r", help="Path to raw HTTP request file")
    imp.add_argument("--base-url", "-u", help="Base URL when using --request (e.g. https://example.com)")
    imp.add_argument("--url", help="Quick mode: full URL (e.g. https://example.com/path)")
    imp.add_argument("--method", default="GET", help="Quick mode: HTTP method (default GET)")
    imp.add_argument("-H", "--header", action="append", help="Quick mode: add header 'Name: value' (repeatable)")
    imp.add_argument("--data", help="Quick mode: request body (string)")
    imp.add_argument("--preset", choices=["default", "dynamic", "nextjs", "api-json"], default="default", help="Normalization preset for comparisons")
    imp.add_argument("--timeout", type=float, default=15.0)
    imp.add_argument("--follow-redirects", action="store_true")
    imp.add_argument("--insecure", action="store_true")

    imp.add_argument("--min-similarity", type=float, default=0.985)
    imp.add_argument("--max-len-delta-ratio", type=float, default=0.02)
    imp.add_argument("--allow-status-change", action="store_true")
    imp.add_argument("--only-changed", action="store_true", help="Show only mutations that changed the response")
    imp.add_argument("--top", type=int, default=0, help="Show only the top N rows (0 = all)")
    imp.add_argument("--top-deltas", type=int, default=0, help="Show N most different mutations even if still equivalent (0=off)")
    imp.add_argument("--pack", default="", help="Use a predefined mutation pack (baseline/proxy/host/cache)")
    imp.add_argument("--depth", choices=["basic", "extended"], default="basic", help="Pack depth")
    imp.add_argument("--ip-set", choices=["basic", "extended"], default="basic", help="IP variants set for proxy pack")
    imp.add_argument("--delay", type=float, default=0.0, help="Sleep N seconds between requests (polite mode)")
    imp.add_argument("--pack-file", default="", help="Load mutations from a file (lines: 'Header: value' or 'HeaderName')")
    imp.add_argument("--pack-file-mode", choices=["set", "remove"], default="set", help="How to use --pack-file (set headers or remove headers)")
    imp.add_argument("--json", action="store_true", help="Output JSON instead of tables")
    imp.add_argument("--out-json", help="Write JSON output to a file (works with --json)")
    imp.add_argument("--ignore-header", action="append", default=[], help="Ignore response header (repeatable), e.g. set-cookie")
    imp.add_argument("--ignore-body-regex", action="append", default=[], help="Regex to scrub from body before compare (repeatable)")
    imp.add_argument("--rps", type=float, default=0.0, help="Requests per second (rate limit). 0 = off")
    imp.add_argument("--retries", type=int, default=0, help="Retry on transient statuses (e.g. 429/503)")
    imp.add_argument("--retry-status", default="429,502,503,504", help="Comma list of HTTP statuses to retry")
    imp.add_argument(
        "--candidate-out",
        help="Write the exploratory candidate manifest to this new file",
    )
    
    _add_authorization_args(imp)
    imp.set_defaults(func=cmd_impact)
    
    # Parent command: profile (subcommands will grow later)
    prof = sub.add_parser("profile", help="Profile a target using a request + response analysis")
    prof_sub = prof.add_subparsers(dest="profile_cmd", required=True)

    sec = prof_sub.add_parser(
        "security-headers",
        help="Fetch response and report common security headers",
    )
    sec.add_argument("--request", "-r", help="Path to raw HTTP request file")
    sec.add_argument("--base-url", "-u", help="Base URL when using --request (e.g. https://example.com)")
    sec.add_argument("--url", help="Quick mode: full URL (e.g. https://example.com/path)")
    sec.add_argument("--method", default="GET", help="Quick mode: HTTP method (default GET)")
    sec.add_argument("-H", "--header", action="append", help="Quick mode: add header 'Name: value' (repeatable)")
    sec.add_argument("--data", help="Quick mode: request body (string)")
    sec.add_argument("--preset", choices=["default", "dynamic", "nextjs", "api-json"], default="default", help="Normalization preset for comparisons")
    sec.add_argument("--timeout", type=float, default=15.0)
    sec.add_argument("--follow-redirects", action="store_true")
    sec.add_argument("--insecure", action="store_true", help="Disable TLS verification")
    sec.add_argument("--json", action="store_true", help="Output JSON instead of tables")
    sec.add_argument("--config", help="Path to a config TOML file")
    sec.add_argument("--no-config", action="store_true", help="Ignore config files")
    sec.add_argument("--out-json", help="Write JSON output to a file (works with --json)")
    sec.add_argument(
        "--add-common",
        action="store_true",
        help="Append common headers (User-Agent/Accept/Connection) unless already present",
    )
    _add_authorization_args(sec)
    sec.set_defaults(func=cmd_profile_security_headers)
    
    px = prof_sub.add_parser(
        "proxy-trust",
        help="Detect whether the target trusts proxy/forwarded headers",
    )
    px.add_argument("--request", "-r", help="Path to raw HTTP request file")
    px.add_argument("--base-url", "-u", help="Base URL when using --request (e.g. https://example.com)")
    px.add_argument("--url", help="Quick mode: full URL (e.g. https://example.com/path)")
    px.add_argument("--method", default="GET", help="Quick mode: HTTP method (default GET)")
    px.add_argument("-H", "--header", action="append", help="Quick mode: add header 'Name: value' (repeatable)")
    px.add_argument("--data", help="Quick mode: request body (string)")
    px.add_argument("--preset", choices=["default", "dynamic", "nextjs", "api-json"], default="default", help="Normalization preset for comparisons")
    px.add_argument("--timeout", type=float, default=15.0)
    px.add_argument("--follow-redirects", action="store_true")
    px.add_argument("--insecure", action="store_true", help="Disable TLS verification")

    px.add_argument("--min-similarity", type=float, default=0.985)
    px.add_argument("--max-len-delta-ratio", type=float, default=0.02)
    px.add_argument("--fake-host", default="example.invalid", help="Value used for forwarded host tests")
    px.add_argument("--json", action="store_true", help="Output JSON instead of tables")
    px.add_argument("--config", help="Path to a config TOML file")
    px.add_argument("--no-config", action="store_true", help="Ignore config files")
    px.add_argument("--out-json", help="Write JSON output to a file (works with --json)")
    px.add_argument("--ignore-header", action="append", default=[], help="Ignore response header (repeatable), e.g. set-cookie")
    px.add_argument("--ignore-body-regex", action="append", default=[], help="Regex to scrub from body before compare (repeatable)")
    px.add_argument("--rps", type=float, default=0.0, help="Requests per second (rate limit). 0 = off")
    px.add_argument("--retries", type=int, default=0, help="Retry on transient statuses (e.g. 429/503)")
    px.add_argument("--retry-status", default="429,502,503,504", help="Comma list of HTTP statuses to retry")

    _add_authorization_args(px)
    px.set_defaults(func=cmd_profile_proxy_trust)
    
    hr = prof_sub.add_parser(
      "host-routing",
      help="Detect whether the target trusts host-related headers",
    )
    hr.add_argument("--request", "-r", help="Raw HTTP request file")
    hr.add_argument("--base-url", "-u", help="Base URL when using --request")
    hr.add_argument("--url", help="Quick mode URL")
    hr.add_argument("--method", default="GET", help="Quick mode method")
    hr.add_argument("-H", "--header", action="append", help="Quick mode header 'Name: value'")
    hr.add_argument("--data", help="Quick mode body (string)")
    hr.add_argument("--preset", choices=["default", "dynamic", "nextjs", "api-json"], default="default", help="Normalization preset for comparisons")

    hr.add_argument("--timeout", type=float, default=15.0)
    hr.add_argument("--follow-redirects", action="store_true")
    hr.add_argument("--insecure", action="store_true")

    hr.add_argument("--min-similarity", type=float, default=0.985)
    hr.add_argument("--max-len-delta-ratio", type=float, default=0.02)
    hr.add_argument("--fake-host", default="example.invalid", help="Value used for host tests")
    hr.add_argument("--json", action="store_true", help="Output JSON instead of tables")
    hr.add_argument("--config", help="Path to a config TOML file")
    hr.add_argument("--no-config", action="store_true", help="Ignore config files")
    hr.add_argument("--out-json", help="Write JSON output to a file (works with --json)")
    hr.add_argument("--ignore-header", action="append", default=[], help="Ignore response header (repeatable), e.g. set-cookie")
    hr.add_argument("--ignore-body-regex", action="append", default=[], help="Regex to scrub from body before compare (repeatable)")
    hr.add_argument("--rps", type=float, default=0.0, help="Requests per second (rate limit). 0 = off")
    hr.add_argument("--retries", type=int, default=0, help="Retry on transient statuses (e.g. 429/503)")
    hr.add_argument("--retry-status", default="429,502,503,504", help="Comma list of HTTP statuses to retry")

    _add_authorization_args(hr)
    hr.set_defaults(func=cmd_profile_host_routing)
    
    rep = sub.add_parser("report", help="Run baseline + impact + profiles and write report files")
    rep.add_argument("--url", required=True, help="Target URL")
    rep.add_argument("--follow-redirects", action="store_true")
    rep.add_argument("--insecure", action="store_true")
    rep.add_argument("--timeout", type=float, default=15.0)
    rep.add_argument("--preset", choices=["default", "dynamic", "nextjs", "api-json"], default="default")
    rep.add_argument("--min-similarity", type=float, default=0.985)
    rep.add_argument("--max-len-delta-ratio", type=float, default=0.02)
    rep.add_argument("--delay", type=float, default=0.0)
    rep.add_argument("--top-deltas", type=int, default=10)
    rep.add_argument("--fake-host", default="example.invalid")
    rep.add_argument("--out-json", default="mrma_report.json")
    rep.add_argument("--out-md", default="mrma_report.md")

    rep.add_argument("--config", help="Path to a config TOML file")
    rep.add_argument("--no-config", action="store_true", help="Ignore config files")
    rep.add_argument("--rps", type=float, default=0.0, help="Requests per second (rate limit). 0 = off")
    rep.add_argument("--retries", type=int, default=0, help="Retry on transient statuses (e.g. 429/503)")
    rep.add_argument("--retry-status", default="429,502,503,504", help="Comma list of HTTP statuses to retry")
    rep.add_argument(
        "--ignore-header",
        action="append",
        default=[],
        help="Ignore response header in comparisons (repeatable). Example: --ignore-header set-cookie",
    )
    rep.add_argument(
        "--ignore-body-regex",
        action="append",
        default=[],
        help="Regex to strip from body before comparison (repeatable).",
    )
    _add_authorization_args(rep)
    rep.set_defaults(func=cmd_report)

    return p


def main() -> None:
    parser = build_parser()

    if len(sys.argv) == 1:
        print_home(__version__)
        raise SystemExit(0)
    if len(sys.argv) == 2 and sys.argv[1] in ("-h", "--help"):
        print_home(__version__)

    args = parser.parse_args()

    if not getattr(args, "cmd", None):
        raise SystemExit(0)

    try:
        if getattr(args, "_requires_authorization", False) and args.func is not cmd_experiment:
            with _legacy_network_scope(args):
                rc = args.func(args)
        else:
            rc = args.func(args)
    except AuthorizationError as exc:
        print(f"Authorization rejected: {exc}", file=sys.stderr)
        rc = EXIT_AUTHORIZATION_REJECTED
    except BudgetError as exc:
        print(f"Budget or policy stopped the run: {exc}", file=sys.stderr)
        rc = EXIT_BUDGET_EXHAUSTED
    except EvidenceIntegrityError as exc:
        print(f"Evidence integrity failure: {exc}", file=sys.stderr)
        rc = EXIT_EVIDENCE_INTEGRITY
    raise SystemExit(rc)
