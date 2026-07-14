from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

from rich import box
from rich.panel import Panel
from rich.table import Table

from . import __version__
from .core.compare import EquivalenceConfig, equivalent_response
from .core.config import cfg_defaults, default_config_paths, load_config
from .core.discover import discover_required_headers
from .core.experiment import ExperimentConfig, run_experiment
from .core.export import to_curl, to_raw
from .core.fingerprint import fingerprint_response
from .core.header_sets import common_headers
from .core.http_client import SemanticHttpTransport, SendOptions, send_raw_request
from .core.impact import run_impact
from .core.isolate import isolate_added_headers
from .core.isolate_remove import isolate_removed_headers
from .core.jsonout import print_json
from .core.mutate import remove_header, set_header
from .core.mutations import default_mutations
from .core.pack_file import parse_pack_file
from .core.packs import list_packs, mutations_for_pack
from .core.quick_request import build_request_from_url
from .core.raw_request import RawRequest, parse_raw_http_request
from .core.render import render_raw_request
from .core.report import render_md_report, utc_now_iso
from .core.sender import RateGate, SendPolicy, send_with_policy
from .core.stability import measure_stability
from .profiles.host_routing import default_host_routing_cases, run_host_routing_profile
from .profiles.proxy_trust import default_proxy_trust_cases, run_proxy_trust_profile
from .profiles.security_headers import audit_security_headers
from .ui import console, print_home, verdict_style


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
        req_text = Path(args.request).read_text(encoding="utf-8", errors="replace")
        req = parse_raw_http_request(req_text)
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

    # If --out is set, write JSON to file; else print to stdout
    out_path = getattr(args, "out_json", None)
    if out_path:
        Path(out_path).write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
            errors="replace",
        )
    else:
        print_json(payload)

    return True

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


def _redacted_target_metadata(base_url: str, req: RawRequest) -> dict[str, object]:
    origin_parts = urlsplit(base_url)
    hostname = origin_parts.hostname or ""
    display_host = f"[{hostname}]" if ":" in hostname else hostname
    port = f":{origin_parts.port}" if origin_parts.port is not None else ""
    origin = urlunsplit((origin_parts.scheme, f"{display_host}{port}", "", "", ""))

    request_target = urlsplit(req.path)
    path = request_target.path or "/"
    query = request_target.query
    metadata: dict[str, object] = {
        "origin": origin,
        "method": req.method,
        "path": path,
        "query_present": bool(query),
    }
    if query:
        metadata["query_sha256"] = hashlib.sha256(
            query.encode("utf-8", errors="replace")
        ).hexdigest()
    return metadata

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
    cfg_data = _load_cfg_for_args(args)
    defaults = cfg_defaults(cfg_data, "experiment")
    apply_cfg_default(args, "rounds", 5, defaults.get("rounds"))
    apply_cfg_default(args, "preset", "default", defaults.get("preset"))
    apply_cfg_default(args, "timeout", 15.0, defaults.get("timeout"))
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
        "max_control_change_rate",
        0.2,
        defaults.get("max_control_change_rate"),
    )
    apply_cfg_list_default(args, "ignore_header", defaults.get("ignore_headers"))
    apply_cfg_list_default(args, "ignore_body_regex", defaults.get("ignore_body_regex"))

    if not 3 <= args.rounds <= 100:
        raise SystemExit("Error: --rounds must be between 3 and 100")
    if not 0.0 <= args.min_similarity <= 1.0:
        raise SystemExit("Error: --min-similarity must be between 0 and 1")
    if args.max_len_delta_ratio < 0.0:
        raise SystemExit("Error: --max-len-delta-ratio cannot be negative")
    if not 0.5 < args.min_reproducibility <= 1.0:
        raise SystemExit("Error: --min-reproducibility must be greater than 0.5 and at most 1")
    if not 0.0 <= args.max_control_change_rate < 0.5:
        raise SystemExit("Error: --max-control-change-rate must be at least 0 and less than 0.5")
    if args.timeout <= 0 or args.delay < 0 or args.rps < 0 or args.retries < 0:
        raise SystemExit("Error: timeout must be positive; delay, rps, and retries cannot be negative")

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
    experiment_cfg = ExperimentConfig(
        rounds=args.rounds,
        min_reproducibility=args.min_reproducibility,
        max_control_change_rate=args.max_control_change_rate,
        equivalence=equivalence,
    )
    opts = SendOptions(
        timeout_s=args.timeout,
        follow_redirects=args.follow_redirects,
        verify_tls=(not args.insecure),
    )
    retry_status = tuple(
        int(value.strip())
        for value in (args.retry_status.split(",") if args.retry_status else [])
        if value.strip().isdigit()
    )
    policy = SendPolicy(
        delay_s=args.delay,
        rps=args.rps,
        retries=args.retries,
        retry_status=retry_status or (429, 502, 503, 504),
    )
    gate = RateGate()
    run_id = uuid4().hex
    started_at = utc_now_iso()
    timer = time.perf_counter()

    with SemanticHttpTransport(opts) as transport:

        def sender(request: RawRequest):
            return send_with_policy(
                lambda: transport.send(request, base_url),
                policy=policy,
                gate=gate,
            )

        if args.json:
            result = run_experiment(baseline, mutated, sender, experiment_cfg)
        else:
            with console.status(
                "[signal]Running counterbalanced control/mutation experiment[/signal]",
                spinner="dots12",
            ) as status:

                def update_progress(done: int, total: int, arm: str) -> None:
                    status.update(
                        f"[signal]Collecting evidence[/signal]  {done}/{total}  [muted]{arm}[/muted]"
                    )

                result = run_experiment(
                    baseline,
                    mutated,
                    sender,
                    experiment_cfg,
                    on_progress=update_progress,
                )

    duration_ms = round((time.perf_counter() - timer) * 1000, 3)
    target_metadata = _redacted_target_metadata(base_url, baseline)
    payload = {
        "schema_version": "mrma.experiment/v1",
        "run": {
            "id": run_id,
            "started_at": started_at,
            "completed_at": utc_now_iso(),
            "duration_ms": duration_ms,
        },
        "tool": {"name": "mrma", "version": __version__},
        "transport": {
            "mode": "semantic-http",
            "adapter": "httpx",
            "connection_reuse": True,
        },
        "target": target_metadata,
        "mutation": {
            "set_header_names": set_headers,
            "removed_header_names": removed_headers,
            "values_redacted": True,
        },
        "thresholds": {
            "preset": args.preset,
            "min_similarity": args.min_similarity,
            "max_len_delta_ratio": args.max_len_delta_ratio,
            "min_reproducibility": args.min_reproducibility,
            "max_control_change_rate": args.max_control_change_rate,
        },
        "result": result.to_dict(),
    }
    if _emit_json_if_requested(args, payload):
        return 0

    style = verdict_style(result.verdict)
    heading = result.verdict.replace("_", " ")
    mutation_names = [f"set {name}" for name in set_headers]
    mutation_names.extend(f"remove {name}" for name in removed_headers)
    summary = Table.grid(expand=True)
    summary.add_column()
    summary.add_column(justify="right")
    summary.add_row(f"[{style}]{heading}[/{style}]", f"[bold]{result.evidence_grade.upper()} EVIDENCE[/bold]")
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
        f"95% interval {low:.0%}-{high:.0%}",
    )
    evidence.add_row(
        "Control instability",
        f"{result.control_changes}/{result.control_comparisons} ({result.control_change_rate:.0%})",
        f"reject above {args.max_control_change_rate:.0%}",
    )
    evidence.add_row(
        "Similarity contrast",
        f"{result.similarity_contrast:+.4f}",
        "control median minus mutation median",
    )
    evidence.add_row(
        "Status shifts",
        f"{result.status_shift_rounds}/{result.rounds}",
        "paired control vs mutation",
    )
    console.print(evidence)

    if result.header_shift_counts:
        shifts = ", ".join(
            f"{name} {count}/{result.rounds}"
            for name, count in sorted(
                result.header_shift_counts.items(), key=lambda item: (-item[1], item[0])
            )
        )
        console.print(f"[muted]Response header evidence:[/muted] {shifts}")
    console.print(f"[muted]Run {run_id[:12]}  |  mrma.experiment/v1  |  {duration_ms:.0f} ms[/muted]")
    return 0


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
    runp.set_defaults(func=cmd_run)

    experiment = sub.add_parser(
        "experiment",
        help="Test one mutation with repeated, counterbalanced controls",
        description=(
            "Run an interleaved AB/BA experiment and reject unstable evidence. "
            "Header values are redacted from result metadata."
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
        "--set-header",
        action="append",
        help="Set a mutation header 'Name: value' (repeatable)",
    )
    experiment.add_argument(
        "--remove-header",
        action="append",
        help="Remove a mutation header by name (repeatable)",
    )
    experiment.add_argument("--rounds", type=int, default=5, help="Paired rounds (3-100)")
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
        help="Mutation change rate required for an influence verdict",
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
    experiment.add_argument("--timeout", type=float, default=15.0)
    add_redirect_flags(experiment, default_follow=False)
    experiment.add_argument("--insecure", action="store_true", help="Disable TLS verification")
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

    isr.set_defaults(func=cmd_isolate_remove)
    
    imp = sub.add_parser("impact", help="Run a safe mutation set and rank what changes the response")
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
    sec.set_defaults(func=cmd_profile_security_headers)
    
    px = prof_sub.add_parser(
        "proxy-trust",
        help="Detect whether the target trusts proxy/forwarded headers (safe)",
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

    px.set_defaults(func=cmd_profile_proxy_trust)
    
    hr = prof_sub.add_parser(
      "host-routing",
      help="Detect whether the target trusts host-related headers (safe)",
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

    rc = args.func(args)
    raise SystemExit(rc)
