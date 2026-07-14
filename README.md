# MRMA

**Evidence-driven HTTP trust-boundary experimentation for authorized security research.**

MRMA determines whether an attacker-controlled request property reproducibly changes behavior
across a layered HTTP system, then helps reduce that signal to the smallest responsible input.
It is not a generic vulnerability scanner and it does not treat a one-off response difference as
a finding.

> Status: `0.3.4` research preview. `mrma experiment` has a conservative evidence contract;
> legacy survey and minimization commands do not yet share this oracle.

## The flagship workflow

Test a single trust-boundary hypothesis with a predeclared 20-round sample. Each mutation is
locally bracketed by an unchanged control before and after it (60 requests at the default):

```bash
mrma experiment \
  --url https://target.example/account \
  --set-header "X-Forwarded-Host: example.invalid" \
  --preset dynamic \
  --assurance research
```

MRMA isolates response-cookie state between observations by default, measures local control drift,
and returns one of three verdicts:

- `INFLUENCE_DETECTED`: the mutation's 95% lower confidence bound crossed the influence threshold.
- `NO_INFLUENCE_OBSERVED`: its 95% upper bound stayed below the no-influence threshold.
- `INCONCLUSIVE`: controls were unstable or mutation evidence was mixed.

Neither influence nor no influence is a safety, exploitability, or severity claim.

The default thresholds deliberately require perfect fixed-sample observations:

| Default 20-round result | Possible verdict |
|---|---|
| `20/20` mutation changes with stable controls | `INFLUENCE_DETECTED` |
| `0/20` mutation changes with stable controls | `NO_INFLUENCE_OBSERVED` |
| `1/20` through `19/20`, or unstable evidence | `INCONCLUSIVE` |

The CLI prints these operating characteristics before sending the default 60 requests.

The result includes:

- mutation reproducibility with a decision-bearing 95% Wilson interval;
- independent control-before/control-after stability intervals;
- control-versus-mutation similarity contrast;
- typed transport outcomes, canonical decision-bearing redirect targets, retry error subtypes,
  status shifts, and field-aware response-header evidence;
- the effective normalization policy, state and connection modes, response bound, complete retry
  policy, negotiated HTTP versions, and stop reason;
- a multidimensional assurance profile for statistical decisiveness, control stability,
  connection independence, state isolation, body completeness, normalization risk, and transport
  reproducibility, without a scalar confidence label;
- structured limitation codes with severity, scope, explanation, and remediation;
- a short run ID and evidence schema version.

The default privacy policy masks paths and internal hosts, buckets size/timing values, and uses a
fresh per-run HMAC key for query, body, redirect, header-value, and normalization-rule
fingerprints. Standard run timestamps are reduced to minute precision; strict evidence retains only
the date and a broad duration bucket. Use `--redaction-policy strict` to mask header names too.
`forensic` intentionally preserves clear target paths and exact size/timing metadata.

For automation, emit the complete versioned evidence object and select an opt-in failure policy:

```bash
mrma experiment \
  --url https://example.com \
  --set-header "X-Forwarded-For: 127.0.0.1" \
  --json --out-json evidence.json \
  --evidence-write durable \
  --fail-on any-signal
```

The output declares `mrma.experiment/v4`; exit code `10` means influence and `11` means
inconclusive when selected by `--fail-on`. The strict v4 JSON Schema defines every nested evidence
object and cross-field assurance invariant. Published v2 and v3 schemas remain packaged and
immutable for compatibility. The default exit code remains zero for all verdicts.
The transport is labeled `semantic-http`; MRMA uses `httpx` and does not claim byte-for-byte HTTP/1
wire reproduction.

Responses are streamed with a default 1 MiB read bound. `--body-storage sample` retains at most 64
KiB per observation. When full normalization cannot be performed, unequal digests are marked
`INDETERMINATE`; they are never silently treated as equivalent. Encoded and non-text bodies use
exact transfer-digest equality only until bounded, content-aware decoders are implemented.

Retries are disabled by default. When enabled, every intermediate attempt, outcome class,
error subtype, retry-triggering status, backoff, and final result is recorded. Stable error-subtype
and asymmetric retry differences are decision-bearing. Attempt elapsed time and configured backoff
are summarized with medians, median absolute deviations, and direction consistency as contextual
quantitative evidence; a small one-off timing difference cannot create an influence verdict.

Redirect comparison resolves and canonicalizes targets before classification. Relative and
absolute forms, default ports, host casing, dot segments, and percent-encoded unreserved
characters do not create false signals. Raw `Location` formatting is retained only as a keyed
fingerprint. Response fields use explicit semantics for `Vary`, `Allow`, CORS token sets,
`Cache-Control`, `Location`, and `Content-Location`. HTTP method tokens remain case-sensitive even
when their list order is irrelevant. Duplicate directives or malformed `Cache-Control` syntax
preserve ordered evidence and emit `AMBIGUOUS_CACHE_CONTROL`; captured fields without a registry
rule and `Set-Cookie` remain conservative ordered evidence.

Connection scope is explicit: `reuse` (default), `per-arm`, `per-round`, or `fresh-observation`.
Cookie state remains a separate policy. Wilson intervals assume repeated observations are suitably
independent; use `--connection-mode fresh-observation` when load-balancer affinity, connection-bound
authentication, HTTP/2 state, throttling, or WAF scoring could violate that assumption.

For publication-oriented work, `--assurance research` authoritatively selects fresh connections,
isolated response state, disabled retries, a 20-round bracketed design, standard privacy, and full
body retention within the configured response bound. `exploratory` preserves efficient pooled
behavior; `forensic` uses research isolation while intentionally retaining exact metadata.

JSON output uses atomic replacement. Add `--evidence-write durable` to flush and synchronize the
temporary file before replacement and synchronize the parent directory on platforms that support
directory `fsync`. The evidence object records whether directory synchronization was performed or
unsupported. This durability mode applies to experiment JSON, not legacy report files.

## Container package

MRMA is published as a non-root multi-architecture container through GitHub Container Registry:
the Python base is pinned by OCI digest and build/runtime dependencies are exact and hash-verified.

```bash
docker pull ghcr.io/0xmrma/mrma:0.3.4
docker run --rm ghcr.io/0xmrma/mrma:0.3.4 --version
```

Run an authorized experiment from the container:

```bash
docker run --rm ghcr.io/0xmrma/mrma:0.3.4 \
  experiment --url https://example.com --set-header "X-Test: 1"
```

## Workflows

| Goal | Command |
|---|---|
| Capture a fingerprint or measure repeat stability | `mrma run` |
| Prove one mutation with interleaved controls | `mrma experiment` |
| Compare one baseline and mutation quickly | `mrma diff` |
| Rank a conservative mutation family | `mrma impact` |
| Find request headers required to preserve behavior | `mrma discover` |
| Minimize added headers that cause a change | `mrma isolate` |
| Minimize removals that cause a change | `mrma isolate-remove` |
| Evaluate proxy identity trust | `mrma profile proxy-trust` |
| Evaluate host-routing influence | `mrma profile host-routing` |
| Audit browser-facing security headers | `mrma profile security-headers` |
| Export semantic requests as curl or HTTP text | `mrma export` |

Run `mrma` for the compact workflow view or `mrma <command> --help` for command details.

## Raw request input

Requests exported by Burp or another proxy can be used as experiment baselines:

```bash
mrma experiment \
  --request request.txt \
  --base-url https://example.com \
  --remove-header X-Forwarded-For
```

The current parser preserves header order and duplicate fields in the in-memory model, but
`semantic-http` replay may normalize them. Wire-accurate HTTP/1 and protocol-specific transports are
planned separately so transport claims remain honest.

## Normalization

Available body presets are `default`, `dynamic`, `nextjs`, and `api-json`. Explicit rules can remove
target-specific noise:

```bash
mrma experiment \
  --url https://example.com/api/session \
  --set-header "X-Test: 1" \
  --ignore-header x-request-id \
  --ignore-body-regex '"requestId"\s*:\s*"[^"]+"'
```

Ignoring a field means the experiment cannot use that field as evidence. Keep the rule set narrow
and record it with the result.

## Configuration

MRMA merges `~/.config/mrma/config.toml` and a local `./mrma.toml`; local settings win. Use
`--no-config` for an isolated run.

```toml
[defaults]
timeout = 15.0
preset = "dynamic"

[experiment]
min_rounds = 6
max_rounds = 20
schedule = "bracketed"
state_mode = "isolated"
connection_mode = "reuse"
max_response_bytes = 1048576
body_storage = "sample"
redaction_policy = "standard"
min_similarity = 0.985
max_len_delta_ratio = 0.02
min_reproducibility = 0.8
no_influence_threshold = 0.2
max_control_change_rate = 0.2
ignore_headers = ["x-request-id"]
```

## Research direction

The [research position](docs/RESEARCH_POSITION.md) compares MRMA with Burp, Param Miner,
AutoRepeater, ZAP, Nuclei, mitmproxy, Turbo Intruder, HTTP Request Smuggler, HTTP Garden, and
Gudifu. The [roadmap](docs/ROADMAP.md) separates implemented capabilities from the planned Trust
Influence Graph, stability-aware minimization, protocol transports, and enterprise controls.

## Safety

- MRMA 0.3.x does not enforce authorization manifests or centralized request budgets.
- Test only targets for which you have explicit authorization.
- Start with low request rates and a small mutation set.
- Do not treat influence as exploitability or severity.
- Review requests that can alter state before replaying them.
- Preserve the evidence, configuration, and transport label when reporting a result.

## Release verification

Publishing requires a signed annotated tag and approval through the protected `release`
environment. Python distributions and the container have GitHub-signed provenance; the image also
contains BuildKit provenance and SBOM manifests. Follow the
[release verification procedure](docs/RELEASE_SECURITY.md) and pin operational deployments to the
reported OCI digest rather than only a mutable version tag.

## Author

Mohamed Abdelaal / [0xMRMA](https://0xmrma.com)
