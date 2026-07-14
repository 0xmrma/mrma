# MRMA

**Evidence-driven HTTP trust-boundary experimentation for authorized security research.**

MRMA determines whether an attacker-controlled request property reproducibly changes behavior
across a layered HTTP system, then helps reduce that signal to the smallest responsible input.
It is not a generic vulnerability scanner and it does not treat a one-off response difference as
a finding.

> Status: `0.3.0` research preview. The experiment workflow is ready for controlled evaluation;
> the broader command set is still being migrated to the same evidence standard.

## The flagship workflow

Test a single trust-boundary hypothesis with five unchanged controls and five mutations:

```bash
mrma experiment \
  --url https://target.example/account \
  --set-header "X-Forwarded-Host: example.invalid" \
  --rounds 5 \
  --preset dynamic
```

MRMA counterbalances request order (`AB/BA`), reuses one semantic HTTP session, measures unchanged
control drift, and returns one of three verdicts:

- `INFLUENCE_DETECTED`: the mutation crossed the configured threshold reproducibly.
- `NO_INFLUENCE_OBSERVED`: no repeatable change was observed under this experiment.
- `INCONCLUSIVE`: controls were unstable or mutation evidence was mixed.

The result includes:

- mutation reproducibility with a 95% Wilson interval;
- control instability;
- control-versus-mutation similarity contrast;
- status and meaningful response-header shifts;
- a short run ID and evidence schema version.

Mutation values, URL credentials, query strings, and response-header values are redacted or hashed
in result metadata. For automation, emit the complete versioned evidence object:

```bash
mrma experiment \
  --url https://example.com \
  --set-header "X-Forwarded-For: 127.0.0.1" \
  --json --out-json evidence.json
```

The output declares `mrma.experiment/v1` and labels the transport as `semantic-http`. MRMA currently
uses `httpx`, so it does not claim byte-for-byte HTTP/1 wire reproduction.

## Container package

MRMA is published as a non-root multi-architecture container through GitHub Container Registry:

```bash
docker pull ghcr.io/0xmrma/mrma:0.3.0
docker run --rm ghcr.io/0xmrma/mrma:0.3.0 --version
```

Run an authorized experiment from the container:

```bash
docker run --rm ghcr.io/0xmrma/mrma:0.3.0 \
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
rounds = 7
min_similarity = 0.985
max_len_delta_ratio = 0.02
min_reproducibility = 0.8
max_control_change_rate = 0.2
ignore_headers = ["x-request-id"]
```

## Research direction

The [research position](docs/RESEARCH_POSITION.md) compares MRMA with Burp, Param Miner,
AutoRepeater, ZAP, Nuclei, mitmproxy, Turbo Intruder, HTTP Request Smuggler, HTTP Garden, and
Gudifu. The [roadmap](docs/ROADMAP.md) separates implemented capabilities from the planned Trust
Influence Graph, stability-aware minimization, protocol transports, and enterprise controls.

## Safety

- Test only targets for which you have explicit authorization.
- Start with low request rates and a small mutation set.
- Do not treat influence as exploitability or severity.
- Review requests that can alter state before replaying them.
- Preserve the evidence, configuration, and transport label when reporting a result.

## Author

Mohamed Abdelaal / [0xMRMA](https://0xmrma.com)
