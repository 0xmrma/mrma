# mrma

<img width="830" height="260" alt="photo0" src="https://github.com/user-attachments/assets/753d9c41-74d1-4e62-af0c-e700ce824d9a" />


**HTTP Trust Boundary Analyzer** — replay requests, mutate headers safely, and quantify response influence (**authorized testing only**).

mrma helps answer: *“Does this target trust proxy/host headers or behave differently based on request metadata?”*  
It focuses on **meaningful diffs** (not just status/length), plus **profiles** that model common trust-boundary behaviors.

---

## Install

### pipx (recommended)

```bash
pipx install .
mrma --version
```

### dev / editable

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
mrma --version
```

**Note**:If your system CA store is broken or you’re testing lab/self-signed certs, use --insecure.

---

## Quick start
### 1) Baseline fingerprint

```bash
mrma run --url https://example.com --follow-redirects
```

### 2) Find the biggest response deltas (safe mutations)

```bash
mrma impact --url https://example.com --follow-redirects --top-deltas 10
```

### 3) Compare baseline vs a single mutation (diff)

```bash
mrma diff --url https://example.com --follow-redirects --set-header "X-Test: 1"
```

### 4) Minimal required header set (delta debugging)

```bash
mrma discover --url https://example.com --follow-redirects --print-minimal-request
```

### 5) Minimal header removals that cause a change (ddmin)

```bash
mrma isolate-remove --url https://example.com --follow-redirects \
  --pack-file remove_headers.txt --preset dynamic --delay 0.2
```

---

## Why this is different

Most tooling stops at: status code, length, or manual diffing.

mrma adds:

- **Preset-aware normalization** (`default`, `dynamic`, `nextjs`, `api-json`)
- **Noise controls**: `--ignore-header`, `--ignore-body-regex`
- **Stability measurement**: `run --repeat` (great for dynamic targets)
- **Trust-boundary profiles**:
  - `profile proxy-trust` (forwarded/proxy headers)
  - `profile host-routing` (host-related routing headers)
- **One-command reporting**:
  - `mrma report` → `mrma_report.json` + `mrma_report.md`
**Operational polish**:
  - rate limiting + retries (`--rps`, `--retries`)
  
---

## Curated packs

List packs:

```bash
mrma pack list
```

Proxy trust pack (extended):

```bash
mrma impact --url https://example.com --follow-redirects \
  --pack proxy --depth extended --ip-set extended --top-deltas 15 --delay 0.2
```

---

## Raw request mode (exact reproduction)

Replay a raw HTTP request file:

```bash
mrma run -r req.txt -u https://example.com --follow-redirects
```

Discover minimal request from a raw request:

```bash
mrma discover -r req.txt -u https://example.com --follow-redirects --print-minimal-request
```

---

## Ignore rules (reduce noise)

Ignore volatile headers:

```bash
mrma diff --url https://example.com --follow-redirects --set-header "X-Test: 1" \
  --ignore-header set-cookie --ignore-header date --ignore-header etag
```

Ignore noisy dynamic content using regex:

```bash
mrma diff --url https://example.com --follow-redirects --set-header "X-Test: 1" \
  --ignore-body-regex '"nonce"\s*:\s*"[A-Za-z0-9\-_]+"' \
  --ignore-body-regex '"requestId"\s*:\s*"[A-Za-z0-9\-_]+"'
```

---

## Reporting

Generate a compact report:

```bash
mrma report --url https://example.com --follow-redirects --top-deltas 10
ls -la mrma_report.*
```

Terminal-friendly Markdown viewing (optional):

```bash
sudo apt update && sudo apt install -y glow
glow -p mrma_report.md
```

---

## JSON output

Most commands support `--json`:

```bash
mrma impact --url https://example.com --pack proxy --top-deltas 5 --json
```

---

## Config

Global config:

- `~/.config/mrma/config.toml`

Local (per-project):

- `./mrma.toml`

Show merged config:

```bash
mrma config --json
```

Example:

```toml
[defaults]
preset = "dynamic"
timeout = 15.0
min_similarity = 0.97
max_len_delta_ratio = 0.05

[impact]
delay = 0.2
ip_set = "basic"
ignore_headers = ["set-cookie", "date", "etag"]
```


**Tip**: disable config for a single run:

```bash
mrma impact --url https://example.com --no-config
```

---

## Safety / legal

- Use only on targets you are authorized to test.
- These mutations are designed to be low-risk by default, but responsibility is yours.

---

## Author

- author: **0xMRMA**
- site: https://0xmrma.com
