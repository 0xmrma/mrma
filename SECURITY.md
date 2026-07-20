# Security policy

## Supported versions

MRMA is a research tool. Only the latest patch release receives security fixes.

## Reporting a vulnerability

Use the repository's private GitHub Security Advisory reporting flow. Do not open a public issue
for a vulnerability that could expose target evidence or credentials.

MRMA v0.4 requires a strict authorization manifest and central budget for every network workflow.
Authorization or budget bypass, uncharged retries/redirects/hooks, decisive partial results, and
secret leakage in standard/strict v7 evidence are security defects. The manifest is an unsigned
local policy object and is not proof of legal authority.

Include the affected version, platform, minimal reproduction, expected security property, and
whether evidence artifacts may contain sensitive data. Remove real credentials, executable
authorization grants, target values, and local paths.

## Scope

Security reports include secret exposure in default evidence, unexpected cross-observation state,
unsafe request replay, dependency or release-control compromise, malformed input that causes
unbounded CPU, memory, disk, or network use, evidence-chain/bundle verification errors, and
authorization-to-socket confusion. Wire-level normalization inherent to the documented semantic
HTTPX adapter is not itself a defect unless MRMA labels it exact or violates a stated invariant.

## Security boundaries

MRMA does not sign authorization manifests, encrypt evidence, bind authorized DNS answers to the
eventual HTTPX socket, or provide protocol-exact HTTP. Review
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) before reporting a limitation as a bypass.
