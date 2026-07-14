# Security policy

## Supported versions

MRMA is a research preview. Only the latest patch release receives security fixes.

## Reporting a vulnerability

Use the repository's private GitHub Security Advisory reporting flow. Do not open a public issue
for a vulnerability that could expose target evidence or credentials.

MRMA 0.3.x does not enforce authorization manifests or centralized request budgets. Operators are
responsible for obtaining authorization and constraining every run. These controls are explicit
v0.4 acceptance criteria; documentation must not imply that the current release prevents an
unauthorized target or excessive request count.

Include the affected version, platform, minimal reproduction, expected security property, and
whether evidence artifacts may contain sensitive data. Remove real credentials and target data.

## Scope

Security reports include secret exposure in default evidence, unexpected cross-observation state,
unsafe request replay, dependency or release-control compromise, and malformed input that causes
unbounded CPU, memory, disk, or network use. Scope or budget bypass becomes a reportable control
failure when the corresponding enforcement feature is released.
