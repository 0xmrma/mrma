# Security policy

## Supported versions

MRMA is a research preview. Only the latest patch release receives security fixes.

## Reporting a vulnerability

Use the repository's private GitHub Security Advisory reporting flow. Do not open a public issue
for a vulnerability that could expose target evidence, credentials, or a method for bypassing the
tool's authorization and request-budget controls.

Include the affected version, platform, minimal reproduction, expected security property, and
whether evidence artifacts may contain sensitive data. Remove real credentials and target data.

## Scope

Security reports include secret exposure in default evidence, scope or rate-limit bypass,
unexpected cross-observation state, unsafe request replay, dependency compromise, and malformed
input that causes unbounded CPU, memory, disk, or network use.
