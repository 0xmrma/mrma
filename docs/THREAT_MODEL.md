# Threat Model

## Assets and security properties

MRMA protects target scope, request budgets, credentials, private evidence values, experiment
integrity, and the distinction between complete and incomplete research. The primary properties are:

1. no network attempt without authorization, lease, and journal context;
2. no redirect, retry, or hook outside the same policy path;
3. no decisive result from incomplete fixed sampling;
4. no configured secrets or local paths in public v7 evidence;
5. no exact-transport claim from semantic replay.

## Considered threats

- Malicious or mistaken targets, including DNS answers that move outside allowed CIDRs.
- Redirects into unauthorized hosts, paths, ports, or address ranges.
- Ambient proxy/CA environment variables that silently alter transport.
- Repetition of state-changing or extension methods beyond approval.
- Retry, redirect, hook, response, byte, duration, or concurrency budget bypass.
- Crash, interruption, partial write, journal reorder, or bundle modification.
- Malformed JSON, raw requests, media types, headers, and adversarial comparator input.
- Evidence leakage through URLs, headers, proxy credentials, authorization grant data, environment
  values, or local paths.
- False certainty caused by unstable controls, incomplete bodies, transport failures, or exhausted
  comparator resources.

## Trust assumptions

The local operator, Python process, operating system, resolver, CA store, and installed MRMA artifact
are trusted. The issuer is responsible for legal and organizational authority. A manifest proves
only that MRMA accepted a local policy document; v1 does not authenticate its issuer.

The target and network may be hostile. MRMA re-resolves immediately before transport, but HTTPX may
resolve again internally and does not expose a supported address-pinning interface. Therefore an
authorized DNS set cannot be cryptographically bound to the eventual socket. This is an explicit
moderate limitation.

## Out of scope for v0.4

- Compromise of the host or Python process.
- Secret storage or encrypted evidence at rest.
- Signed organizational authorization grants and remote policy distribution.
- Wire-level request smuggling, HTTP/1 parser differential, or HTTP/2 stream experiments.
- Proving which intermediary made a black-box decision.
- Proving exploitability, business impact, or absence of a vulnerability.
- Distributed coordination, multi-user review, retention, or enterprise operations.

## Fail-closed behavior

Policy rejection stops before the next attempt. Budget exhaustion releases active reservations and
returns partial `INCONCLUSIVE` evidence. Comparator limits make the affected comparison
indeterminate. Unknown media semantics use digest-only evidence. Journal and bundle verification
reject duplicate keys, non-finite numbers, malformed chains, unknown entries, and incompatible
schemas.
