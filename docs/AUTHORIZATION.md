# Authorization

## Manifest contract

Research networking requires a strict `mrma.authorization/v1` JSON manifest. Unknown fields,
duplicate keys, non-finite numbers, malformed tokens, wildcards, invalid time windows, and an
incorrect optional digest are rejected.

The manifest contains engagement, issuer, subject, issue/expiry times, exact schemes/hosts/ports,
segment-bounded path prefixes, case-sensitive method tokens, operation kinds, CIDRs, body limits,
method repetition policy, proxy/redirect policy, mutation families/risk classes, and the central
budget. It must not contain secrets.

HTTP methods are case-sensitive under [RFC 9110 section 9.1](https://www.rfc-editor.org/rfc/rfc9110#section-9.1).
`GET` and `get` are different tokens. Lowercase standard-looking methods are unknown extensions and
require explicit authorization and repetition limits.

## Decision sequence

1. Validate the authorization validity window.
2. Canonicalize the semantic target and reject URL userinfo.
3. Match exact scheme, IDNA host, effective port, path segment, method, operation kind, and body
   bound.
4. Resolve all A/AAAA answers and require every address to fall inside an allowed CIDR.
5. Validate explicit proxy name, port, and every proxy address when proxy use is enabled.
6. Enforce the higher of method risk and declared mutation risk.
7. Enforce idempotency-key and per-method repetition policy.
8. Return an `AuthorizedRequestContext` containing only private canonical target data and public
   fingerprints.
9. Revalidate expiry, target DNS, and proxy DNS immediately before transport.

Redirect destinations repeat the sequence. Same-origin and cross-origin behavior is selected by the
manifest; credentials are stripped cross-origin unless explicit policy permits forwarding.

## Hooks and state-changing methods

Setup and reset hooks require the operation kind, method, target, CIDR, and budget to be authorized.
Their rule must declare `disposable_environment: true`. Repeated POST, PATCH, PUT, DELETE, CONNECT,
TRACE, and unknown methods require `maximum_repetitions_by_method`; selected methods can also
require `Idempotency-Key`.

## Proxy and environment policy

Ambient transport configuration is rejected in v0.4. `--trust-environment` exists only to return a
clear policy error. Use `--proxy` and `--ca-bundle`; evidence stores endpoint/keyed fingerprints and
CA digests, not values or paths.

## Operational guidance

Keep manifests short-lived and generated under an external approval process. Restrict paths,
methods, operation kinds, CIDRs, and budgets to the exact design. The local example authorizes only
loopback port 8000. Authorization v1 is not signed and does not establish legal authority.
