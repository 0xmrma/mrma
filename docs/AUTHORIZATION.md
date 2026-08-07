# Authorization

## Manifest contract

Network execution requires a strict authorization JSON manifest. New manifests should use
`mrma.authorization/v2`; v1 remains readable for compatibility. Unknown fields,
duplicate keys, non-finite numbers, malformed tokens, wildcards, invalid time windows, and an
incorrect optional digest are rejected.

The manifest contains engagement, issuer, subject, issue/expiry times, exact schemes/hosts/ports,
segment-bounded path prefixes, case-sensitive method tokens, operation kinds, CIDRs, body limits,
method repetition policy, proxy/redirect policy, mutation families/risk classes, and the central
budget. Version 2 additionally defines query-key rules, effective authority rules, exact header
mutation operations, and cross-origin header forwarding. A manifest must not contain secrets.

HTTP methods are case-sensitive under [RFC 9110 section 9.1](https://www.rfc-editor.org/rfc/rfc9110#section-9.1).
`GET` and `get` are different tokens. Lowercase standard-looking methods are unknown extensions and
require explicit authorization and repetition limits.

## Decision sequence

1. Validate the authorization validity window.
2. Reject URL userinfo, fragments, Unicode host conversion, encoded path octets, ambiguous query
   keys, double-encoding markers, backslashes, and parser-dependent query delimiters.
3. Resolve the effective URL, `Host`, TLS SNI, and proxy CONNECT authorities. Reject duplicate
   `Host` fields and require every mismatch to be explicitly authorized.
4. Match exact scheme, explicit ASCII A-label or IP host, effective port, path segment, query
   policy, method, operation kind, and body bound.
5. Resolve all A/AAAA answers and require every address to fall inside an allowed CIDR.
6. Validate explicit proxy name, port, and every proxy address when proxy use is enabled.
7. Enforce the higher of method risk and declared mutation risk.
8. Enforce idempotency-key, per-method repetition, and header mutation policy.
9. Return an `AuthorizedRequestContext` containing only private canonical target data and public
   fingerprints.
10. Revalidate expiry, target DNS, and proxy DNS immediately before transport.

Redirect destinations repeat the sequence. Cross-origin hops retain only `Accept`,
`Accept-Language`, and `User-Agent` by default. Additional fields require an explicit v2 allowlist.
The policy is enforced against the final HTTPX-built request, so domain cookies from the active
observation jar and explicit `Cookie` fields are suppressed unless `cookie` or `*` is explicitly
allowed. At a denied cross-origin boundary, source-origin response-cookie state is discarded before
the destination request; cookies newly issued by that destination remain available to its
same-origin continuation. When redirect semantics change a method to `GET`, body and
content/signature metadata are removed.

Legacy exploratory workflows preserve the request loaded at workflow entry as their mutation
baseline. Every outgoing addition, replacement, removal, and value size is checked against the v2
header mutation policy before an attempt is journaled or sent. Duplicate field values are compared
as ordered sequences; mixed add/replace/remove operations are all required, and reordering fails
closed because authorization v2 has no reorder operation. Mutation attempts carry a digest-bound
validation context that the transport requires independently from ordinary target authorization.

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
loopback port 8000. Authorization manifests are not signed and do not establish legal authority.
