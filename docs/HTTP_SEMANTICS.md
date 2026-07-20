# HTTP Semantics

## Scope

The registry version is `http-semantics/2.0`. MRMA compares semantic HTTP observations, not wire
syntax. Its rules are grounded in [HTTP Semantics (RFC 9110)](https://www.rfc-editor.org/rfc/rfc9110),
[JSON (RFC 8259)](https://www.rfc-editor.org/rfc/rfc8259),
[XML media types (RFC 7303)](https://www.rfc-editor.org/rfc/rfc7303), and
[JavaScript media types (RFC 9239)](https://www.rfc-editor.org/rfc/rfc9239).

## Charset resolution

| Media type | Missing charset policy |
|---|---|
| `application/json`, `*+json` | UTF-8; a non-UTF-8 HTTP charset is rejected |
| `text/plain` | US-ASCII |
| other `text/*` | Digest-only, even when a charset is declared; registry has no subtype rule |
| `application/xml`, `text/xml`, `*+xml` | Bounded BOM/declaration resolution; UTF-8 default; conflicts rejected |
| JavaScript registry types | BOM, declared charset, then UTF-8 default; conflicts rejected |
| `application/x-www-form-urlencoded` | Digest-only unless charset is explicit |
| missing, malformed, unsupported | Digest-only unless the explicit missing-type text override is selected |

Decoding is strict. Replacement characters are never inserted. UTF-32 XML is intentionally not
eligible in v0.4. `CharsetResolution` records declared media/charset, resolved charset, source,
eligibility, reasons, and registry version.

## Content-Type equivalence

The parser handles quoted delimiters and escapes, token grammar, duplicate/conflicting parameters,
case-insensitive type/subtype and parameter names, charset aliases, equivalent token/quoted values,
and order-independent parameters. Parameter values remain case-sensitive unless their semantics are
explicitly known; multipart boundary case is preserved. Malformed or ambiguous declarations retain
ordered raw decision evidence.

## Field-aware response semantics

- `Vary` and named header sets compare as case-insensitive sets.
- `Allow` and CORS method sets preserve case-sensitive method tokens.
- `Cache-Control` compares parsed directive maps; duplicate/malformed directives remain ordered and
  ambiguous.
- `Location` and `Content-Location` compare canonical resolved URIs when context exists.
- `Set-Cookie` and unknown headers preserve conservative ordered values.

All-stable mode first uses budgeted controls to qualify unknown response fields. Missing or varying
fields remain volatile; promoted unknown fields use ordered comparison.

## Comparator bounds

Regex normalization uses pinned `regex==2026.7.10`, per-rule and total deadlines, and all-or-nothing
normalization. Body similarity uses bounded trigram Dice input and memory. Guarded JSON requires a
complete retained body, strict eligible decoding, duplicate-key rejection, finite numbers, and
numeric bounds. Resource failure makes comparison indeterminate and records comparator versions and
limitations.

## Raw request ingestion

`parse_raw_http_request_bytes` preserves binary body bytes, header order/duplicates, method case,
declared HTTP/1.0 or HTTP/1.1, line-ending provenance, target form, and original digest. It rejects
controls, invalid names, folding, malformed lines, and ambiguous Content-Length/Transfer-Encoding.
Authority and asterisk forms are retained but not eligible for the semantic HTTP adapter.

## Effective authority

Authorization v2 evaluates the URL authority and the effective `Host` field before every network
attempt. Multiple `Host` fields are rejected. The default policy requires `Host` to match the URL;
an alternate virtual host must be named by an explicit authority policy that also permits Host
mutation. HTTPS SNI and proxy CONNECT authority remain bound to the URL target. HTTP/2
`:authority`, when emitted by the semantic backend, is derived from the already authorized Host
semantics.

## Redirect state and fields

Redirects are authorized and budgeted one hop at a time. A logical observation owns its cookie jar
and connection scope across all redirects and retries, then isolated mode resets that state before
the next observation. On cross-origin redirects, safe-default policy retains only `Accept`,
`Accept-Language`, and `User-Agent`; every other caller-supplied field requires an explicit
allowlist entry. Method changes to `GET` or `HEAD` remove body framing, representation metadata,
digests, and configured signature fields.
