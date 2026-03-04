# mrma report

- URL: `https://0xmrma.com/`
- Generated: `2026-03-04T05:45:46.990120+00:00`

## Baseline

- Status: `200`
- Length: `14746`
- SHA256: `d759f3d37089cee81e1aaf2b38284e84a9608a55cc9992e349b5d3cb040c743f`

## Top deltas (impact)

| Mutation | Verdict | Similarity | Status | Len |
|---|---:|---:|---:|---:|
| set-accept-encoding-br | CHANGED | 0.00573271228950197 | 200→200 | 14746→4275 |
| remove-user-agent | EQUIV | 1.0 | 200→200 | 14746→14746 |
| remove-accept | EQUIV | 1.0 | 200→200 | 14746→14746 |
| remove-accept-encoding | EQUIV | 1.0 | 200→200 | 14746→14746 |
| remove-accept-language | EQUIV | 1.0 | 200→200 | 14746→14746 |
| set-accept-any | EQUIV | 1.0 | 200→200 | 14746→14746 |
| set-accept-html | EQUIV | 1.0 | 200→200 | 14746→14746 |
| set-accept-encoding-gzip | EQUIV | 1.0 | 200→200 | 14746→14746 |
| set-accept-encoding-identity | EQUIV | 1.0 | 200→200 | 14746→14746 |

## Security headers

- Score: `17` (0 best)
- OK/WEAK/MISSING: `0/1/8`

| Header | Status | Note |
|---|---:|---|
| Strict-Transport-Security | WEAK | max-age=63072000 but missing includeSubDomains (recommended) |
| Content-Security-Policy | MISSING | Helps mitigate XSS and data injection |
| X-Frame-Options | MISSING | Clickjacking protection (or use CSP frame-ancestors) |
| X-Content-Type-Options | MISSING | Recommended: nosniff |
| Referrer-Policy | MISSING | Controls referrer leakage |
| Permissions-Policy | MISSING | Optional hardening (recommended) |
| Cross-Origin-Opener-Policy | MISSING | Optional hardening |
| Cross-Origin-Embedder-Policy | MISSING | Optional hardening |
| Cross-Origin-Resource-Policy | MISSING | Optional hardening |

## Proxy-trust

| Case | Verdict | Similarity | Status | Location change |
|---|---:|---:|---:|---:|
| xfp-http | EQUIV | 1.0 | 200→200 | no |
| xfp-https | EQUIV | 1.0 | 200→200 | no |
| xfh-fakehost | EQUIV | 1.0 | 200→200 | no |
| xff-localhost | EQUIV | 1.0 | 200→200 | no |
| xrealip-localhost | EQUIV | 1.0 | 200→200 | no |
| forwarded-combo | EQUIV | 1.0 | 200→200 | no |

## Host-routing

| Case | Verdict | Similarity | Status | Location change |
|---|---:|---:|---:|---:|
| xfh-fakehost | EQUIV | 1.0 | 200→200 | no |
| xoriginalhost-fakehost | EQUIV | 1.0 | 200→200 | no |
| xhost-fakehost | EQUIV | 1.0 | 200→200 | no |
| forwarded-host | EQUIV | 1.0 | 200→200 | no |
