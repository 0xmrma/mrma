from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class SecurityHeaderFinding:
    header: str          # display name (nice)
    status: str          # OK / WEAK / MISSING
    note: str            # why


def _get(h: dict[str, str], name: str) -> str | None:
    return h.get(name.lower())


def _parse_max_age(hsts_value: str) -> int | None:
    m = re.search(r"max-age\s*=\s*(\d+)", hsts_value, flags=re.IGNORECASE)
    if not m:
        return None
    try:
        return int(m.group(1))
    except Exception:
        return None

def audit_security_headers(resp_headers: dict[str, str]) -> list[SecurityHeaderFinding]:
    """
    resp_headers can be normal dict or httpx Headers; we normalize to lowercase dict.
    """
    h = {str(k).lower(): str(v) for k, v in dict(resp_headers).items()}
    out: list[SecurityHeaderFinding] = []

    def add(display: str, status: str, note: str):
        out.append(SecurityHeaderFinding(display, status, note))

    # 1) HSTS
    hsts = _get(h, "strict-transport-security")
    if not hsts:
        add("Strict-Transport-Security", "MISSING", "Recommended on HTTPS to prevent SSL stripping")
    else:
        max_age = _parse_max_age(hsts)
        has_include = "includesubdomains" in hsts.lower()
        has_preload = "preload" in hsts.lower()

        if max_age is None:
            add("Strict-Transport-Security", "WEAK", f"Present but missing max-age: {hsts}")
        else:
            # 6 months = 15768000 seconds
            if max_age < 15768000:
                add("Strict-Transport-Security", "WEAK", f"max-age too low ({max_age}); consider >= 15768000")
            elif not has_include:
                add("Strict-Transport-Security", "WEAK", f"max-age={max_age} but missing includeSubDomains (recommended)")
            else:
                note = f"max-age={max_age}"
                if has_preload:
                    note += ", preload"
                add("Strict-Transport-Security", "OK", note)

    # 2) CSP
    csp = _get(h, "content-security-policy")
    if not csp:
        add("Content-Security-Policy", "MISSING", "Helps mitigate XSS and data injection")
        csp_has_frame_ancestors = False
    else:
        low = csp.lower()
        csp_has_frame_ancestors = "frame-ancestors" in low

        if "unsafe-inline" in low or "unsafe-eval" in low:
            add("Content-Security-Policy", "WEAK", "Contains unsafe-inline/unsafe-eval")
        else:
            add("Content-Security-Policy", "OK", "Present")

    # 3) X-Frame-Options
    xfo = _get(h, "x-frame-options")
    if not xfo:
        if csp_has_frame_ancestors:
            add("X-Frame-Options", "OK", "Not present, but CSP frame-ancestors is set")
        else:
            add("X-Frame-Options", "MISSING", "Clickjacking protection (or use CSP frame-ancestors)")
    else:
        v = xfo.strip().upper()
        if v not in {"DENY", "SAMEORIGIN"}:
            add("X-Frame-Options", "WEAK", f"Unexpected value: {xfo!r}")
        else:
            add("X-Frame-Options", "OK", v)

    # 4) X-Content-Type-Options
    xcto = _get(h, "x-content-type-options")
    if not xcto:
        add("X-Content-Type-Options", "MISSING", "Recommended: nosniff")
    else:
        if xcto.strip().lower() != "nosniff":
            add("X-Content-Type-Options", "WEAK", f"Should be 'nosniff' (got {xcto!r})")
        else:
            add("X-Content-Type-Options", "OK", "nosniff")

    # 5) Referrer-Policy
    rp = _get(h, "referrer-policy")
    if not rp:
        add("Referrer-Policy", "MISSING", "Controls referrer leakage")
    else:
        low = rp.lower()
        if "unsafe-url" in low:
            add("Referrer-Policy", "WEAK", "unsafe-url is very permissive")
        else:
            add("Referrer-Policy", "OK", rp)

    # 6) Permissions-Policy
    pp = _get(h, "permissions-policy")
    if not pp:
        add("Permissions-Policy", "MISSING", "Optional hardening (recommended)")
    else:
        add("Permissions-Policy", "OK", "Present")

    # 7) Cross-Origin policies (optional hardening)
    for key, display in [
        ("cross-origin-opener-policy", "Cross-Origin-Opener-Policy"),
        ("cross-origin-embedder-policy", "Cross-Origin-Embedder-Policy"),
        ("cross-origin-resource-policy", "Cross-Origin-Resource-Policy"),
    ]:
        v = _get(h, key)
        if not v:
            add(display, "MISSING", "Optional hardening")
        else:
            add(display, "OK", v)

    return out
