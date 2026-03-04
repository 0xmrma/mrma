from __future__ import annotations

from dataclasses import dataclass

from .ip_sets import ip_set
from .mutations import Mutation

Header = tuple[str, str]

@dataclass
class Pack:
    name: str
    description: str

def list_packs() -> list[Pack]:
    return [
        Pack("baseline", "Small safe set: UA/Accept/Accept-Language/Accept-Encoding toggles"),
        Pack("proxy", "Forwarded/proxy header influence tests (X-Forwarded-*, Forwarded, etc.)"),
        Pack("host", "Host-related header influence tests (X-Forwarded-Host, X-Original-Host, etc.)"),
        Pack("cache", "Cache-key and vary related toggles (Cache-Control, Pragma, If-None-Match, etc.)"),
    ]

def mutations_for_pack(name: str, depth: str = "basic", ipset: str = "basic") -> list[Mutation]:
    name = name.lower().strip()
    depth = depth.lower().strip()

    if name == "baseline":
        from .mutations import default_mutations
        return default_mutations()

    if name == "proxy":
        ips = ip_set(ipset)

        muts: list[Mutation] = []

        # For each IP, generate a few high-signal headers
        for ip in ips:
            muts.append(Mutation(f"set-x-forwarded-for-{ip}", set_header=("X-Forwarded-For", ip)))
            muts.append(Mutation(f"set-x-real-ip-{ip}", set_header=("X-Real-IP", ip)))

            if depth == "extended":
                muts.append(Mutation(f"set-true-client-ip-{ip}", set_header=("True-Client-IP", ip)))
                muts.append(Mutation(f"set-cf-connecting-ip-{ip}", set_header=("CF-Connecting-IP", ip)))

                # Forwarded header variants
                if ":" not in ip:  # skip IPv6 forms to keep output readable
                    muts.append(Mutation(f"set-forwarded-for-{ip}", set_header=("Forwarded", f"for={ip};proto=http")))

        # Proto/scheme/port toggles (not per-IP)
        muts += [
            Mutation("set-x-forwarded-proto-http", set_header=("X-Forwarded-Proto", "http")),
            Mutation("set-x-forwarded-proto-https", set_header=("X-Forwarded-Proto", "https")),
        ]
        if depth == "extended":
            muts += [
                Mutation("set-x-forwarded-port-80", set_header=("X-Forwarded-Port", "80")),
                Mutation("set-x-forwarded-scheme-http", set_header=("X-Forwarded-Scheme", "http")),
                Mutation("set-forwarded-host-fake", set_header=("Forwarded", 'host="example.invalid"')),
            ]

        return muts

    if name == "host":
        muts = [
            Mutation("set-x-forwarded-host-fake", set_header=("X-Forwarded-Host", "example.invalid")),
            Mutation("set-x-original-host-fake", set_header=("X-Original-Host", "example.invalid")),
            Mutation("set-x-host-fake", set_header=("X-Host", "example.invalid")),
            Mutation("set-forwarded-host-fake", set_header=("Forwarded", 'host="example.invalid"')),
        ]
        if depth == "extended":
            muts += [
                Mutation("set-x-forwarded-server-fake", set_header=("X-Forwarded-Server", "example.invalid")),
                Mutation("set-x-forwarded-uri-root", set_header=("X-Forwarded-Uri", "/")),
            ]
        return muts

    if name == "cache":
        muts = [
            Mutation("set-cache-control-no-cache", set_header=("Cache-Control", "no-cache")),
            Mutation("set-cache-control-max-age-0", set_header=("Cache-Control", "max-age=0")),
            Mutation("set-pragma-no-cache", set_header=("Pragma", "no-cache")),
            Mutation("set-if-none-match-star", set_header=("If-None-Match", "*")),
            Mutation("remove-if-none-match", remove="If-None-Match"),
        ]
        if depth == "extended":
            muts += [
                Mutation("set-if-modified-since", set_header=("If-Modified-Since", "Wed, 21 Oct 2015 07:28:00 GMT")),
                Mutation("set-range-0-0", set_header=("Range", "bytes=0-0")),
            ]
        return muts

    raise ValueError(f"Unknown pack: {name!r}")
