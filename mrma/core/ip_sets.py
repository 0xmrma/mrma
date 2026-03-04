from __future__ import annotations


def ip_set(name: str) -> list[str]:
    name = (name or "basic").lower().strip()

    if name == "basic":
        return [
            "127.0.0.1",
            "10.0.0.1",
        ]

    if name == "extended":
        return [
            "127.0.0.1",
            "127.1",
            "127.0.1.1",
            "::1",
            "0:0:0:0:0:0:0:1",
            "2130706433",          # decimal form of 127.0.0.1 (some stacks)
            "169.254.169.254",     # metadata IP (detection only)
        ]

    raise ValueError(f"Unknown ip-set: {name!r}")
