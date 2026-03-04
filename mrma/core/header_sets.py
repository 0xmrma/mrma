from __future__ import annotations

Header = tuple[str, str]

def common_headers() -> list[Header]:
    return [
        ("User-Agent", "mrma/0.1"),
        ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Accept-Encoding", "gzip, deflate, br"),
        ("Cache-Control", "no-cache"),
        ("Pragma", "no-cache"),
        ("Connection", "close"),
        ("Upgrade-Insecure-Requests", "1"),
    ]
