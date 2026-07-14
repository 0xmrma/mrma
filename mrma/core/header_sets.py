from __future__ import annotations

from .. import __version__

Header = tuple[str, str]


def common_headers() -> list[Header]:
    return [
        ("User-Agent", f"mrma/{__version__}"),
        ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Accept-Encoding", "gzip, deflate, br"),
        ("Cache-Control", "no-cache"),
        ("Pragma", "no-cache"),
        ("Connection", "close"),
        ("Upgrade-Insecure-Requests", "1"),
    ]
