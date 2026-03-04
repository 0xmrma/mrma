from __future__ import annotations

from .mutations import Mutation

Header = tuple[str, str]

# Smart defaults for name-only entries
DEFAULT_VALUES: dict[str, str] = {
    "x-forwarded-for": "127.0.0.1",
    "x-real-ip": "127.0.0.1",
    "true-client-ip": "127.0.0.1",
    "cf-connecting-ip": "127.0.0.1",
    "x-forwarded-proto": "http",
    "x-forwarded-host": "example.invalid",
    "x-original-host": "example.invalid",
    "x-host": "example.invalid",
    "forwarded": 'for=127.0.0.1;proto=http',
    "cache-control": "no-cache",
    "pragma": "no-cache",
    "if-none-match": "*",
}

def parse_pack_file(path: str, mode: str = "set") -> list[Mutation]:
    """
    mode:
      - set: each line becomes a header SET mutation
      - remove: each line becomes a header REMOVE mutation (value ignored)
    File lines can be:
      - "Header: value"
      - "HeaderName" (uses DEFAULT_VALUES if known, otherwise "1")
    Ignores blank lines and comments (# ...).
    """
    mode = (mode or "set").lower().strip()
    if mode not in {"set", "remove"}:
        raise ValueError(f"Unknown pack-file mode: {mode!r}")

    muts: list[Mutation] = []

    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            raw = line.strip()
            if not raw or raw.startswith("#"):
                continue

            if ":" in raw:
                k, v = raw.split(":", 1)
                name = k.strip()
                value = v.lstrip()
            else:
                name = raw.strip()
                value = DEFAULT_VALUES.get(name.lower(), "1")

            if mode == "remove":
                muts.append(Mutation(name=f"packfile-remove-{name.lower()}", remove=name))
            else:
                muts.append(Mutation(name=f"packfile-set-{name.lower()}", set_header=(name, value)))

    return muts
