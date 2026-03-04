from __future__ import annotations

Header = tuple[str, str]

def render_raw_request(method: str, path: str, headers: list[Header], body: bytes | None = None) -> str:
    lines = [f"{method} {path} HTTP/1.1"]
    for k, v in headers:
        lines.append(f"{k}: {v}")
    lines.append("")  # blank line
    if body:
        try:
            lines.append(body.decode("utf-8", errors="replace"))
        except Exception:
            # binary-ish body; don't print
            pass
    return "\r\n".join(lines) + "\r\n"
