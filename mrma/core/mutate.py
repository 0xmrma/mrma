from __future__ import annotations

from dataclasses import replace

from .raw_request import RawRequest


def remove_header(req: RawRequest, name: str) -> RawRequest:
    nl = name.lower()
    new_headers = [(k, v) for (k, v) in req.headers if k.lower() != nl]
    return replace(req, headers=new_headers)

def set_header(req: RawRequest, name: str, value: str, override: bool = True) -> RawRequest:
    nl = name.lower()
    new_headers: list[tuple[str, str]] = []
    replaced = False
    for k, v in req.headers:
        if k.lower() == nl:
            if override and not replaced:
                new_headers.append((name, value))
                replaced = True
            else:
                # drop duplicates if overriding; keep if not
                if not override:
                    new_headers.append((k, v))
        else:
            new_headers.append((k, v))
    if not replaced:
        new_headers.append((name, value))
    return replace(req, headers=new_headers)
