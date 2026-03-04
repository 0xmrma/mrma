from __future__ import annotations

from dataclasses import dataclass

Header = tuple[str, str]

@dataclass
class Mutation:
    name: str
    remove: str | None = None
    set_header: Header | None = None

def default_mutations() -> list[Mutation]:
    return [
        Mutation(name="remove-user-agent", remove="User-Agent"),
        Mutation(name="remove-accept", remove="Accept"),
        Mutation(name="remove-accept-encoding", remove="Accept-Encoding"),
        Mutation(name="remove-accept-language", remove="Accept-Language"),
        Mutation(name="set-accept-any", set_header=("Accept", "*/*")),
        Mutation(name="set-accept-html", set_header=("Accept", "text/html")),
        Mutation(name="set-accept-encoding-br", set_header=("Accept-Encoding", "br")),
        Mutation(name="set-accept-encoding-gzip", set_header=("Accept-Encoding", "gzip")),
        Mutation(name="set-accept-encoding-identity", set_header=("Accept-Encoding", "identity")),
    ]
