from __future__ import annotations

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

MRMA_THEME = Theme(
    {
        "brand": "bold bright_cyan",
        "signal": "bright_cyan",
        "muted": "grey58",
        "safe": "green",
        "warning": "yellow",
        "danger": "bold red",
    }
)

console = Console(theme=MRMA_THEME, highlight=False)


def print_home(version: str) -> None:
    title = Text.assemble(("MRMA", "brand"), ("  /  TRUST BOUNDARY LAB", "bold white"))
    subtitle = Text("Evidence-driven HTTP influence analysis", style="muted")
    identity = Table.grid(expand=True)
    identity.add_column()
    identity.add_column(justify="right", no_wrap=True)
    identity.add_row(title, Text(f"v{version}", style="muted"))
    identity.add_row(subtitle, Text("AUTHORIZED RESEARCH ONLY", style="warning"))
    console.print(Panel(identity, border_style="bright_cyan", box=box.SQUARE, padding=(0, 1)))

    workflows = Table(
        box=box.SIMPLE_HEAD,
        header_style="muted",
        show_edge=False,
        pad_edge=False,
        expand=True,
    )
    workflows.add_column("WORKFLOW", style="brand", no_wrap=True, width=14)
    workflows.add_column("COMMAND", style="bold white", no_wrap=True, width=20)
    workflows.add_column("PURPOSE")
    workflows.add_row("ESTABLISH", "mrma run", "Capture a baseline or measure repeat stability")
    workflows.add_row("PROVE", "mrma experiment", "Run counterbalanced controls and mutations")
    workflows.add_row("SURVEY", "mrma impact", "Rank safe mutation families by response influence")
    workflows.add_row("MINIMIZE", "mrma isolate", "Reduce an influence signal to its smallest input")
    workflows.add_row("MODEL", "mrma profile", "Evaluate proxy, host-routing, and policy behavior")
    console.print(workflows)
    console.print("[muted]Start:[/muted] mrma experiment --help")


def verdict_style(verdict: str) -> str:
    if verdict == "INFLUENCE_DETECTED":
        return "danger"
    if verdict == "NO_INFLUENCE_OBSERVED":
        return "safe"
    return "warning"
