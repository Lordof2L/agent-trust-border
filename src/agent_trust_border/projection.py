"""Downstream human projection. It cannot influence the receiver verdict."""

from __future__ import annotations

import io
from collections.abc import Sequence

from rich.console import Console
from rich.table import Table


def render_trace_html(rows: Sequence[dict]) -> str:
    buffer = io.StringIO()
    console = Console(
        file=buffer,
        record=True,
        force_terminal=True,
        color_system="truecolor",
        width=120,
    )
    console.print("[bold blue]Agent Trust Border[/bold blue] — synthetic offline trace")
    console.print(
        "[dim]Integrity, identity, authority, evidence and world truth remain separate. "
        "No requested action is executed.[/dim]\n"
    )
    table = Table(show_header=True, header_style="bold", box=None)
    table.add_column("Step", style="bold")
    table.add_column("Verdict")
    table.add_column("Reason")
    table.add_column("Effective scope")
    table.add_column("Action")
    for row in rows:
        resources = row["effective_scope"]["resources"]
        scope = ", ".join(resources) if resources else "none"
        verdict = row["verdict"]
        verdict_style = {
            "ADMIT": "green",
            "DENY": "red",
            "UNKNOWN": "yellow",
        }.get(verdict, "white")
        table.add_row(
            row["step"],
            f"[{verdict_style}]{verdict}[/{verdict_style}]",
            ", ".join(row["reason_codes"]),
            scope,
            "not executed",
        )
    console.print(table)
    console.print(
        "\n[dim]Boundary: synthetic pinned adapter fixture; real DSSE/Ed25519 grant and "
        "receipt operations; no live A2A/GB/Z conformance and no world-truth claim.[/dim]"
    )
    html = console.export_html(inline_styles=True)
    return "\n".join(line.rstrip() for line in html.splitlines()) + "\n"
