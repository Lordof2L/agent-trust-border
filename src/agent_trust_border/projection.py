"""Deterministic downstream human projection; never an admission input."""

from __future__ import annotations

from collections.abc import Sequence
from html import escape


def render_trace_html(rows: Sequence[dict]) -> str:
    body_rows: list[str] = []
    for row in rows:
        verdict = str(row["verdict"])
        resources = row["effective_scope"]["resources"]
        scope = ", ".join(str(item) for item in resources) if resources else "none"
        reason = ", ".join(str(item) for item in row["reason_codes"])
        body_rows.append(
            "        <tr>"
            f"<th>{escape(str(row['step']))}</th>"
            f"<td class=\"{escape(verdict.lower())}\">{escape(verdict)}</td>"
            f"<td>{escape(reason)}</td>"
            f"<td>{escape(scope)}</td>"
            "<td>not executed</td></tr>"
        )

    lines = [
        "<!doctype html>",
        '<html lang="en">',
        "<head>",
        '  <meta charset="utf-8">',
        '  <meta name="viewport" content="width=device-width, initial-scale=1">',
        "  <title>Agent Trust Border — synthetic offline trace</title>",
        "  <style>",
        "    body{font:15px ui-monospace,monospace;margin:2rem;color:#172033;background:#f7f9fc}",
        "    table{border-collapse:collapse;width:100%;background:white}",
        "    th,td{border:1px solid #d8deea;padding:.7rem;text-align:left}",
        "    .admit{color:#08783e}.deny{color:#a32626}.unknown{color:#8a6200}",
        "    .boundary{max-width:80ch;color:#4a5568}",
        "  </style>",
        "</head>",
        "<body>",
        "  <h1>Agent Trust Border</h1>",
        "  <p class=\"boundary\">Synthetic offline trace. Integrity, identity, authority, "
        "evidence and world truth remain separate. No requested action is executed.</p>",
        "  <table>",
        "    <thead><tr><th>Step</th><th>Verdict</th><th>Reason</th>"
        "<th>Effective scope</th><th>Action</th></tr></thead>",
        "    <tbody>",
        *body_rows,
        "    </tbody>",
        "  </table>",
        "  <p class=\"boundary\">Boundary: synthetic pinned adapter fixture; real "
        "DSSE/Ed25519 grant and receipt operations; no live A2A/GB/Z conformance and "
        "no world-truth claim.</p>",
        "</body>",
        "</html>",
    ]
    return "\n".join(lines) + "\n"
