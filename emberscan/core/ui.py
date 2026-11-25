"""
Console UI helpers for EmberScan.

A thin presentation layer built on top of ``rich`` (a declared core
dependency) with a graceful plain-text fallback so the tool still runs if
``rich`` is somehow unavailable. All human-facing CLI output should go through
this module so the look stays consistent and log noise stays out of stdout.
"""

from __future__ import annotations

import os
import sys
from contextlib import contextmanager
from typing import Dict, Iterable, List, Optional

# ---------------------------------------------------------------------------
# rich detection (never hard-crash if the optional pretty layer is missing)
# ---------------------------------------------------------------------------
try:  # pragma: no cover - exercised implicitly
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import (
        BarColumn,
        Progress,
        SpinnerColumn,
        TextColumn,
        TimeElapsedColumn,
    )
    from rich.table import Table
    from rich.text import Text

    _HAS_RICH = True
except Exception:  # pragma: no cover
    _HAS_RICH = False


__version_label__ = "1.0.0"

# Severity presentation (ordered most → least severe)
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_SEV_STYLE = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}
_SEV_PLAIN_COLOR = {
    "critical": "\033[1;97;41m",
    "high": "\033[91m",
    "medium": "\033[93m",
    "low": "\033[96m",
    "info": "\033[2m",
}
_RESET = "\033[0m"


def _want_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


class _UI:
    """Facade over rich with a plain fallback. One shared instance: ``ui``."""

    def __init__(self) -> None:
        self.quiet = False
        self._console = Console(highlight=False) if _HAS_RICH else None

    # -- low level -----------------------------------------------------------
    @property
    def rich(self) -> bool:
        return _HAS_RICH and self._console is not None

    def _print(self, msg: str = "") -> None:
        if self.rich:
            self._console.print(msg)
        else:
            print(_strip_markup(msg))

    # -- banner --------------------------------------------------------------
    def banner(self, version: str) -> None:
        if self.quiet:
            return
        if self.rich:
            title = Text()
            title.append("🔥 EmberScan ", style="bold orange1")
            title.append(f"v{version}", style="bold white")
            title.append("\n")
            title.append("Embedded / IoT Firmware Security Scanner", style="dim")
            self._console.print(
                Panel(title, box=box.ROUNDED, border_style="orange1", expand=False, padding=(0, 2))
            )
        else:
            print(f"\n=== EmberScan v{version} — Firmware Security Scanner ===\n")

    # -- simple lines --------------------------------------------------------
    def step(self, msg: str) -> None:
        self._print(f"[bold cyan]▸[/bold cyan] {msg}" if self.rich else f"[*] {msg}")

    def info(self, msg: str) -> None:
        self._print(f"  {msg}")

    def success(self, msg: str) -> None:
        self._print(f"[bold green]✔[/bold green] {msg}" if self.rich else f"[+] {msg}")

    def warn(self, msg: str) -> None:
        self._print(f"[yellow]⚠ {msg}[/yellow]" if self.rich else f"[!] {msg}")

    def error(self, msg: str) -> None:
        self._print(f"[bold red]✘ {msg}[/bold red]" if self.rich else f"[x] {msg}")

    def rule(self, title: str = "") -> None:
        if self.rich:
            self._console.rule(f"[bold]{title}[/bold]" if title else "")
        else:
            print(f"\n--- {title} " + "-" * max(0, 56 - len(title)))

    def blank(self) -> None:
        if not self.quiet:
            self._print("")

    # -- key/value target summary -------------------------------------------
    def kv_panel(self, title: str, rows: List[tuple], border: str = "cyan") -> None:
        if self.rich:
            tbl = Table.grid(padding=(0, 2))
            tbl.add_column(style="dim", justify="right")
            tbl.add_column(style="bold")
            for k, v in rows:
                tbl.add_row(str(k), str(v))
            self._console.print(
                Panel(
                    tbl,
                    title=title,
                    title_align="left",
                    border_style=border,
                    box=box.ROUNDED,
                    expand=False,
                )
            )
        else:
            print(f"\n{title}")
            for k, v in rows:
                print(f"  {k:>14}: {v}")

    # -- severity summary ----------------------------------------------------
    def severity_summary(self, counts: Dict[str, int], total: Optional[int] = None) -> None:
        total = total if total is not None else sum(counts.get(s, 0) for s in SEVERITY_ORDER)
        if self.rich:
            tbl = Table(box=box.SIMPLE_HEAVY, show_edge=False, pad_edge=False)
            tbl.add_column("Severity", justify="left")
            tbl.add_column("Count", justify="right")
            for sev in SEVERITY_ORDER:
                c = counts.get(sev, 0)
                style = _SEV_STYLE[sev] if c else "dim"
                tbl.add_row(Text(sev.upper(), style=style), Text(str(c), style=style))
            tbl.add_row(Text("TOTAL", style="bold"), Text(str(total), style="bold"))
            self._console.print(tbl)
        else:
            print("\n  SEVERITY    COUNT")
            for sev in SEVERITY_ORDER:
                print(f"  {sev.upper():<10}  {counts.get(sev, 0):>5}")
            print(f"  {'TOTAL':<10}  {total:>5}")

    # -- findings table ------------------------------------------------------
    def findings_table(self, findings: Iterable[dict], limit: int = 40) -> None:
        findings = list(findings)
        if not findings:
            self.success("No vulnerabilities found.")
            return
        shown = findings[:limit]
        if self.rich:
            tbl = Table(box=box.ROUNDED, show_lines=False, expand=True, header_style="bold")
            tbl.add_column("Sev", no_wrap=True)
            tbl.add_column("Type", no_wrap=True, style="dim")
            tbl.add_column("Finding")
            tbl.add_column("Location", style="dim", overflow="fold")
            for f in shown:
                sev = f.get("severity", "info")
                tbl.add_row(
                    Text(sev.upper(), style=_SEV_STYLE.get(sev, "dim")),
                    f.get("vuln_type", "") or "",
                    f.get("title", ""),
                    f.get("location", "") or "",
                )
            self._console.print(tbl)
        else:
            for f in shown:
                sev = f.get("severity", "info")
                c = _SEV_PLAIN_COLOR.get(sev, "") if _want_color() else ""
                r = _RESET if c else ""
                print(f"\n{c}[{sev.upper()}]{r} {f.get('title','')}")
                if f.get("location"):
                    print(f"    {f['location']}")
                if f.get("evidence"):
                    print(f"    evidence: {f['evidence']}")
        if len(findings) > limit:
            self.info(f"... and {len(findings) - limit} more (see the full report).")

    # -- progress over named phases -----------------------------------------
    @contextmanager
    def phases(self, title: str = "Scanning"):
        """Yield a callable ``phase(name)`` context manager for sequential steps."""
        if self.rich and not self.quiet:
            progress = Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(bar_width=None),
                TimeElapsedColumn(),
                console=self._console,
                transient=True,
            )
            with progress:
                task = progress.add_task(title, total=None)

                @contextmanager
                def phase(name: str):
                    progress.update(task, description=name)
                    yield

                yield phase
        else:

            @contextmanager
            def phase(name: str):
                if not self.quiet:
                    self.step(name)
                yield

            yield phase


def _strip_markup(msg: str) -> str:
    """Remove rich-style ``[tag]`` markup for the plain fallback."""
    import re

    return re.sub(r"\[/?[a-zA-Z0-9_ ]+\]", "", msg)


# shared singleton
ui = _UI()
