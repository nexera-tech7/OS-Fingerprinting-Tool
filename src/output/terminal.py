from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.progress import Progress, BarColumn, TextColumn, TaskProgressColumn
from rich.rule import Rule
from rich import box

from ..config import VERSION
from ..network.validation import ValidationResult
from ..scanner.ports import PortResult
from ..fingerprint.analyzer import AnalysisResult
from ..fingerprint.confidence import ConfidenceLevel

console = Console()

# OS display names, emoji icons, and brand colours
_OS_META: dict[str, tuple[str, str, str]] = {
    "linux":   ("Linux",   "🐧", "green"),
    "windows": ("Windows", "🪟", "blue"),
    "android": ("Android", "🤖", "green"),
    "ios":     ("iOS",     "📱", "white"),
    "macos":   ("macOS",   "🍎", "white"),
    "bsd":     ("BSD",     "😈", "red"),
    "unknown": ("Unknown", "❓", "dim"),
}


def print_banner() -> None:
    title = Text()
    title.append(f"OSDETECT v{VERSION}\n", style="bold cyan")
    title.append("OS Fingerprinting Tool", style="dim")
    console.print(Panel(title, box=box.DOUBLE, style="cyan", expand=False, padding=(0, 8)))
    console.print()


def print_target_info(
    validation: ValidationResult,
    reachable: bool,
    rdns: str | None = None,
    elapsed: float | None = None,
    hops: int | None = None,
) -> None:
    console.print("[bold]Target[/bold]")
    console.print(f"  IP:          {validation.normalized}")
    ipv = f"IPv{validation.ip_version}" if validation.ip_version else ""
    console.print(f"  Type:        {validation.address_type.value}  {ipv}")
    reachable_str = "[green]Yes[/green]" if reachable else "[red]No[/red]"
    console.print(f"  Reachable:   {reachable_str}")
    if rdns:
        console.print(f"  Hostname:    [dim]{rdns}[/dim]")
    if hops is not None:
        console.print(f"  Est. hops:   {hops}")
    if elapsed is not None:
        console.print(f"  Scan time:   {elapsed:.2f}s")
    console.print()


def print_port_table(results: list[PortResult]) -> None:
    open_count    = sum(1 for r in results if r.state == "open")
    closed_count  = sum(1 for r in results if r.state == "closed")
    filter_count  = sum(1 for r in results if r.state == "filtered")

    title = (
        f"Port Scan  "
        f"[green]{open_count} open[/green]  "
        f"[yellow]{filter_count} filtered[/yellow]  "
        f"[red]{closed_count} closed[/red]"
    )
    table = Table(title=title, box=box.SIMPLE_HEAVY, show_edge=False, pad_edge=False)
    table.add_column("PORT",    style="cyan",  min_width=10)
    table.add_column("STATE",   min_width=10)
    table.add_column("SERVICE", min_width=12)
    table.add_column("BANNER",  max_width=55)

    for r in results:
        state_style = {"open": "green", "closed": "red", "filtered": "yellow"}.get(r.state, "white")
        banner_display = r.banner[:55] if r.banner else ""
        table.add_row(
            f"{r.port}/tcp",
            f"[{state_style}]{r.state}[/{state_style}]",
            r.service,
            f"[dim]{banner_display}[/dim]",
        )

    console.print(table)
    console.print()


def print_results(result: AnalysisResult, confidence: ConfidenceLevel) -> None:
    console.print(Rule("[bold]Results[/bold]", style="dim"))

    os_key  = result.likely_os
    os_name, os_icon, os_colour = _OS_META.get(os_key, ("Unknown", "❓", "dim"))

    conf_colors = {
        ConfidenceLevel.VERY_HIGH: "bold green",
        ConfidenceLevel.HIGH:      "green",
        ConfidenceLevel.MEDIUM:    "yellow",
        ConfidenceLevel.LOW:       "red",
        ConfidenceLevel.VERY_LOW:  "bold red",
    }
    conf_style = conf_colors.get(confidence, "white")

    console.print(f"\n[bold]Likely OS[/bold]")
    console.print(f"  {os_icon}  [{os_colour}]{os_name}[/{os_colour}]")

    console.print(f"\n[bold]Confidence[/bold]")
    console.print(f"  [{conf_style}]{confidence.value}[/{conf_style}]")

    console.print(f"\n[bold]Probability[/bold]")
    sorted_probs = sorted(result.probabilities.items(), key=lambda x: x[1], reverse=True)
    for key, prob in sorted_probs:
        name, icon, colour = _OS_META.get(key, (key.capitalize(), "", "white"))
        bar_len = prob // 2
        bar     = "█" * bar_len
        highlight = "[bold]" if key == os_key and prob > 0 else ""
        end_h     = "[/bold]" if highlight else ""
        console.print(
            f"  {icon} {highlight}[{colour}]{name:<10}[/{colour}]{end_h}"
            f"  {prob:>3}%  [cyan]{bar}[/cyan]"
        )

    if result.evidence:
        console.print(f"\n[bold]Evidence[/bold]")
        seen: set[str] = set()
        for e in result.evidence:
            if e.description not in seen and e.weight > 0:
                console.print(f"  [green]✓[/green] {e.description}")
                seen.add(e.description)

    if result.warnings:
        console.print(f"\n[bold yellow]Warnings[/bold yellow]")
        for w in result.warnings:
            console.print(f"  [yellow]⚠[/yellow]  {w}")

    console.print(Rule(style="dim"))
    console.print()


def print_error(message: str) -> None:
    console.print(f"[bold red]✗[/bold red]  {message}")


def print_info(message: str) -> None:
    console.print(f"[dim]ℹ[/dim]  {message}")


def create_progress() -> Progress:
    return Progress(
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=30, complete_style="cyan", finished_style="green"),
        TaskProgressColumn(),
        console=console,
        transient=True,
    )


def _format_os_name(key: str) -> str:
    name, _, _ = _OS_META.get(key, (key.capitalize(), "", ""))
    return name
