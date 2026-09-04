from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.progress import Progress, BarColumn, TextColumn, TaskProgressColumn
from rich import box
import time

from ..config import VERSION
from ..network.validation import ValidationResult
from ..scanner.ports import PortResult
from ..fingerprint.analyzer import AnalysisResult
from ..fingerprint.confidence import ConfidenceLevel

console = Console()


def print_banner() -> None:
    title = Text()
    title.append(f"OSDETECT v{VERSION}\n", style="bold cyan")
    title.append("OS Fingerprinting Tool", style="dim")
    console.print(Panel(title, box=box.DOUBLE, style="cyan", expand=False, padding=(0, 8)))
    console.print()


def print_target_info(validation: ValidationResult, reachable: bool, rdns: str | None = None) -> None:
    console.print("[bold]Target[/bold]")
    console.print(f"  IP:          {validation.normalized}")
    console.print(f"  Type:        {validation.address_type.value}")
    console.print(f"  Reachable:   {'Yes' if reachable else 'No'}")
    if rdns:
        console.print(f"  Hostname:    {rdns}")
    console.print()


def print_port_table(results: list[PortResult]) -> None:
    table = Table(title="Port Scan", box=box.SIMPLE_HEAVY, show_edge=False, pad_edge=False)
    table.add_column("PORT", style="cyan", min_width=10)
    table.add_column("STATE", min_width=10)
    table.add_column("SERVICE", min_width=10)
    table.add_column("BANNER", max_width=50)

    for r in results:
        state_style = {"open": "green", "closed": "red", "filtered": "yellow"}.get(r.state, "white")
        banner_display = r.banner[:50] if r.banner else ""
        table.add_row(f"{r.port}/tcp", f"[{state_style}]{r.state}[/{state_style}]", r.service, banner_display)

    console.print(table)
    console.print()


def print_results(result: AnalysisResult, confidence: ConfidenceLevel) -> None:
    console.print("[bold]Results[/bold]")
    console.print("─" * 50)

    os_name = result.likely_os.capitalize() if result.likely_os != "ios" else "iOS"
    if result.likely_os == "macos":
        os_name = "macOS"
    if result.likely_os == "bsd":
        os_name = "BSD"

    conf_colors = {
        ConfidenceLevel.VERY_HIGH: "bold green",
        ConfidenceLevel.HIGH: "green",
        ConfidenceLevel.MEDIUM: "yellow",
        ConfidenceLevel.LOW: "red",
        ConfidenceLevel.VERY_LOW: "bold red",
    }
    conf_style = conf_colors.get(confidence, "white")

    console.print(f"\n[bold]Likely OS[/bold]")
    console.print(f"  {os_name}")
    console.print(f"\n[bold]Confidence[/bold]")
    console.print(f"  [{conf_style}]{confidence.value}[/{conf_style}]")

    console.print(f"\n[bold]Probability[/bold]")
    sorted_probs = sorted(result.probabilities.items(), key=lambda x: x[1], reverse=True)
    for os_key, prob in sorted_probs:
        label = _format_os_name(os_key)
        bar_len = prob // 2
        bar = "█" * bar_len
        console.print(f"  {label:<12} {prob:>3}%  [cyan]{bar}[/cyan]")

    if result.evidence:
        console.print(f"\n[bold]Evidence[/bold]")
        seen = set()
        for e in result.evidence:
            if e.description not in seen and e.weight > 0:
                console.print(f"  • {e.description}")
                seen.add(e.description)

    if result.warnings:
        console.print(f"\n[bold yellow]Warnings[/bold yellow]")
        for w in result.warnings:
            console.print(f"  • {w}")

    console.print("─" * 50)


def print_error(message: str) -> None:
    console.print(f"[bold red][!][/bold red] {message}")


def print_info(message: str) -> None:
    console.print(f"[dim][*][/dim] {message}")


def create_progress() -> Progress:
    return Progress(
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=30),
        TaskProgressColumn(),
        console=console,
    )


def _format_os_name(key: str) -> str:
    names = {"linux": "Linux", "windows": "Windows", "android": "Android", "ios": "iOS", "macos": "macOS", "bsd": "BSD", "unknown": "Unknown"}
    return names.get(key, key.capitalize())
