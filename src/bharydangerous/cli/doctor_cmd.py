"""Environment diagnostic and system doctor command."""
import typer
from rich.console import Console
from rich.table import Table

from bharydangerous.adapters.system_detector import run_all_doctor_checks

console = Console()

def run_doctor():
    """Inspect environment, Python runtime, standard libraries, and external forensic utilities."""
    console.print("[bold cyan]BHARYDANGEROUS-Investigator — System Diagnostics & Doctor[/bold cyan]\n")
    results = run_all_doctor_checks()

    table = Table(title="Forensic Tooling & Environment Health", show_header=True, header_style="bold cyan")
    table.add_column("Category")
    table.add_column("Component / Utility")
    table.add_column("Status", justify="center")
    table.add_column("Details & Notes")

    status_styles = {
        "OK": "[bold green]OK[/bold green]",
        "WARNING": "[bold yellow]WARNING[/bold yellow]",
        "MISSING": "[bold red]MISSING[/bold red]",
        "OPTIONAL": "[dim cyan]OPTIONAL[/dim cyan]",
    }

    for r in results:
        table.add_row(
            r.category,
            r.name,
            status_styles.get(r.status, r.status),
            r.details,
        )

    console.print(table)
    console.print("\n[dim]Note: External forensic utilities (TSK, Volatility, TShark, YARA) are optional dependencies.[/dim]")
    console.print("[dim]BHARYDANGEROUS-Investigator provides built-in pure-Python fallback analyzers when binary utilities are absent.[/dim]")
