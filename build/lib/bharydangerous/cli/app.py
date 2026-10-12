"""Master Typer application entry point for BHARYDANGEROUS-Investigator."""
import typer
from rich.console import Console
from rich.panel import Panel

from bharydangerous.cli.analyze_cmd import app as analyze_app
from bharydangerous.cli.ai_cmd import app as ai_app
from bharydangerous.cli.case_cmd import app as case_app
from bharydangerous.cli.doctor_cmd import run_doctor
from bharydangerous.cli.evidence_cmd import app as evidence_app
from bharydangerous.cli.report_cmd import app as report_app
from bharydangerous.cli.timeline_cmd import app as timeline_app
from bharydangerous.core.constants import AUTHOR, PRODUCT_NAME, VERSION
from bharydangerous.plugins.manager import PluginManager

app = typer.Typer(
    name="bdinvestigator",
    help=f"{PRODUCT_NAME} — Digital Forensics & Incident Response CLI by {AUTHOR}",
    add_completion=False,
    no_args_is_help=True,
)
console = Console()

# Register Command Groups
app.add_typer(case_app, name="case")
app.add_typer(evidence_app, name="evidence")
app.add_typer(analyze_app, name="analyze")
app.add_typer(timeline_app, name="timeline")
app.add_typer(ai_app, name="ai")
app.add_typer(report_app, name="report")

@app.command("doctor")
def doctor():
    """Verify system utilities, Python runtime, standard libraries, and environment health."""
    run_doctor()

@app.command("version")
def show_version():
    """Display tool version, author, and branding information."""
    console.print(f"[bold cyan]{PRODUCT_NAME}[/bold cyan] v[bold]{VERSION}[/bold] by [bold]{AUTHOR}[/bold]")

@app.command("plugins")
def list_plugins():
    """List loaded community and third-party forensic plugins."""
    mgr = PluginManager()
    plugins = mgr.list_plugins()
    if not plugins:
        console.print("[dim]No third-party plugins loaded. (Plugins directory: ~/.bharydangerous/plugins)[/dim]")
        return
    console.print(f"[bold cyan]Active Plugins ({len(plugins)}):[/bold cyan]")
    for p in plugins:
        console.print(f"  - [bold]{p['name']}[/bold] v{p['version']} by {p['author']}: {p['description']}")

def main():
    app()

if __name__ == "__main__":
    main()
