"""Timeline building, querying, and correlation CLI commands."""
from pathlib import Path
from typing import Optional
import typer
from rich.console import Console
from rich.table import Table

from bharydangerous.core.constants import DEFAULT_DB_FILENAME
from bharydangerous.correlation.engine import CorrelationEngine
from bharydangerous.correlation.timeline import TimelineEngine
from bharydangerous.db.repositories import CaseRepository, CorrelationRepository, TimelineRepository

app = typer.Typer(help="Manage normalized timelines and cross-artifact incident correlations.")
console = Console()

def _get_context(workspace: Path, specified_case: Optional[str]):
    db_path = workspace.resolve() / DEFAULT_DB_FILENAME
    case_repo = CaseRepository(db_path)
    if specified_case:
        c = case_repo.get_by_id(specified_case)
    else:
        cases = case_repo.list_all()
        c = cases[0] if cases else None
    if not c:
        console.print("[red]No active case found. Run 'bdinvestigator case create' first.[/red]")
        raise typer.Exit(code=1)
    return db_path, c.case_id

@app.command("build")
def build_timeline(
    workspace: Path = typer.Option(Path("."), "--workspace", "-w", help="Workspace directory."),
    case_id: Optional[str] = typer.Option(None, "--case", "-c", help="Target Case ID."),
):
    """Synthesize unified timeline and execute cross-artifact correlation rules."""
    db_path, cid = _get_context(workspace, case_id)
    timeline_repo = TimelineRepository(db_path)
    corr_repo = CorrelationRepository(db_path)

    timeline_engine = TimelineEngine(timeline_repo)
    stats = timeline_engine.get_summary_stats(cid)

    console.print(f"[bold cyan]Building Timeline for Case {cid}...[/bold cyan]")
    console.print(f"  Total Timeline Events: {stats['total_events']}")
    if stats["sources"]:
        for src, cnt in stats["sources"].items():
            console.print(f"    - {src}: {cnt} events")

    console.print("[dim]Executing cross-artifact correlation rules...[/dim]")
    corr_engine = CorrelationEngine(timeline_repo, corr_repo)
    correlations = corr_engine.run_correlations(cid)

    if not correlations:
        console.print("[green]Timeline built successfully. No anomalous correlation chains triggered.[/green]")
    else:
        console.print(f"[bold yellow]Found {len(correlations)} Correlated Incidents:[/bold yellow]")
        table = Table(title="Cross-Artifact Correlated Chains", show_header=True, header_style="bold magenta")
        table.add_column("Correlation ID")
        table.add_column("Rule Name")
        table.add_column("Score")
        table.add_column("Summary")
        table.add_column("Linked Events")

        for c in correlations:
            table.add_row(
                c.correlation_id,
                c.rule_name,
                f"{int(c.score * 100)}%",
                c.summary,
                str(len(c.event_ids)),
            )
        console.print(table)

@app.command("query")
def query_timeline(
    limit: int = typer.Option(50, "--limit", "-n", help="Maximum events to display."),
    source_type: Optional[str] = typer.Option(None, "--source", "-s", help="Filter by source (EVTX, SYSLOG, PCAP, WEBLOG)."),
    workspace: Path = typer.Option(Path("."), "--workspace", "-w", help="Workspace directory."),
    case_id: Optional[str] = typer.Option(None, "--case", "-c", help="Target Case ID."),
):
    """Query and inspect chronological timeline events."""
    db_path, cid = _get_context(workspace, case_id)
    timeline_repo = TimelineRepository(db_path)
    events = timeline_repo.list_by_case(cid, source_type=source_type, limit=limit)

    if not events:
        console.print("[dim]No timeline events found matching criteria.[/dim]")
        return

    table = Table(title=f"Timeline Events — Case {cid}", show_header=True, header_style="bold cyan")
    table.add_column("Timestamp (UTC)", style="bold")
    table.add_column("Source")
    table.add_column("Type")
    table.add_column("Summary")
    table.add_column("Actor")

    for e in events:
        table.add_row(
            e.timestamp[:19],
            e.source_type,
            e.event_type,
            e.summary[:70] + ("..." if len(e.summary) > 70 else ""),
            e.actor or "-",
        )

    console.print(table)
