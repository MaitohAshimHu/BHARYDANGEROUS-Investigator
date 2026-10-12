"""Case management CLI commands."""
import uuid
from pathlib import Path
from typing import Optional
import typer
from rich.console import Console
from rich.table import Table

from bharydangerous.core.constants import DEFAULT_DB_FILENAME
from bharydangerous.core.models import CaseRecord
from bharydangerous.db.migrations import initialize_database
from bharydangerous.db.repositories import CaseRepository

app = typer.Typer(help="Manage digital forensics investigation cases.")
console = Console()

@app.command("create")
def create_case(
    name: str = typer.Option(..., "--name", "-n", help="Human-readable name of the investigation case."),
    investigator: str = typer.Option("Ashim", "--investigator", "-i", help="Lead investigator name."),
    workspace: Path = typer.Option(Path("."), "--workspace", "-w", help="Workspace directory for case database."),
    description: Optional[str] = typer.Option(None, "--description", "-d", help="Optional case description."),
):
    """Initialize a new forensic case and create the case database."""
    workspace_path = workspace.resolve()
    workspace_path.mkdir(parents=True, exist_ok=True)
    db_path = workspace_path / DEFAULT_DB_FILENAME

    initialize_database(db_path)
    repo = CaseRepository(db_path)

    case_id = f"CASE-{uuid.uuid4().hex[:8].upper()}"
    case_record = CaseRecord(
        case_id=case_id,
        name=name,
        investigator=investigator,
        workspace_path=str(workspace_path),
        description=description,
    )
    repo.create(case_record)

    console.print(f"[bold green]✓[/bold green] Case initialized successfully!")
    console.print(f"  [bold]Case ID:[/bold] {case_id}")
    console.print(f"  [bold]Name:[/bold] {name}")
    console.print(f"  [bold]Investigator:[/bold] {investigator}")
    console.print(f"  [bold]Database:[/bold] {db_path}")

@app.command("list")
def list_cases(
    workspace: Path = typer.Option(Path("."), "--workspace", "-w", help="Workspace directory."),
):
    """List all cases in the current workspace."""
    db_path = workspace.resolve() / DEFAULT_DB_FILENAME
    if not db_path.is_file():
        console.print(f"[yellow]No case database found at {db_path}. Run 'bdinvestigator case create' first.[/yellow]")
        raise typer.Exit(code=1)

    repo = CaseRepository(db_path)
    cases = repo.list_all()

    if not cases:
        console.print("[dim]No cases recorded in database.[/dim]")
        return

    table = Table(title="Forensic Cases", show_header=True, header_style="bold cyan")
    table.add_column("Case ID", style="bold")
    table.add_column("Name")
    table.add_column("Investigator")
    table.add_column("Status")
    table.add_column("Created (UTC)")

    for c in cases:
        table.add_row(c.case_id, c.name, c.investigator, c.status, c.created_at[:19])

    console.print(table)

@app.command("info")
def case_info(
    case_id: Optional[str] = typer.Option(None, "--case", "--case-id", "-c", help="Specific Case ID (defaults to latest)."),
    workspace: Path = typer.Option(Path("."), "--workspace", "-w", help="Workspace directory."),
):
    """Display detailed parameters and metadata for a case."""
    db_path = workspace.resolve() / DEFAULT_DB_FILENAME
    if not db_path.is_file():
        console.print(f"[yellow]No case database found at {db_path}.[/yellow]")
        raise typer.Exit(code=1)

    repo = CaseRepository(db_path)
    if case_id:
        case = repo.get_by_id(case_id)
    else:
        cases = repo.list_all()
        case = cases[0] if cases else None

    if not case:
        console.print(f"[red]Case not found.[/red]")
        raise typer.Exit(code=1)

    console.print(f"[bold cyan]Case Metadata: {case.name}[/bold cyan]")
    console.print(f"  Case ID:      {case.case_id}")
    console.print(f"  Investigator: {case.investigator}")
    console.print(f"  Status:       {case.status}")
    console.print(f"  Created:      {case.created_at}")
    console.print(f"  Description:  {case.description or 'N/A'}")
    console.print(f"  Workspace:    {case.workspace_path}")
