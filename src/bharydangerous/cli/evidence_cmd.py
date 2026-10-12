"""Evidence intake and verification CLI commands."""
import uuid
from pathlib import Path
from typing import Optional
import typer
from rich.console import Console
from rich.table import Table

from bharydangerous.core.constants import DEFAULT_DB_FILENAME
from bharydangerous.core.hashing import compute_hashes, verify_file_hashes
from bharydangerous.core.models import ChainOfCustodyRecord, EvidenceRecord
from bharydangerous.db.repositories import CaseRepository, ChainOfCustodyRepository, EvidenceRepository

app = typer.Typer(help="Read-only evidence intake, verification, and provenance.")
console = Console()

def _get_active_case_id(db_path: Path, specified_id: Optional[str]) -> str:
    case_repo = CaseRepository(db_path)
    if specified_id:
        c = case_repo.get_by_id(specified_id)
        if not c:
            console.print(f"[red]Error: Case '{specified_id}' not found.[/red]")
            raise typer.Exit(code=1)
        return c.case_id
    cases = case_repo.list_all()
    if not cases:
        console.print("[red]No cases exist. Create one first using 'bdinvestigator case create'.[/red]")
        raise typer.Exit(code=1)
    return cases[0].case_id

@app.command("add")
def add_evidence(
    path: Path = typer.Argument(..., help="Path to evidence file to ingest."),
    label: str = typer.Option(..., "--label", "-l", help="Descriptive label for this evidence."),
    evidence_type: str = typer.Option("FILE", "--type", "-t", help="Evidence type (FILE, DISK_IMAGE, MEMORY_DUMP, PCAP, LOG_FILE)."),
    case_id: Optional[str] = typer.Option(None, "--case", "-c", help="Target Case ID (defaults to latest case)."),
    investigator: str = typer.Option("Ashim", "--investigator", "-i", help="Analyst performing intake."),
    workspace: Path = typer.Option(Path("."), "--workspace", "-w", help="Workspace directory."),
):
    """Ingest evidence in read-only mode, calculate cryptographic hashes, and log chain of custody."""
    source_file = path.resolve()
    if not source_file.is_file():
        console.print(f"[red]Error: Evidence file not found: {source_file}[/red]")
        raise typer.Exit(code=1)

    db_path = workspace.resolve() / DEFAULT_DB_FILENAME
    active_case_id = _get_active_case_id(db_path, case_id)

    console.print(f"[dim]Streaming SHA-256 and MD5 hashing for: {source_file.name}...[/dim]")
    sha256, md5 = compute_hashes(source_file)
    stat = source_file.stat()

    ev_id = f"EV-{uuid.uuid4().hex[:8].upper()}"
    ev_record = EvidenceRecord(
        evidence_id=ev_id,
        case_id=active_case_id,
        label=label,
        evidence_type=evidence_type.upper(),
        source_path=str(source_file),
        file_size_bytes=stat.st_size,
        sha256=sha256,
        md5=md5,
        verification_status="VERIFIED",
    )

    ev_repo = EvidenceRepository(db_path)
    ev_repo.add(ev_record)

    # Record initial chain of custody
    coc_repo = ChainOfCustodyRepository(db_path)
    coc_repo.record(ChainOfCustodyRecord(
        log_id=f"COC-{uuid.uuid4().hex[:8].upper()}",
        evidence_id=ev_id,
        action="INTAKE_VERIFIED",
        performed_by=investigator,
        recorded_hash=sha256,
        details_json={"file_size": stat.st_size, "source_path": str(source_file)},
    ))

    console.print(f"[bold green]✓[/bold green] Evidence successfully ingested into Case {active_case_id}!")
    console.print(f"  [bold]Evidence ID:[/bold] {ev_id}")
    console.print(f"  [bold]Label:[/bold]       {label}")
    console.print(f"  [bold]File Size:[/bold]   {stat.st_size:,} bytes")
    console.print(f"  [bold]SHA-256:[/bold]     {sha256}")
    console.print(f"  [bold]MD5:[/bold]         {md5}")

@app.command("verify")
def verify_evidence(
    evidence_id: Optional[str] = typer.Option(None, "--id", help="Specific Evidence ID to verify (or verify all in case)."),
    case_id: Optional[str] = typer.Option(None, "--case", "-c", help="Case ID (defaults to latest case)."),
    workspace: Path = typer.Option(Path("."), "--workspace", "-w", help="Workspace directory."),
):
    """Re-compute cryptographic hashes and verify evidence integrity against provenance records."""
    db_path = workspace.resolve() / DEFAULT_DB_FILENAME
    active_case_id = _get_active_case_id(db_path, case_id)
    ev_repo = EvidenceRepository(db_path)

    items = [ev_repo.get_by_id(evidence_id)] if evidence_id else ev_repo.list_by_case(active_case_id)
    if not items or items[0] is None:
        console.print("[yellow]No matching evidence records found to verify.[/yellow]")
        raise typer.Exit(code=1)

    table = Table(title="Evidence Integrity Verification", show_header=True, header_style="bold cyan")
    table.add_column("Evidence ID")
    table.add_column("Label")
    table.add_column("Recorded SHA-256")
    table.add_column("Status", justify="center")

    has_mismatch = False
    for ev in items:
        ev_file = Path(ev.source_path)
        if not ev_file.is_file():
            table.add_row(ev.evidence_id, ev.label, ev.sha256[:16] + "...", "[bold red]FILE MISSING[/bold red]")
            has_mismatch = True
            continue

        res = verify_file_hashes(ev_file, ev.sha256, ev.md5)
        if res["sha256_match"]:
            table.add_row(ev.evidence_id, ev.label, ev.sha256[:16] + "...", "[bold green]VERIFIED (MATCH)[/bold green]")
        else:
            table.add_row(ev.evidence_id, ev.label, ev.sha256[:16] + "...", "[bold red]TAMPERED / MISMATCH[/bold red]")
            has_mismatch = True

    console.print(table)
    if has_mismatch:
        console.print("[bold red]WARNING: Integrity verification failed for one or more evidence artifacts![/bold red]")
        raise typer.Exit(code=1)
    else:
        console.print("[bold green]All evidence files match their cryptographic intake hashes perfectly.[/bold green]")

@app.command("list")
def list_evidence(
    case_id: Optional[str] = typer.Option(None, "--case", "-c", help="Target Case ID (defaults to latest)."),
    workspace: Path = typer.Option(Path("."), "--workspace", "-w", help="Workspace directory."),
):
    """List all evidence recorded in the active case."""
    db_path = workspace.resolve() / DEFAULT_DB_FILENAME
    active_case_id = _get_active_case_id(db_path, case_id)
    ev_repo = EvidenceRepository(db_path)
    items = ev_repo.list_by_case(active_case_id)

    if not items:
        console.print(f"[dim]No evidence items registered for Case {active_case_id}.[/dim]")
        return

    table = Table(title=f"Evidence Inventory — Case {active_case_id}", show_header=True, header_style="bold cyan")
    table.add_column("ID", style="bold")
    table.add_column("Label")
    table.add_column("Type")
    table.add_column("Size (Bytes)")
    table.add_column("SHA-256 Preview")
    table.add_column("Status")

    for ev in items:
        table.add_row(ev.evidence_id, ev.label, ev.evidence_type, f"{ev.file_size_bytes:,}", ev.sha256[:16] + "...", ev.verification_status)

    console.print(table)
