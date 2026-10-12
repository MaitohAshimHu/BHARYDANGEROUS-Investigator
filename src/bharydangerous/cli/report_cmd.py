"""Forensic report generation CLI commands."""
from pathlib import Path
from typing import Optional
import typer
from rich.console import Console

from bharydangerous.adapters.system_detector import run_all_doctor_checks
from bharydangerous.core.constants import DEFAULT_DB_FILENAME, PRODUCT_NAME, VERSION
from bharydangerous.core.models import ReportModel
from bharydangerous.correlation.timeline import TimelineEngine
from bharydangerous.db.repositories import (
    AIAnnotationRepository,
    CaseRepository,
    CorrelationRepository,
    EvidenceRepository,
    FindingRepository,
    TimelineRepository,
)
from bharydangerous.reporting.html_reporter import HtmlReporter
from bharydangerous.reporting.json_reporter import JsonReporter
from bharydangerous.reporting.markdown_reporter import MarkdownReporter

app = typer.Typer(help="Generate multi-format forensic reports (JSON, Markdown, standalone HTML).")
console = Console()

@app.command("generate")
def generate_report(
    output_dir: Path = typer.Option(Path("./exports"), "--output-dir", "-o", help="Target output directory."),
    report_format: str = typer.Option("all", "--format", "-f", help="Format to generate (json, md, html, all)."),
    workspace: Path = typer.Option(Path("."), "--workspace", "-w", help="Workspace directory."),
    case_id: Optional[str] = typer.Option(None, "--case", "-c", help="Target Case ID."),
):
    """Compile and export complete forensic investigation report."""
    db_path = workspace.resolve() / DEFAULT_DB_FILENAME
    case_repo = CaseRepository(db_path)
    cases = case_repo.list_all()
    if not cases:
        console.print("[red]No cases found in database.[/red]")
        raise typer.Exit(code=1)
    target_case = case_repo.get_by_id(case_id) if case_id else cases[0]

    ev_repo = EvidenceRepository(db_path)
    evidence_list = ev_repo.list_by_case(target_case.case_id)

    finding_repo = FindingRepository(db_path)
    findings_list = finding_repo.list_by_case(target_case.case_id)

    timeline_repo = TimelineRepository(db_path)
    timeline_engine = TimelineEngine(timeline_repo)
    timeline_stats = timeline_engine.get_summary_stats(target_case.case_id)

    corr_repo = CorrelationRepository(db_path)
    correlations = corr_repo.list_by_case(target_case.case_id)

    annot_repo = AIAnnotationRepository(db_path)
    annotations = annot_repo.list_by_case(target_case.case_id)

    tool_diagnostics = run_all_doctor_checks()

    report_data = ReportModel(
        product_name=PRODUCT_NAME,
        version=VERSION,
        case=target_case,
        evidence_list=evidence_list,
        findings_list=findings_list,
        timeline_summary=timeline_stats,
        correlations=correlations,
        ai_annotations=annotations,
        tool_diagnostics=tool_diagnostics,
    )

    out_path = output_dir.resolve()
    out_path.mkdir(parents=True, exist_ok=True)
    slug = target_case.name.lower().replace(" ", "_")

    fmt = report_format.lower()
    generated_files = []

    if fmt in ("json", "all"):
        json_file = out_path / f"{slug}_report.json"
        JsonReporter().generate(report_data, json_file)
        generated_files.append(json_file)

    if fmt in ("md", "markdown", "all"):
        md_file = out_path / f"{slug}_report.md"
        MarkdownReporter().generate(report_data, md_file)
        generated_files.append(md_file)

    if fmt in ("html", "all"):
        html_file = out_path / f"{slug}_report.html"
        HtmlReporter().generate(report_data, html_file)
        generated_files.append(html_file)

    console.print(f"[bold green]✓ Report generated successfully for Case '{target_case.name}'![/bold green]")
    for gf in generated_files:
        console.print(f"  [bold]Created:[/bold] {gf} ({gf.stat().st_size:,} bytes)")
