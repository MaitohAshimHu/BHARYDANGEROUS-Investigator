"""AI forensic reasoning CLI commands (explain, summarize)."""
import hashlib
from pathlib import Path
from typing import Optional
import uuid
import typer
from rich.console import Console
from rich.markdown import Markdown

from bharydangerous.ai.consent import (
    extract_cited_finding_ids_with_validation,
    request_ai_consent,
)
from bharydangerous.ai.gemini import GeminiProvider
from bharydangerous.ai.local_ollama import LocalOllamaProvider
from bharydangerous.ai.mock_provider import MockAIProvider
from bharydangerous.ai.prompt_templates import (
    build_finding_explanation_prompt,
    build_investigation_summary_prompt,
)
from bharydangerous.core.config import get_gemini_api_key
from bharydangerous.core.constants import DEFAULT_DB_FILENAME
from bharydangerous.core.exceptions import AIProviderError, ConsentDeniedError
from bharydangerous.core.models import AIAnnotationRecord
from bharydangerous.db.repositories import (
    AIAnnotationRepository,
    CaseRepository,
    FindingRepository,
    TimelineRepository,
)

app = typer.Typer(help="AI-assisted finding explanations and investigation summaries.")
console = Console()

def _resolve_provider(provider_name: str, model_name: Optional[str] = None):
    pname = provider_name.lower()
    if pname == "mock":
        return MockAIProvider(model_name=model_name or "offline-deterministic-v1")
    elif pname == "ollama":
        return LocalOllamaProvider(model_name=model_name)
    elif pname == "gemini":
        api_key = get_gemini_api_key()
        if not api_key:
            console.print("[yellow]Notice: No GEMINI_API_KEY detected. Falling back to deterministic Mock AI Provider.[/yellow]")
            return MockAIProvider(model_name=model_name or "offline-deterministic-v1")
        try:
            return GeminiProvider(model_name=model_name)
        except AIProviderError as e:
            console.print(f"[yellow]Gemini initialization notice: {e}. Falling back to Mock AI Provider.[/yellow]")
            return MockAIProvider(model_name=model_name or "offline-deterministic-v1")
    else:
        console.print(f"[red]Unknown AI provider: {provider_name}[/red]")
        raise typer.Exit(code=1)

@app.command("explain")
def ai_explain(
    finding_arg: Optional[str] = typer.Argument(None, help="Target Finding ID (positional)."),
    finding_id: Optional[str] = typer.Option(None, "--finding", "-f", help="Target Finding ID (e.g., FND-XXXX)."),
    provider: str = typer.Option("gemini", "--provider", "-p", help="AI provider (gemini, ollama, mock)."),
    consent: bool = typer.Option(False, "--consent", "--consent-ai-upload", help="Explicit non-interactive consent to send sanitized data."),
    workspace: Path = typer.Option(Path("."), "--workspace", "-w", help="Workspace directory."),
    case_id: Optional[str] = typer.Option(None, "--case", "--case-id", "-c", help="Target Case ID."),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="Specific model identifier to use."),
):
    """Explain a specific forensic finding with structured MITRE lifecycle mapping and verification steps."""
    target_fid = finding_arg or finding_id
    if not target_fid:
        console.print("[red]Error: Missing required finding ID. Provide as argument or --finding/-f option.[/red]")
        raise typer.Exit(code=1)

    db_path = workspace.resolve() / DEFAULT_DB_FILENAME
    case_repo = CaseRepository(db_path)
    cases = case_repo.list_all()
    if not cases:
        console.print("[red]No cases found.[/red]")
        raise typer.Exit(code=1)
    target_case = case_repo.get_by_id(case_id) if case_id else cases[0]

    finding_repo = FindingRepository(db_path)
    finding = finding_repo.get_by_id(target_fid)
    if not finding:
        console.print(f"[red]Finding '{target_fid}' not found in case database.[/red]")
        raise typer.Exit(code=1)

    timeline_repo = TimelineRepository(db_path)
    context_events = timeline_repo.list_by_case(target_case.case_id, limit=20)

    # Build and redact prompt preview
    prompt_text = build_finding_explanation_prompt(finding, context_events)

    # Consent Gate
    try:
        request_ai_consent(prompt_text, auto_consent=consent, console=console)
    except ConsentDeniedError as e:
        console.print(f"[yellow]Operation aborted: {e}[/yellow]")
        raise typer.Exit(code=0)

    ai_engine = _resolve_provider(provider, model_name=model)
    console.print(f"[dim]Generating explanation via {provider.upper()}...[/dim]")

    try:
        response = ai_engine.explain_finding(finding, context_events)
    except Exception as exc:
        console.print(f"[red]AI explanation failed: {exc}[/red]")
        raise typer.Exit(code=1)

    # Validate citations
    verified_citations, ungrounded_citations = extract_cited_finding_ids_with_validation(
        response.text, {finding.finding_id}
    )
    if ungrounded_citations:
        console.print(
            f"[bold yellow]⚠ Grounding Warning: Model cited ungrounded Finding ID(s): {', '.join(ungrounded_citations)}[/bold yellow]"
        )

    # Store annotation
    annot_repo = AIAnnotationRepository(db_path)
    annot = AIAnnotationRecord(
        annotation_id=f"AI-{uuid.uuid4().hex[:8].upper()}",
        case_id=target_case.case_id,
        target_type="FINDING_EXPLANATION",
        target_id=target_fid,
        model_identifier=response.model_name,
        prompt_hash=hashlib.sha256(prompt_text.encode("utf-8")).hexdigest(),
        sanitized_prompt_preview=prompt_text[:200],
        response_text=response.text,
        cited_finding_ids=verified_citations,
    )
    annot_repo.add(annot)

    console.print(Markdown(response.text))
    console.print(f"\n[dim]Analysis saved to case database (Annotation ID: {annot.annotation_id}). Verified citations: {annot.cited_finding_ids}[/dim]")

@app.command("summarize")
def ai_summarize(
    provider: str = typer.Option("gemini", "--provider", "-p", help="AI provider (gemini, ollama, mock)."),
    consent: bool = typer.Option(False, "--consent", "--consent-ai-upload", help="Explicit non-interactive consent to send sanitized data."),
    workspace: Path = typer.Option(Path("."), "--workspace", "-w", help="Workspace directory."),
    case_id: Optional[str] = typer.Option(None, "--case", "--case-id", "-c", help="Target Case ID."),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="Specific model identifier to use."),
):
    """Synthesize complete executive and technical case summary across all findings and events."""
    db_path = workspace.resolve() / DEFAULT_DB_FILENAME
    case_repo = CaseRepository(db_path)
    cases = case_repo.list_all()
    if not cases:
        console.print("[red]No cases found.[/red]")
        raise typer.Exit(code=1)
    target_case = case_repo.get_by_id(case_id) if case_id else cases[0]

    finding_repo = FindingRepository(db_path)
    findings = finding_repo.list_by_case(target_case.case_id)
    timeline_repo = TimelineRepository(db_path)
    events = timeline_repo.list_by_case(target_case.case_id, limit=50)

    prompt_text = build_investigation_summary_prompt(target_case.name, findings, events)

    # Consent Gate
    try:
        request_ai_consent(prompt_text, auto_consent=consent, console=console)
    except ConsentDeniedError as e:
        console.print(f"[yellow]Operation aborted: {e}[/yellow]")
        raise typer.Exit(code=0)

    ai_engine = _resolve_provider(provider, model_name=model)
    console.print(f"[dim]Synthesizing investigation summary via {provider.upper()}...[/dim]")

    try:
        response = ai_engine.summarize_investigation(target_case.name, findings, events)
    except Exception as exc:
        console.print(f"[red]AI summary synthesis failed: {exc}[/red]")
        raise typer.Exit(code=1)

    # Validate citations
    valid_finding_ids = {f.finding_id for f in findings}
    verified_citations, ungrounded_citations = extract_cited_finding_ids_with_validation(
        response.text, valid_finding_ids
    )
    if ungrounded_citations:
        console.print(
            f"[bold yellow]⚠ Grounding Warning: Model cited ungrounded Finding ID(s): {', '.join(ungrounded_citations)}[/bold yellow]"
        )

    annot_repo = AIAnnotationRepository(db_path)
    annot = AIAnnotationRecord(
        annotation_id=f"AI-{uuid.uuid4().hex[:8].upper()}",
        case_id=target_case.case_id,
        target_type="CASE_SUMMARY",
        target_id=target_case.case_id,
        model_identifier=response.model_name,
        prompt_hash=hashlib.sha256(prompt_text.encode("utf-8")).hexdigest(),
        sanitized_prompt_preview=prompt_text[:200],
        response_text=response.text,
        cited_finding_ids=verified_citations,
    )
    annot_repo.add(annot)

    console.print(Markdown(response.text))
    console.print(f"\n[dim]Summary saved to case database (Annotation ID: {annot.annotation_id}). Citations: {annot.cited_finding_ids}[/dim]")

