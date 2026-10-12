"""Interactive and non-interactive consent gate for AI transmission."""
import re
from typing import List, Set
from rich.console import Console
from rich.panel import Panel

from bharydangerous.core.exceptions import ConsentDeniedError

def request_ai_consent(prompt_text: str, auto_consent: bool = False, console: Console | None = None) -> bool:
    """
    Ensure explicit consent before transmitting evidence data to an AI model.
    If auto_consent is True (passed via --consent-ai-upload), proceeds.
    Otherwise, displays the preview and prompts interactively.
    """
    if auto_consent:
        return True

    c = console or Console()
    preview = prompt_text[:1000]
    if len(prompt_text) > 1000:
        preview += "\n...[TRUNCATED: Additional evidence context]..."

    c.print(Panel(
        f"[bold yellow]NOTICE: AI Data Transmission Consent Required[/bold yellow]\n\n"
        f"You are about to send forensic evidence excerpt ({len(prompt_text.encode('utf-8'))} bytes) to the configured AI provider.\n\n"
        f"[dim]Data Preview:[/dim]\n{preview}",
        title="Consent Gate",
        border_style="yellow",
    ))

    try:
        response = input("Do you consent to sending this sanitized excerpt to the AI provider? (yes/NO): ")
        if response.strip().lower() in ("yes", "y"):
            return True
        raise ConsentDeniedError("User denied consent for AI data transmission.")
    except (EOFError, KeyboardInterrupt):
        raise ConsentDeniedError("Consent prompt aborted by user.")

def extract_cited_finding_ids_with_validation(response_text: str, valid_finding_ids: Set[str]) -> tuple[List[str], List[str]]:
    """Extract all [FND-...] citations and return (verified_ids, ungrounded_ids)."""
    found_ids = re.findall(r"\[(FND-[A-Za-z0-9\-]+)\]", response_text)
    verified = []
    ungrounded = []
    for fid in found_ids:
        if valid_finding_ids and fid not in valid_finding_ids:
            if fid not in ungrounded:
                ungrounded.append(fid)
        else:
            if fid not in verified:
                verified.append(fid)
    return verified, ungrounded

def extract_and_verify_cited_finding_ids(response_text: str, valid_finding_ids: Set[str]) -> List[str]:
    """Extract all [FND-...] citations from response and return only verified ones."""
    verified, _ = extract_cited_finding_ids_with_validation(response_text, valid_finding_ids)
    return verified
