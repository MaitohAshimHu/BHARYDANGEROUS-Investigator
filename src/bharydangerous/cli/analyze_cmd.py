"""Forensic analysis sub-commands (triage, logs, disk, memory, pcap, yara)."""
from pathlib import Path
from typing import Optional
import uuid
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from bharydangerous.adapters.yara_adapter import YaraAdapter
from bharydangerous.analyzers.archive_inspector import ArchiveInspector
from bharydangerous.analyzers.disk_inspector import DiskInspector
from bharydangerous.analyzers.evtx_parser import EvtxParser
from bharydangerous.analyzers.file_triage import triage_file
from bharydangerous.analyzers.memory_inspector import MemoryInspector
from bharydangerous.analyzers.pcap_analyzer import PcapAnalyzer
from bharydangerous.analyzers.strings_extractor import extract_strings
from bharydangerous.analyzers.syslog_parser import SyslogParser
from bharydangerous.analyzers.weblog_parser import WebLogParser
from bharydangerous.core.constants import DEFAULT_DB_FILENAME
from bharydangerous.core.models import FindingRecord
from bharydangerous.db.repositories import CaseRepository, EvidenceRepository, FindingRepository, TimelineRepository

app = typer.Typer(help="Execute specialized forensic analysis modules.")
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

@app.command("triage")
def analyze_triage(
    path: Path = typer.Argument(..., help="Path to file or archive to triage."),
    extract_strings_flag: bool = typer.Option(False, "--strings", "-s", help="Extract printable strings and regex IOCs."),
    workspace: Path = typer.Option(Path("."), "--workspace", "-w", help="Workspace directory."),
    case_id: Optional[str] = typer.Option(None, "--case", "--case-id", "-c", help="Target Case ID."),
):
    """File identification, entropy calculation, binary headers, and archive inspection."""
    target = path.resolve()
    if not target.is_file():
        console.print(f"[red]Target file not found: {target}[/red]")
        raise typer.Exit(code=1)

    db_path, cid = _get_context(workspace, case_id)
    ev_repo = EvidenceRepository(db_path)
    finding_repo = FindingRepository(db_path)

    # Find or auto-associate evidence
    ev_list = ev_repo.list_by_case(cid)
    ev_id = ev_list[0].evidence_id if ev_list else "EV-UNTRACKED"

    console.print(f"[bold cyan]Triaging File: {target.name}[/bold cyan]")
    triage_res = triage_file(target)

    console.print(f"  [bold]Format:[/bold]       {triage_res['file_type']} ({triage_res['mime_type']})")
    console.print(f"  [bold]Size:[/bold]         {triage_res['file_size_bytes']:,} bytes")
    console.print(f"  [bold]Entropy:[/bold]      {triage_res['entropy']} / 8.0")
    console.print(f"  [bold]SHA-256:[/bold]      {triage_res['sha256']}")

    # If high entropy, generate finding
    if triage_res["is_high_entropy"]:
        f = FindingRecord(
            finding_id=f"FND-{uuid.uuid4().hex[:8].upper()}",
            evidence_id=ev_id,
            title=f"High Entropy File ({triage_res['entropy']}): Potential Packed / Encrypted Payload",
            category="MALWARE",
            severity="MEDIUM",
            confidence="HEURISTIC_DETECTION",
            facts_json={"entropy": triage_res["entropy"], "mime": triage_res["mime_type"]},
            analyst_notes="Entropy exceeds 7.2 threshold indicating compression or encryption.",
            source_artifact=target.name,
        )
        finding_repo.add(f)
        console.print(f"  [bold yellow]⚠ Finding Logged:[/bold yellow] {f.title} ([bold]{f.finding_id}[/bold])")

    # If archive, inspect safety
    if "Archive" in triage_res["file_type"] or "ZIP" in triage_res["file_type"]:
        console.print("[dim]Inspecting archive structure for decompression bombs...[/dim]")
        arch_insp = ArchiveInspector()
        arch_res = arch_insp.inspect_archive(target)
        if arch_res.get("valid"):
            console.print(f"  [bold]Entries:[/bold]      {arch_res['entry_count']}")
            console.print(f"  [bold]Expansion:[/bold]    {arch_res['overall_ratio']}:1 ({arch_res['uncompressed_size_bytes']:,} bytes)")
            if arch_res.get("is_bomb_suspect"):
                f = FindingRecord(
                    finding_id=f"FND-{uuid.uuid4().hex[:8].upper()}",
                    evidence_id=ev_id,
                    title=f"Potential Decompression Bomb Detected ({arch_res['overall_ratio']}:1)",
                    category="ANOMALY",
                    severity="CRITICAL",
                    confidence="CONFIRMED_FACT",
                    facts_json=arch_res,
                    analyst_notes="Archive expansion ratio exceeds safety threshold.",
                    source_artifact=target.name,
                )
                finding_repo.add(f)
                console.print(f"  [bold red]🚨 CRITICAL Finding:[/bold red] {f.title}")

    # Strings extraction
    if extract_strings_flag:
        console.print("[dim]Extracting printable strings and IOCs...[/dim]")
        str_res = extract_strings(target)
        iocs = str_res["iocs"]
        console.print(f"  [bold]Strings Extracted:[/bold] {str_res['total_extracted']:,}")
        if iocs["ips"]:
            console.print(f"  [bold]IPs Found:[/bold] {', '.join(iocs['ips'][:5])}")
        if iocs["urls"]:
            console.print(f"  [bold]URLs Found:[/bold] {', '.join(iocs['urls'][:3])}")

@app.command("logs")
def analyze_logs(
    path: Path = typer.Argument(..., help="Path to log file (EVTX, syslog, web access log)."),
    log_format: str = typer.Option("auto", "--format", "-f", help="Log format (auto, evtx, syslog, web)."),
    workspace: Path = typer.Option(Path("."), "--workspace", "-w", help="Workspace directory."),
    case_id: Optional[str] = typer.Option(None, "--case", "--case-id", "-c", help="Target Case ID."),
):
    """Parse log files into normalized timeline events."""
    target = path.resolve()
    if not target.is_file():
        console.print(f"[red]Log file not found: {target}[/red]")
        raise typer.Exit(code=1)

    db_path, cid = _get_context(workspace, case_id)
    ev_repo = EvidenceRepository(db_path)
    ev_list = ev_repo.list_by_case(cid)
    ev_id = ev_list[0].evidence_id if ev_list else "EV-UNTRACKED"

    timeline_repo = TimelineRepository(db_path)
    events = []

    fmt = log_format.lower()
    if fmt == "auto":
        if target.suffix.lower() == ".evtx" or "ElfFile" in target.name:
            fmt = "evtx"
        elif "access" in target.name.lower() or "nginx" in target.name.lower() or "apache" in target.name.lower():
            fmt = "web"
        else:
            fmt = "syslog"

    console.print(f"[bold cyan]Parsing Log Artifact ({fmt.upper()}): {target.name}[/bold cyan]")
    if fmt == "evtx":
        parser = EvtxParser()
        events = parser.parse_file(target, cid, ev_id)
    elif fmt == "web":
        parser = WebLogParser()
        events = parser.parse_file(target, cid, ev_id)
    else:
        parser = SyslogParser()
        events = parser.parse_file(target, cid, ev_id)

    timeline_repo.add_batch(events)
    console.print(f"[bold green]✓[/bold green] Parsed and added [bold]{len(events)}[/bold] normalized events to timeline!")

@app.command("disk")
def analyze_disk(
    path: Path = typer.Argument(..., help="Path to raw disk image (.dd, .raw, .img)."),
    workspace: Path = typer.Option(Path("."), "--workspace", "-w", help="Workspace directory."),
    case_id: Optional[str] = typer.Option(None, "--case", "--case-id", "-c", help="Target Case ID."),
):
    """Inspect partition tables and filesystems on disk images."""
    target = path.resolve()
    if not target.is_file():
        console.print(f"[red]Disk image not found: {target}[/red]")
        raise typer.Exit(code=1)

    db_path, cid = _get_context(workspace, case_id)
    ev_repo = EvidenceRepository(db_path)
    finding_repo = FindingRepository(db_path)
    ev_list = ev_repo.list_by_case(cid)
    ev_id = ev_list[0].evidence_id if ev_list else "EV-UNTRACKED"

    inspector = DiskInspector()
    res = inspector.inspect_disk(target, ev_id)

    console.print(f"[bold cyan]Disk Inspection: {target.name}[/bold cyan]")
    p_info = res["partition_info"]
    console.print(f"  Method: {p_info.get('method')}")

    parts = p_info.get("partitions", [])
    if parts:
        table = Table(title="Detected Partitions", show_header=True)
        table.add_column("Slot")
        table.add_column("Start Sector")
        table.add_column("Length")
        table.add_column("Type / Description")
        for p in parts:
            table.add_row(str(p.get("slot")), str(p.get("start_sector")), str(p.get("length_sectors")), str(p.get("description")))
        console.print(table)
    else:
        console.print("[dim]No standard partition tables detected.[/dim]")

    for f in res["findings"]:
        finding_repo.add(f)
        console.print(f"[yellow]Finding Logged:[/yellow] {f.title} ({f.finding_id})")

@app.command("memory")
def analyze_memory(
    path: Path = typer.Argument(..., help="Path to raw memory dump (.raw, .dmp, .bin)."),
    workspace: Path = typer.Option(Path("."), "--workspace", "-w", help="Workspace directory."),
    case_id: Optional[str] = typer.Option(None, "--case", "--case-id", "-c", help="Target Case ID."),
):
    """Analyze memory dumps using Volatility 3 or native heuristic memory scanning."""
    target = path.resolve()
    if not target.is_file():
        console.print(f"[red]Memory dump not found: {target}[/red]")
        raise typer.Exit(code=1)

    db_path, cid = _get_context(workspace, case_id)
    ev_repo = EvidenceRepository(db_path)
    finding_repo = FindingRepository(db_path)
    ev_list = ev_repo.list_by_case(cid)
    ev_id = ev_list[0].evidence_id if ev_list else "EV-UNTRACKED"

    inspector = MemoryInspector()
    res = inspector.inspect_memory(target, ev_id)

    console.print(f"[bold cyan]Memory Dump Analysis: {target.name}[/bold cyan]")
    console.print(f"  Volatility Executed: {res['volatility_executed']}")
    nt = res["native_triage"]
    console.print(f"  Embedded PE Headers: {nt.get('pe_headers_detected', 0)}")
    console.print(f"  IP Indicators Found: {len(nt.get('ip_indicators', []))}")
    console.print(f"  URL Indicators Found: {len(nt.get('url_indicators', []))}")

    for f in res["findings"]:
        finding_repo.add(f)
        console.print(f"[yellow]Finding Logged:[/yellow] {f.title} ({f.finding_id})")

@app.command("pcap")
def analyze_pcap(
    path: Path = typer.Argument(..., help="Path to PCAP capture file."),
    workspace: Path = typer.Option(Path("."), "--workspace", "-w", help="Workspace directory."),
    case_id: Optional[str] = typer.Option(None, "--case", "--case-id", "-c", help="Target Case ID."),
):
    """Dissect PCAP files: IP conversations, DNS lookups, HTTP traffic, and unencrypted credentials."""
    target = path.resolve()
    if not target.is_file():
        console.print(f"[red]PCAP file not found: {target}[/red]")
        raise typer.Exit(code=1)

    db_path, cid = _get_context(workspace, case_id)
    ev_repo = EvidenceRepository(db_path)
    finding_repo = FindingRepository(db_path)
    timeline_repo = TimelineRepository(db_path)
    ev_list = ev_repo.list_by_case(cid)
    ev_id = ev_list[0].evidence_id if ev_list else "EV-UNTRACKED"

    analyzer = PcapAnalyzer()
    res = analyzer.analyze_pcap(target, cid, ev_id)

    if not res.get("valid"):
        console.print(f"[red]Error parsing PCAP: {res.get('error')}[/red]")
        raise typer.Exit(code=1)

    console.print(f"[bold cyan]PCAP Dissection: {target.name}[/bold cyan]")
    console.print(f"  Total Packets:         {res['packet_count']:,}")
    console.print(f"  Distinct Conversations: {len(res['conversations'])}")
    console.print(f"  DNS Domains Queried:    {len(res['dns_queries'])}")
    console.print(f"  HTTP Sessions:          {len(res['http_requests'])}")

    # Add timeline events
    if res.get("timeline_events"):
        timeline_repo.add_batch(res["timeline_events"])
        console.print(f"[bold green]✓[/bold green] Added {len(res['timeline_events'])} network events to timeline.")

    # Check for credentials
    creds = res.get("plaintext_credentials_found", [])
    if creds:
        console.print(f"[bold red]🚨 Plaintext Credentials Identified in Network Stream![/bold red]")
        for c in creds:
            f = FindingRecord(
                finding_id=f"FND-{uuid.uuid4().hex[:8].upper()}",
                evidence_id=ev_id,
                title=f"Unencrypted HTTP Basic Credentials Found: {c['credential']}",
                category="CREDENTIAL_ACCESS",
                severity="HIGH",
                confidence="CONFIRMED_FACT",
                facts_json=c,
                analyst_notes="Identified cleartext basic auth header in HTTP request.",
                source_artifact=target.name,
            )
            finding_repo.add(f)
            console.print(f"  Finding: {f.title} ({f.finding_id})")

@app.command("yara")
def analyze_yara(
    path: Path = typer.Argument(..., help="Path to file or directory to scan."),
    rule_file: Optional[Path] = typer.Option(None, "--rules", "-r", help="Custom .yar rule file."),
    workspace: Path = typer.Option(Path("."), "--workspace", "-w", help="Workspace directory."),
    case_id: Optional[str] = typer.Option(None, "--case", "--case-id", "-c", help="Target Case ID."),
):
    """Scan file or folder against default or custom forensic YARA rules."""
    target = path.resolve()
    if not target.exists():
        console.print(f"[red]Target path not found: {target}[/red]")
        raise typer.Exit(code=1)

    db_path, cid = _get_context(workspace, case_id)
    ev_repo = EvidenceRepository(db_path)
    finding_repo = FindingRepository(db_path)
    ev_list = ev_repo.list_by_case(cid)
    ev_id = ev_list[0].evidence_id if ev_list else "EV-UNTRACKED"

    adapter = YaraAdapter()
    files_to_scan = [target] if target.is_file() else [p for p in target.rglob("*") if p.is_file()][:100]

    console.print(f"[bold cyan]Scanning {len(files_to_scan)} file(s) with YARA...[/bold cyan]")
    total_matches = 0

    for fpath in files_to_scan:
        matches = adapter.scan_file(fpath, rule_file)
        for m in matches:
            total_matches += 1
            f = FindingRecord(
                finding_id=f"FND-{uuid.uuid4().hex[:8].upper()}",
                evidence_id=ev_id,
                title=f"YARA Detection: {m.rule_name} on {fpath.name}",
                category="MALWARE",
                severity="HIGH",
                confidence="HEURISTIC_DETECTION",
                facts_json=m.to_dict(),
                analyst_notes=f"Matched YARA rule {m.rule_name} with tags {m.tags}.",
                source_artifact=fpath.name,
            )
            finding_repo.add(f)
            console.print(f"  [bold red]MATCH:[/bold red] {m.rule_name} on [bold]{fpath.name}[/bold] -> Finding {f.finding_id}")

    if total_matches == 0:
        console.print("[green]✓ Clean scan: No YARA signature matches detected.[/green]")
    else:
        console.print(f"[bold yellow]Total YARA Detections:[/bold yellow] {total_matches}")
