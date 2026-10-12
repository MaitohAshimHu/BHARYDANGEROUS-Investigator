"""Unit tests for AI redaction, consent gate, mock reasoning, and multi-format reporting."""
from pathlib import Path
import json
import pytest

from bharydangerous.ai.consent import extract_and_verify_cited_finding_ids, request_ai_consent
from bharydangerous.ai.mock_provider import MockAIProvider
from bharydangerous.ai.redactor import redact_sensitive_data
from bharydangerous.core.models import (
    CaseRecord,
    DoctorCheckResult,
    EvidenceRecord,
    FindingRecord,
    ReportModel,
    TimelineEventRecord,
)
from bharydangerous.reporting.html_reporter import HtmlReporter
from bharydangerous.reporting.json_reporter import JsonReporter
from bharydangerous.reporting.markdown_reporter import MarkdownReporter

def test_secret_redactor():
    dirty_text = (
        "Found Google API key AIzaSyA1234567890123456789012345678901 and password=SuperSecretPassword123! "
        "and Authorization: Basic YWRtaW46cGFzc3dvcmQ= on server."
    )
    clean_text = redact_sensitive_data(dirty_text)

    assert "AIza" not in clean_text
    assert "[REDACTED_GOOGLE_API_KEY]" in clean_text
    assert "SuperSecretPassword123!" not in clean_text
    assert "[REDACTED_PASSWORD]" in clean_text
    assert "Basic YWRtaW46" not in clean_text

def test_consent_gate_and_citation_verifier():
    # Auto-consent True should pass without prompting
    assert request_ai_consent("test prompt", auto_consent=True) is True

    # Citation verifier
    sample_response = "We analyzed findings [FND-1001] and [FND-1002] along with hallucinated [FND-9999]."
    valid_ids = {"FND-1001", "FND-1002", "FND-1003"}
    cited = extract_and_verify_cited_finding_ids(sample_response, valid_ids)

    assert "FND-1001" in cited
    assert "FND-1002" in cited

def test_mock_ai_provider():
    provider = MockAIProvider()
    finding = FindingRecord(
        finding_id="FND-1001",
        evidence_id="EV-01",
        title="Webshell Detected",
        category="MALWARE",
        severity="HIGH",
        confidence="CONFIRMED_FACT",
        source_artifact="shell.php",
    )
    resp = provider.explain_finding(finding, [])
    assert "[FND-1001]" in resp.text
    assert "FND-1001" in resp.cited_finding_ids

def test_multi_format_reporting(tmp_path: Path):
    case = CaseRecord(
        case_id="CASE-REP-01",
        name="Reporting Test Case",
        investigator="Ashim",
        workspace_path=str(tmp_path),
    )
    evidence = EvidenceRecord(
        evidence_id="EV-01",
        case_id=case.case_id,
        label="Disk Image",
        evidence_type="DISK_IMAGE",
        source_path="/evidence/disk.raw",
        file_size_bytes=1048576,
        sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        md5="d41d8cd98f00b204e9800998ecf8427e",
    )
    finding = FindingRecord(
        finding_id="FND-01",
        evidence_id="EV-01",
        title="Suspicious Cron Job",
        category="PERSISTENCE",
        severity="HIGH",
        confidence="CONFIRMED_FACT",
        source_artifact="/etc/crontab",
    )

    report_model = ReportModel(
        product_name="BHARYDANGEROUS-Investigator",
        version="1.0.0",
        case=case,
        evidence_list=[evidence],
        findings_list=[finding],
        timeline_summary={"total_events": 10, "sources": {"EVTX": 10}},
        correlations=[],
        ai_annotations=[],
        tool_diagnostics=[
            DoctorCheckResult(category="Tools", name="TSK", status="OK", details="Active")
        ],
    )

    # 1. JSON Report
    json_path = tmp_path / "report.json"
    JsonReporter().generate(report_model, json_path)
    assert json_path.is_file()
    loaded = json.loads(json_path.read_text(encoding="utf-8"))
    assert loaded["product_name"] == "BHARYDANGEROUS-Investigator"
    assert loaded["case"]["case_id"] == "CASE-REP-01"

    # 2. Markdown Report
    md_path = tmp_path / "report.md"
    MarkdownReporter().generate(report_model, md_path)
    assert md_path.is_file()
    md_content = md_path.read_text(encoding="utf-8")
    assert "Forensic Investigation Report" in md_content
    assert "FND-01" in md_content

    # 3. HTML Report (Zero-CDN, Standalone)
    html_path = tmp_path / "report.html"
    HtmlReporter().generate(report_model, html_path)
    assert html_path.is_file()
    html_content = html_path.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in html_content
    assert "Reporting Test Case" in html_content
    assert "badge-HIGH" in html_content
    # Confirm zero external CDN links
    assert "cdn." not in html_content
    assert "unpkg.com" not in html_content
    assert "cdnjs.cloudflare.com" not in html_content
