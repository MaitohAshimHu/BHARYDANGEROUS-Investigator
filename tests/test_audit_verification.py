"""Release-readiness audit verification tests for BHARYDANGEROUS-Investigator.

Covers:
- Memory forensics adapter and native memory triage.
- Volatility plugin execution (mocked and uninstalled fallback).
- Config CLI subcommands (show, set-api-key, set-model).
- Evidence verification failure detection (tampered file, missing file).
- Evidence read-only enforcement upon ingestion.
- HTML report XSS autoescaping and incomplete-analysis warning banners.
- Redaction of Bearer tokens, JWTs, and API credentials in logs and error messages.
- Gemini provider missing API key and exception sanitization.
- Deterministic offline analyzers.
"""
import json
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest
from typer.testing import CliRunner

from bharydangerous.adapters.base import SubprocessResult
from bharydangerous.adapters.volatility import VolatilityAdapter
from bharydangerous.ai.gemini import GeminiProvider
from bharydangerous.ai.redactor import redact_sensitive_data
from bharydangerous.analyzers.memory_inspector import MemoryInspector
from bharydangerous.cli.app import app
from bharydangerous.core.constants import DEFAULT_DB_FILENAME
from bharydangerous.core.exceptions import AIProviderError
from bharydangerous.core.hashing import is_file_readonly, set_file_readonly
from bharydangerous.core.models import (
    CaseRecord,
    DoctorCheckResult,
    EvidenceRecord,
    FindingRecord,
    ReportModel,
)
from bharydangerous.db.repositories import CaseRepository, EvidenceRepository
from bharydangerous.reporting.html_reporter import HtmlReporter
from bharydangerous.reporting.markdown_reporter import MarkdownReporter

runner = CliRunner()


def test_memory_adapter_native_triage(synthetic_memory_dump: Path):
    """Verify native memory triage without Volatility finds PE headers, IPs, and URLs."""
    adapter = VolatilityAdapter()
    res = adapter.native_memory_triage(synthetic_memory_dump)

    assert res["method"] == "native_memory_triage"
    assert res["pe_headers_detected"] >= 1
    assert "198.51.100.77" in res["ip_indicators"]
    assert any("c2.forensic-testing.org" in url for url in res["url_indicators"])


def test_memory_inspector_and_volatility_mock(synthetic_memory_dump: Path):
    """Verify MemoryInspector runs native triage and handles mocked Volatility output."""
    inspector = MemoryInspector()

    # Case 1: Volatility not available (default fallback)
    with patch.object(inspector.vol_adapter, "vol_cmd", None):
        res = inspector.inspect_memory(synthetic_memory_dump, evidence_id="EV-MEM-01")
        assert res["volatility_executed"] is False
        assert len(res["findings"]) >= 1
        assert "Embedded Portable Executables" in res["findings"][0].title

    # Case 2: Volatility available with mocked pslist & malfind hits
    mock_malfind_output = SubprocessResult(
        exit_code=0,
        stdout="PID\tProcess\tAddress\tProtection\n1044\tsvchost.exe\t0x7ffa0000\tPAGE_EXECUTE_READWRITE",
        stderr="",
    )
    with patch.object(inspector.vol_adapter, "vol_cmd", "vol"), \
         patch("bharydangerous.adapters.volatility.run_command_safely", return_value=mock_malfind_output):
        res_vol = inspector.inspect_memory(synthetic_memory_dump, evidence_id="EV-MEM-01")
        assert res_vol["volatility_executed"] is True
        assert "pslist" in res_vol["volatility_results"]
        assert "malfind" in res_vol["volatility_results"]
        titles = [f.title for f in res_vol["findings"]]
        assert any("Injected Memory Section" in t for t in titles)


def test_cli_analyze_memory(tmp_path: Path, synthetic_memory_dump: Path):
    """Verify CLI 'bdinvestigator analyze memory' executes properly."""
    ws = str(tmp_path)
    runner.invoke(app, ["case", "create", "--name", "MemCase", "--workspace", ws])

    res = runner.invoke(app, ["analyze", "memory", str(synthetic_memory_dump), "--workspace", ws])
    assert res.exit_code == 0
    assert "Memory Dump Analysis" in res.output
    assert "Embedded Portable Executables" in res.output or "Native Memory Triage" in res.output


def test_cli_config_commands(tmp_path: Path, monkeypatch):
    """Verify 'bdinvestigator config show', 'set-api-key', and 'set-model' subcommands."""
    mock_env = {}
    monkeypatch.setattr("os.environ", mock_env)

    # Isolate config file to temporary directory
    tmp_config = tmp_path / "config.json"
    monkeypatch.setattr("bharydangerous.core.config.CONFIG_FILE", tmp_config)
    monkeypatch.setattr("bharydangerous.cli.config_cmd.CONFIG_FILE", tmp_config)

    # Show initially (empty)
    res_show = runner.invoke(app, ["config", "show"])
    assert res_show.exit_code == 0
    assert "BHARYDANGEROUS-Investigator Configuration" in res_show.output
    assert "Not Set" in res_show.output

    # Set API Key
    res_key = runner.invoke(app, ["config", "set-api-key", "AIzaSyTestKey123456789012345678901234"])
    assert res_key.exit_code == 0
    assert "Gemini API key saved successfully" in res_key.output
    saved_cfg = json.loads(tmp_config.read_text(encoding="utf-8"))
    assert saved_cfg.get("gemini_api_key") == "AIzaSyTestKey123456789012345678901234"

    # Set Model
    res_model = runner.invoke(app, ["config", "set-model", "gemini-2.5-flash"])
    assert res_model.exit_code == 0
    assert "Default model updated to" in res_model.output
    saved_cfg2 = json.loads(tmp_config.read_text(encoding="utf-8"))
    assert saved_cfg2.get("gemini_model") == "gemini-2.5-flash"

    # Show after setting
    res_show2 = runner.invoke(app, ["config", "show"])
    assert res_show2.exit_code == 0
    assert "AIzaSyTestKey" not in res_show2.output  # Full key should be masked!
    assert "AIzaSy...1234" in res_show2.output
    assert "gemini-2.5-flash" in res_show2.output


def test_evidence_tamper_and_missing_verification_failure(tmp_path: Path):
    """Verify that evidence verification fails with exit code 1 when files are tampered or missing."""
    ws = str(tmp_path)
    runner.invoke(app, ["case", "create", "--name", "VerifyCase", "--workspace", ws])

    # Create dummy evidence file
    ev_file = tmp_path / "original_sample.bin"
    ev_file.write_bytes(b"Clean Forensic Payload Data")

    # Add evidence
    res_add = runner.invoke(app, [
        "evidence", "add", str(ev_file),
        "--label", "Sample", "--type", "FILE",
        "--workspace", ws,
    ])
    assert res_add.exit_code == 0

    # 1. Initial verification must pass
    res_v1 = runner.invoke(app, ["evidence", "verify", "--workspace", ws])
    assert res_v1.exit_code == 0
    assert "VERIFIED (MATCH)" in res_v1.output

    # 2. Tamper the evidence file in the case storage (or source)
    db_path = tmp_path / DEFAULT_DB_FILENAME
    ev_repo = EvidenceRepository(db_path)
    case_repo = CaseRepository(db_path)
    cases = case_repo.list_all()
    active_case = cases[0]
    evidence_records = ev_repo.list_by_case(active_case.case_id)
    target_ev_path = Path(evidence_records[0].stored_path or evidence_records[0].source_path)

    # Modify file contents (unset read-only first if necessary)
    target_ev_path.chmod(0o666)
    target_ev_path.write_bytes(b"Tampered Malicious Forensic Payload")

    res_v_tampered = runner.invoke(app, ["evidence", "verify", "--workspace", ws])
    assert res_v_tampered.exit_code == 1
    assert "TAMPERED" in res_v_tampered.output or "FAILED" in res_v_tampered.output

    # 3. Missing file verification must fail
    target_ev_path.unlink()
    res_v_missing = runner.invoke(app, ["evidence", "verify", "--workspace", ws])
    assert res_v_missing.exit_code == 1
    assert "MISSING" in res_v_missing.output or "FAILED" in res_v_missing.output


def test_evidence_read_only_enforcement(tmp_path: Path):
    """Verify set_file_readonly marks files read-only and prevents modification."""
    test_file = tmp_path / "readonly_test.dat"
    test_file.write_bytes(b"Immutable Evidence")

    set_file_readonly(test_file)
    assert is_file_readonly(test_file) is True

    # Attempting to write in standard mode should raise PermissionError
    with pytest.raises(PermissionError):
        with open(test_file, "wb") as f:
            f.write(b"Attempt to overwrite")


def test_report_html_xss_escaping_and_warnings(tmp_path: Path):
    """Verify Jinja2 HTML report autoescapes XSS vectors and includes incomplete-analysis warning banners."""
    case = CaseRecord(
        case_id="CASE-XSS-01",
        name="<script>alert('XSS_CASE')</script>",
        investigator="Ashim",
        workspace_path=str(tmp_path),
    )
    evidence = EvidenceRecord(
        evidence_id="EV-01",
        case_id=case.case_id,
        label="<img src=x onerror=alert('XSS_EV')>",
        evidence_type="LOG_FILE",
        source_path="/test/path",
        file_size_bytes=100,
        sha256="0" * 64,
        md5="0" * 32,
    )
    finding = FindingRecord(
        finding_id="FND-01",
        evidence_id="EV-01",
        title="<script>alert('XSS_FINDING')</script>",
        category="MALWARE",
        severity="CRITICAL",
        confidence="CONFIRMED_FACT",
        source_artifact="payload.log",
    )

    report_model = ReportModel(
        product_name="BHARYDANGEROUS-Investigator",
        version="1.0.0",
        case=case,
        evidence_list=[evidence],
        findings_list=[finding],
        timeline_summary={"total_events": 1},
        correlations=[],
        ai_annotations=[],
        tool_diagnostics=[
            DoctorCheckResult(category="Tools", name="TSK", status="MISSING", details="SleuthKit not installed in PATH")
        ],
        incomplete_analysis_warnings=[
            "WARNING: The SleuthKit is missing. Detailed NTFS/EXT4 filesystem analysis was skipped.",
            "WARNING: Volatility 3 is missing. Deep kernel memory inspection was skipped.",
        ],
    )

    html_file = tmp_path / "xss_test_report.html"
    HtmlReporter().generate(report_model, html_file)
    content = html_file.read_text(encoding="utf-8")

    # Verify XSS strings are autoescaped
    assert "<script>alert('XSS_FINDING')</script>" not in content
    assert "&lt;script&gt;alert(&#39;XSS_FINDING&#39;)&lt;/script&gt;" in content or "&lt;script&gt;alert('XSS_FINDING')&lt;/script&gt;" in content
    assert "<img src=x onerror=alert('XSS_EV')>" not in content

    # Verify Incomplete Analysis Warning Banner is rendered prominently
    assert "Incomplete Analysis & Environment Warnings" in content
    assert "The SleuthKit is missing" in content
    assert "Volatility 3 is missing" in content

    # Test Markdown report includes the warning banner as well
    md_file = tmp_path / "warning_test_report.md"
    MarkdownReporter().generate(report_model, md_file)
    md_content = md_file.read_text(encoding="utf-8")
    assert "Incomplete Analysis & Environment Warnings" in md_content
    assert "The SleuthKit is missing" in md_content


def test_bearer_token_and_jwt_redaction():
    """Verify Bearer tokens and JWT structures are redacted from raw data."""
    raw = (
        "Authorization: Bearer ya29.a0AfH6SMBxyz1234567890abcdefghijklmnopqrstuvwxyz\n"
        "JWT Session: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    redacted = redact_sensitive_data(raw)

    assert "ya29." not in redacted
    assert "[REDACTED_TOKEN]" in redacted
    assert "eyJhbGciOi" not in redacted
    assert "[REDACTED_JWT_TOKEN]" in redacted


def test_gemini_error_handling_sanitization(monkeypatch):
    """Verify GeminiProvider sanitizes secrets in exceptions and handles missing API key."""
    # When GEMINI_API_KEY is not set
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setattr("bharydangerous.ai.gemini.get_gemini_api_key", lambda: None)
    with pytest.raises(AIProviderError) as exc_info:
        GeminiProvider()
    assert "Gemini API key not found" in str(exc_info.value)

    # When an API exception contains an accidental key during generation
    with patch("google.genai.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.models.generate_content.side_effect = Exception(
            "Request failed for key AIzaSyDummyTestKeyForVerification999: 403 Forbidden"
        )

        provider = GeminiProvider(api_key="AIzaSyDummyTestKeyForVerification999")
        provider._client = mock_client

        with pytest.raises(AIProviderError) as exc_info2:
            provider._generate_with_retry("Test prompt", max_retries=1)

        err_str = str(exc_info2.value)
        assert "AIzaSyDummyTestKeyForVerification999" not in err_str
        assert "[REDACTED_GOOGLE_API_KEY]" in err_str


def test_cli_case_id_alias(tmp_path: Path):
    """Verify --case-id alias works everywhere --case is supported."""
    ws = str(tmp_path)
    res = runner.invoke(app, ["case", "create", "--name", "AliasCase", "--workspace", ws])
    assert res.exit_code == 0

    res_info = runner.invoke(app, ["case", "info", "--case-id", "AliasCase", "--workspace", ws])
    assert res_info.exit_code == 0
    assert "AliasCase" in res_info.output
