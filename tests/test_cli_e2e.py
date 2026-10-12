"""End-to-End CLI tests verifying all advertised commands."""
from pathlib import Path
import pytest
from typer.testing import CliRunner

from bharydangerous.cli.app import app

runner = CliRunner()

def test_cli_help_and_version():
    res = runner.invoke(app, ["--help"])
    assert res.exit_code == 0
    assert "BHARYDANGEROUS-Investigator" in res.output

    res_ver = runner.invoke(app, ["version"])
    assert res_ver.exit_code == 0
    assert "Ashim" in res_ver.output

def test_cli_doctor():
    res = runner.invoke(app, ["doctor"])
    assert res.exit_code == 0
    assert "Python Environment" in res.output

def test_cli_plugins():
    res = runner.invoke(app, ["plugins"])
    assert res.exit_code == 0

def test_cli_full_investigation_lifecycle(
    tmp_path: Path,
    synthetic_windows_xml: Path,
    synthetic_pcap: Path,
    synthetic_mbr_disk: Path,
    synthetic_yara_sample: Path,
):
    ws = str(tmp_path)

    # 1. case create
    res_case = runner.invoke(app, ["case", "create", "--name", "Alpha-Incident", "--investigator", "Ashim", "--workspace", ws])
    assert res_case.exit_code == 0
    assert "Case initialized successfully" in res_case.output

    # 2. case list & info
    res_list = runner.invoke(app, ["case", "list", "--workspace", ws])
    assert res_list.exit_code == 0
    assert "Alpha-Incident" in res_list.output

    res_info = runner.invoke(app, ["case", "info", "--workspace", ws])
    assert res_info.exit_code == 0
    assert "Alpha-Incident" in res_info.output

    # 3. evidence add
    res_ev1 = runner.invoke(app, [
        "evidence", "add", str(synthetic_windows_xml),
        "--label", "SecurityLogs", "--type", "LOG_FILE",
        "--workspace", ws,
    ])
    assert res_ev1.exit_code == 0
    assert "Evidence successfully ingested" in res_ev1.output

    res_ev2 = runner.invoke(app, [
        "evidence", "add", str(synthetic_pcap),
        "--label", "NetworkTraffic", "--type", "PCAP",
        "--workspace", ws,
    ])
    assert res_ev2.exit_code == 0

    # 4. evidence verify
    res_v = runner.invoke(app, ["evidence", "verify", "--workspace", ws])
    assert res_v.exit_code == 0
    assert "VERIFIED (MATCH)" in res_v.output

    # 5. evidence list
    res_ev_list = runner.invoke(app, ["evidence", "list", "--workspace", ws])
    assert res_ev_list.exit_code == 0
    assert "SecurityLo" in res_ev_list.output

    # 6. analyze triage
    res_triage = runner.invoke(app, ["analyze", "triage", str(synthetic_windows_xml), "--strings", "--workspace", ws])
    assert res_triage.exit_code == 0
    assert "Triaging File" in res_triage.output

    # 7. analyze logs
    res_logs = runner.invoke(app, ["analyze", "logs", str(synthetic_windows_xml), "--workspace", ws])
    assert res_logs.exit_code == 0
    assert "Parsed and added" in res_logs.output

    # 8. analyze disk
    res_disk = runner.invoke(app, ["analyze", "disk", str(synthetic_mbr_disk), "--workspace", ws])
    assert res_disk.exit_code == 0
    assert "Disk Inspection" in res_disk.output

    # 9. analyze pcap
    res_pcap = runner.invoke(app, ["analyze", "pcap", str(synthetic_pcap), "--workspace", ws])
    assert res_pcap.exit_code == 0
    assert "PCAP Dissection" in res_pcap.output
    assert "Plaintext Credentials" in res_pcap.output

    # 10. analyze yara
    res_yara = runner.invoke(app, ["analyze", "yara", str(synthetic_yara_sample), "--workspace", ws])
    assert res_yara.exit_code == 0
    assert "MATCH:" in res_yara.output

    # 11. timeline build & query
    res_tb = runner.invoke(app, ["timeline", "build", "--workspace", ws])
    assert res_tb.exit_code == 0
    assert "Timeline built" in res_tb.output or "Correlated Incidents" in res_tb.output

    res_tq = runner.invoke(app, ["timeline", "query", "--limit", "10", "--workspace", ws])
    assert res_tq.exit_code == 0
    assert "Timeline Events" in res_tq.output

    # 12. ai explain & summarize (using mock provider and --consent-ai-upload)
    # Find a logged finding ID from database or run explain
    from bharydangerous.core.constants import DEFAULT_DB_FILENAME
    from bharydangerous.db.repositories import FindingRepository
    f_repo = FindingRepository(Path(ws) / DEFAULT_DB_FILENAME)
    findings = f_repo.list_by_case(f_repo._get_conn().execute("SELECT case_id FROM cases").fetchone()[0])
    assert len(findings) > 0
    fid = findings[0].finding_id

    res_ai_exp = runner.invoke(app, [
        "ai", "explain", "--finding", fid,
        "--provider", "mock", "--consent-ai-upload",
        "--workspace", ws,
    ])
    assert res_ai_exp.exit_code == 0
    assert "Technical Finding Analysis" in res_ai_exp.output

    res_ai_sum = runner.invoke(app, [
        "ai", "summarize", "--provider", "mock",
        "--consent-ai-upload", "--workspace", ws,
    ])
    assert res_ai_sum.exit_code == 0
    assert "Executive Incident Investigation Summary" in res_ai_sum.output

    # 13. report generate
    res_rep = runner.invoke(app, [
        "report", "generate", "--format", "all",
        "--output-dir", str(tmp_path / "exports"),
        "--workspace", ws,
    ])
    assert res_rep.exit_code == 0
    assert "Report generated successfully" in res_rep.output

    # Verify generated files
    exp_dir = tmp_path / "exports"
    json_rep = list(exp_dir.glob("*.json"))
    md_rep = list(exp_dir.glob("*.md"))
    html_rep = list(exp_dir.glob("*.html"))
    assert len(json_rep) == 1
    assert len(md_rep) == 1
    assert len(html_rep) == 1
