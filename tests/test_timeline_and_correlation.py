"""Unit tests for timeline normalization and correlation engine."""
from pathlib import Path
import pytest

from bharydangerous.analyzers.evtx_parser import EvtxParser
from bharydangerous.analyzers.weblog_parser import WebLogParser
from bharydangerous.correlation.engine import CorrelationEngine
from bharydangerous.correlation.normalizer import normalize_timestamp_to_utc
from bharydangerous.correlation.timeline import TimelineEngine
from bharydangerous.core.constants import DEFAULT_DB_FILENAME
from bharydangerous.core.models import CaseRecord, EvidenceRecord
from bharydangerous.db.repositories import (
    CaseRepository,
    CorrelationRepository,
    EvidenceRepository,
    TimelineRepository,
)

def test_timestamp_normalizer():
    iso = normalize_timestamp_to_utc("2026-10-12T14:30:00Z")
    assert "2026-10-12" in iso
    assert "+00:00" in iso or "Z" in iso

    epoch_iso = normalize_timestamp_to_utc("1791813600")
    assert "2026" in epoch_iso

def test_timeline_engine_and_correlation(temp_workspace: Path, synthetic_windows_xml: Path, synthetic_web_log: Path):
    db_path = temp_workspace / DEFAULT_DB_FILENAME
    case_repo = CaseRepository(db_path)
    timeline_repo = TimelineRepository(db_path)
    corr_repo = CorrelationRepository(db_path)

    case_record = CaseRecord(
        case_id="CASE-CORR-01",
        name="Correlation Test Case",
        investigator="Ashim",
        workspace_path=str(temp_workspace),
    )
    case_repo.create(case_record)

    ev_repo = EvidenceRepository(db_path)
    ev_repo.add(EvidenceRecord(
        evidence_id="EV-01", case_id="CASE-CORR-01", label="WinLogs",
        evidence_type="LOG_FILE", source_path=str(synthetic_windows_xml),
        file_size_bytes=1000, sha256="aa"*32, md5="bb"*16
    ))
    ev_repo.add(EvidenceRecord(
        evidence_id="EV-02", case_id="CASE-CORR-01", label="WebLogs",
        evidence_type="LOG_FILE", source_path=str(synthetic_web_log),
        file_size_bytes=1000, sha256="cc"*32, md5="dd"*16
    ))

    # Ingest Windows EVTX events (Contains 3 failed logons + 1 success + 1 process spawn)
    evtx_events = EvtxParser().parse_file(synthetic_windows_xml, "CASE-CORR-01", "EV-01")
    timeline_repo.add_batch(evtx_events)

    # Ingest Web access log events
    web_events = WebLogParser().parse_file(synthetic_web_log, "CASE-CORR-01", "EV-02")
    timeline_repo.add_batch(web_events)

    # Query timeline
    timeline_engine = TimelineEngine(timeline_repo)
    stats = timeline_engine.get_summary_stats("CASE-CORR-01")
    assert stats["total_events"] == len(evtx_events) + len(web_events)

    # Run correlation engine
    corr_engine = CorrelationEngine(timeline_repo, corr_repo)
    correlations = corr_engine.run_correlations("CASE-CORR-01")

    assert len(correlations) > 0
    rule_names = [c.rule_name for c in correlations]
    assert "CORR-BRUTEFORCE-LOGON" in rule_names
    assert any("Brute-force attack detected" in c.summary for c in correlations)
