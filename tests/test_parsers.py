"""Unit tests for forensic parsers (EVTX, Syslog, Web, PCAP, Disk, YARA)."""
from pathlib import Path
import pytest

from bharydangerous.adapters.sleuthkit import SleuthKitAdapter
from bharydangerous.adapters.yara_adapter import YaraAdapter
from bharydangerous.analyzers.evtx_parser import EvtxParser
from bharydangerous.analyzers.pcap_analyzer import PcapAnalyzer
from bharydangerous.analyzers.syslog_parser import SyslogParser
from bharydangerous.analyzers.weblog_parser import WebLogParser

def test_evtx_parser(synthetic_windows_xml: Path):
    parser = EvtxParser()
    events = parser.parse_file(synthetic_windows_xml, case_id="CASE-TEST", evidence_id="EV-TEST")

    assert len(events) == 5
    event_types = [e.event_type for e in events]
    assert event_types.count("Logon_Failed") == 3
    assert "Logon_Success" in event_types
    assert "Process_Created" in event_types

def test_syslog_and_auth_parser(synthetic_auth_log: Path):
    parser = SyslogParser()
    events = parser.parse_file(synthetic_auth_log, case_id="CASE-TEST", evidence_id="EV-TEST")

    assert len(events) == 5
    types = [e.event_type for e in events]
    assert types.count("SSH_Auth_Failed") == 3
    assert "SSH_Auth_Success" in types
    assert "Sudo_Execution" in types

def test_web_log_parser(synthetic_web_log: Path):
    parser = WebLogParser()
    events = parser.parse_file(synthetic_web_log, case_id="CASE-TEST", evidence_id="EV-TEST")

    assert len(events) == 3
    event_types = [e.event_type for e in events]
    assert "Web_SQL_Injection" in event_types
    assert "Web_Webshell_Access" in event_types

def test_pcap_analyzer(synthetic_pcap: Path):
    analyzer = PcapAnalyzer()
    res = analyzer.analyze_pcap(synthetic_pcap, case_id="CASE-TEST", evidence_id="EV-TEST")

    assert res["valid"] is True
    assert res["packet_count"] == 2
    assert "malicious-c2.example.com" in res["dns_queries"]
    assert len(res["http_requests"]) == 1

    creds = res["plaintext_credentials_found"]
    assert len(creds) == 1
    assert "admin:SuperSecret123" in creds[0]["credential"]

def test_disk_native_mbr_parser(synthetic_mbr_disk: Path):
    adapter = SleuthKitAdapter()
    info = adapter.inspect_partitions(synthetic_mbr_disk)

    assert info["has_mbr_magic"] is True
    partitions = info["partitions"]
    assert len(partitions) == 1
    assert partitions[0]["slot"] == "MBR-1"
    assert "Linux Native" in partitions[0]["description"]

def test_yara_scanner(synthetic_yara_sample: Path):
    adapter = YaraAdapter()
    matches = adapter.scan_file(synthetic_yara_sample)

    assert len(matches) > 0
    rule_names = [m.rule_name for m in matches]
    assert any("webshell" in r.lower() for r in rule_names)
