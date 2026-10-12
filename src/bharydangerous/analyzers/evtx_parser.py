"""Windows Event Log (EVTX / XML) forensic parser."""
import re
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional
try:
    from defusedxml.ElementTree import fromstring as safe_xml_fromstring
except ImportError:
    from xml.etree.ElementTree import fromstring as safe_xml_fromstring
import xml.etree.ElementTree as ET

from bharydangerous.core.models import TimelineEventRecord

EVENT_ID_MAP = {
    4624: ("Logon_Success", "Successful user logon"),
    4625: ("Logon_Failed", "Failed user logon / Brute-force indicator"),
    4688: ("Process_Created", "New process created"),
    4720: ("User_Created", "A user account was created"),
    4726: ("User_Deleted", "A user account was deleted"),
    4738: ("User_Modified", "A user account was modified"),
    7045: ("Service_Installed", "A service was installed on system (Persistence)"),
    4104: ("PowerShell_ScriptBlock", "PowerShell script block execution"),
    1: ("Sysmon_ProcessCreate", "Sysmon Process Creation"),
    3: ("Sysmon_NetworkConnect", "Sysmon Network Connection"),
    11: ("Sysmon_FileCreate", "Sysmon File Creation"),
}

class EvtxParser:
    """Parser for Windows Event Logs with XML and binary fallback support."""

    def parse_file(self, file_path: Path | str, case_id: str, evidence_id: str) -> List[TimelineEventRecord]:
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"EVTX file not found: {path}")

        events: List[TimelineEventRecord] = []

        # Check if file is plaintext XML export
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as f:
                head = f.read(512)
                if "<Events" in head or "<Event" in head:
                    return self._parse_xml_events(path, case_id, evidence_id)
        except Exception:
            pass

        # Parse binary EVTX
        return self._parse_binary_evtx(path, case_id, evidence_id)

    def _parse_xml_events(self, path: Path, case_id: str, evidence_id: str) -> List[TimelineEventRecord]:
        events: List[TimelineEventRecord] = []
        content = path.read_text(encoding="utf-8", errors="ignore")
        # Extract <Event> blocks using regex to handle multi-event streams
        event_blocks = re.findall(r"<Event\b[^>]*>.*?</Event>", content, re.DOTALL)

        for block in event_blocks[:5000]:  # Cap at 5000 events
            try:
                root = safe_xml_fromstring(block)
                # Namespace strip
                for elem in root.iter():
                    if "}" in elem.tag:
                        elem.tag = elem.tag.split("}", 1)[1]

                system = root.find("System")
                if system is None:
                    continue

                event_id_elem = system.find("EventID")
                event_id_val = int(event_id_elem.text) if event_id_elem is not None and event_id_elem.text and event_id_elem.text.isdigit() else 0

                time_created = system.find("TimeCreated")
                timestamp = time_created.attrib.get("SystemTime", "1970-01-01T00:00:00Z") if time_created is not None else "1970-01-01T00:00:00Z"

                computer = system.findtext("Computer", "Unknown")
                event_name, desc = EVENT_ID_MAP.get(event_id_val, ("WinEvent", f"Event ID {event_id_val}"))

                # Extract event data fields
                event_data_dict = {}
                event_data = root.find("EventData")
                if event_data is not None:
                    for data in event_data.findall("Data"):
                        name = data.attrib.get("Name", "Field")
                        event_data_dict[name] = data.text or ""

                actor = event_data_dict.get("TargetUserName") or event_data_dict.get("SubjectUserName") or computer
                target = event_data_dict.get("NewProcessName") or event_data_dict.get("WorkstationName") or ""

                summary = f"{desc} (ID: {event_id_val})"
                if actor:
                    summary += f" by {actor}"
                if target:
                    summary += f" targeting {target}"

                events.append(TimelineEventRecord(
                    event_id=f"EVT-{uuid.uuid4().hex[:12]}",
                    case_id=case_id,
                    evidence_id=evidence_id,
                    timestamp=timestamp,
                    timestamp_desc="TimeCreated",
                    source_type="EVTX",
                    event_type=event_name,
                    summary=summary,
                    actor=actor,
                    target=target,
                    raw_record_json={"EventID": event_id_val, "Computer": computer, "Data": event_data_dict},
                    normalized_json={"event_id": event_id_val, "name": event_name},
                ))
            except Exception:
                continue

        return events

    def _parse_binary_evtx(self, path: Path, case_id: str, evidence_id: str) -> List[TimelineEventRecord]:
        """Binary parser fallback for raw EVTX files."""
        events: List[TimelineEventRecord] = []
        with path.open("rb") as f:
            header = f.read(4096)
            if not header.startswith(b"ElfFile\x00"):
                return []

            f.seek(0)
            data = f.read(10 * 1024 * 1024)  # Read up to 10 MB for chunk triage

        # Scan for Event IDs and timestamps via string/regex heuristics
        time_regex = re.compile(rb"\b(20[2-3][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9](?:\.[0-9]+)?Z)\b")
        id_regex = re.compile(rb"<EventID[^>]*>([0-9]+)</EventID>")

        timestamps = [m.group(1).decode("ascii") for m in time_regex.finditer(data)]
        event_ids = [int(m.group(1).decode("ascii")) for m in id_regex.finditer(data)]

        count = min(len(timestamps), len(event_ids), 1000)
        for i in range(count):
            eid = event_ids[i]
            ts = timestamps[i]
            event_name, desc = EVENT_ID_MAP.get(eid, ("WinEvent", f"Event ID {eid}"))
            events.append(TimelineEventRecord(
                event_id=f"EVT-{uuid.uuid4().hex[:12]}",
                case_id=case_id,
                evidence_id=evidence_id,
                timestamp=ts,
                timestamp_desc="TimeCreated",
                source_type="EVTX",
                event_type=event_name,
                summary=f"{desc} (ID: {eid})",
                actor="System/Extracted",
                target="",
                raw_record_json={"EventID": eid, "Timestamp": ts},
                normalized_json={"event_id": eid, "name": event_name},
            ))

        return events
