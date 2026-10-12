"""Linux syslog and authentication log forensic parser."""
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List
from bharydangerous.core.models import TimelineEventRecord

# RFC 3164 Syslog: Oct 12 14:22:01 hostname daemon[pid]: message
SYSLOG_RFC3164 = re.compile(
    r"^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+([a-zA-Z0-9\.\-_]+)\s+([a-zA-Z0-9\.\-_]+)(?:\[(\d+)\])?:\s+(.*)$"
)

# RFC 5424 Syslog: 2026-10-12T14:22:01.000Z hostname app pid msgid ...
SYSLOG_RFC5424 = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\s+([a-zA-Z0-9\.\-_]+)\s+([a-zA-Z0-9\.\-_]+)\s+(\S+)\s+(\S+)\s*(.*)$"
)

SSH_FAILED = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)")
SSH_ACCEPTED = re.compile(r"Accepted (?:password|publickey) for (\S+) from (\S+) port (\d+)")
SUDO_CMD = re.compile(r"(\S+)\s*:\s*.*COMMAND=(.*)")

class SyslogParser:
    """Parser for Linux system logs and authentication events."""

    def parse_file(self, file_path: Path | str, case_id: str, evidence_id: str) -> List[TimelineEventRecord]:
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"Log file not found: {path}")

        events: List[TimelineEventRecord] = []
        current_year = datetime.now(timezone.utc).year

        with path.open("r", encoding="utf-8", errors="ignore") as f:
            for line_idx, line in enumerate(f):
                if line_idx > 10_000:
                    break  # Cap at 10,000 log lines per file
                line = line.strip()
                if not line:
                    continue

                event = self._parse_line(line, line_idx, current_year, case_id, evidence_id)
                if event:
                    events.append(event)

        return events

    def _parse_line(
        self, line: str, line_idx: int, current_year: int, case_id: str, evidence_id: str
    ) -> TimelineEventRecord | None:
        # Try RFC 5424 first
        m5424 = SYSLOG_RFC5424.match(line)
        if m5424:
            ts, host, app, pid, msgid, msg = m5424.groups()
            return self._build_event(ts, host, app, msg, case_id, evidence_id, line)

        # Try RFC 3164
        m3164 = SYSLOG_RFC3164.match(line)
        if m3164:
            ts_str, host, daemon, pid, msg = m3164.groups()
            # Convert "Oct 12 14:22:01" to ISO
            try:
                dt = datetime.strptime(f"{current_year} {ts_str}", "%Y %b %d %H:%M:%S")
                dt = dt.replace(tzinfo=timezone.utc)
                iso_ts = dt.isoformat()
            except Exception:
                iso_ts = datetime.now(timezone.utc).isoformat()
            return self._build_event(iso_ts, host, daemon, msg, case_id, evidence_id, line)

        return None

    def _build_event(
        self, timestamp: str, host: str, daemon: str, msg: str, case_id: str, evidence_id: str, raw_line: str
    ) -> TimelineEventRecord:
        event_type = f"Syslog_{daemon}"
        summary = f"[{daemon}] {msg}"
        actor = host
        target = daemon

        # Check for SSH Failed
        m_failed = SSH_FAILED.search(msg)
        if m_failed:
            user, src_ip, port = m_failed.groups()
            event_type = "SSH_Auth_Failed"
            summary = f"Failed SSH login for user '{user}' from {src_ip}:{port}"
            actor = f"{src_ip} ({user})"
            target = f"ssh:{port}"

        # Check for SSH Accepted
        m_acc = SSH_ACCEPTED.search(msg)
        if m_acc:
            user, src_ip, port = m_acc.groups()
            event_type = "SSH_Auth_Success"
            summary = f"Successful SSH login for user '{user}' from {src_ip}:{port}"
            actor = f"{src_ip} ({user})"
            target = f"ssh:{port}"

        # Check for Sudo Execution
        m_sudo = SUDO_CMD.search(msg)
        if m_sudo:
            user, cmd = m_sudo.groups()
            event_type = "Sudo_Execution"
            summary = f"User '{user}' executed sudo command: {cmd.strip()}"
            actor = user
            target = cmd.strip()

        return TimelineEventRecord(
            event_id=f"EVT-{uuid.uuid4().hex[:12]}",
            case_id=case_id,
            evidence_id=evidence_id,
            timestamp=timestamp,
            timestamp_desc="LogTime",
            source_type="SYSLOG",
            event_type=event_type,
            summary=summary,
            actor=actor,
            target=target,
            raw_record_json={"line": raw_line, "daemon": daemon, "host": host},
            normalized_json={"event_type": event_type, "summary": summary},
        )
