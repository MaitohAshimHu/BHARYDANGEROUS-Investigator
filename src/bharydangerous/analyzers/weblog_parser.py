"""Web server access log parser (Apache, Nginx, IIS) with attack pattern matching."""
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List
from bharydangerous.core.models import TimelineEventRecord

# Combined Log Format: 192.168.1.10 - - [12/Oct/2026:14:22:01 +0000] "GET /index.php HTTP/1.1" 200 1234 "referer" "user-agent"
COMBINED_REGEX = re.compile(
    r'^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^"\s]+)\s+([^"]+)"\s+(\d{3})\s+(\S+)(?:\s+"([^"]*)"\s+"([^"]*)")?'
)

ATTACK_SIGNATURES = [
    ("SQL_Injection", re.compile(r"(?:union\s+select|select\s+.*from|\b(?:or|and)\b\s+1=1|--|\bwaitfor\s+delay\b)", re.IGNORECASE)),
    ("Path_Traversal", re.compile(r"(?:\.\./|\.\.\\|/etc/passwd|windows/win\.ini)", re.IGNORECASE)),
    ("Command_Injection", re.compile(r"(?:;\s*(?:id|whoami|cat\s+/etc/passwd|powershell|curl|wget)|\$\(.*\)|`.*`)", re.IGNORECASE)),
    ("Log4j_Exploit", re.compile(r"\$\{jndi:(?:ldap|rmi|dns):", re.IGNORECASE)),
    ("Webshell_Access", re.compile(r"(?:c99\.php|r57\.php|cmd\.php|shell\.php|\.php\?cmd=|\.jsp\?cmd=)", re.IGNORECASE)),
]

class WebLogParser:
    """Parser for NCSA Common and Combined web access logs."""

    def parse_file(self, file_path: Path | str, case_id: str, evidence_id: str) -> List[TimelineEventRecord]:
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"Web log not found: {path}")

        events: List[TimelineEventRecord] = []
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            for idx, line in enumerate(f):
                if idx > 10_000:
                    break
                line = line.strip()
                if not line:
                    continue

                m = COMBINED_REGEX.match(line)
                if not m:
                    continue

                ip, user, ts_str, method, uri, proto, status, size, referer, ua = m.groups()
                # Parse timestamp: 12/Oct/2026:14:22:01 +0000
                iso_ts = self._parse_log_timestamp(ts_str)

                # Check for attack patterns
                attack_detected = None
                for name, pat in ATTACK_SIGNATURES:
                    if pat.search(uri) or (ua and pat.search(ua)):
                        attack_detected = name
                        break

                event_type = f"Web_{attack_detected}" if attack_detected else "Web_Request"
                summary = f"[{status}] {method} {uri}"
                if attack_detected:
                    summary = f"ATTACK ({attack_detected}): {summary}"

                events.append(TimelineEventRecord(
                    event_id=f"EVT-{uuid.uuid4().hex[:12]}",
                    case_id=case_id,
                    evidence_id=evidence_id,
                    timestamp=iso_ts,
                    timestamp_desc="RequestTime",
                    source_type="WEBLOG",
                    event_type=event_type,
                    summary=summary,
                    actor=ip,
                    target=uri,
                    raw_record_json={"status": int(status), "method": method, "uri": uri, "user_agent": ua or ""},
                    normalized_json={"status": int(status), "attack": attack_detected},
                ))

        return events

    def _parse_log_timestamp(self, ts_str: str) -> str:
        try:
            # Strip timezone if present for parse
            parts = ts_str.split()
            dt = datetime.strptime(parts[0], "%d/%b/%Y:%H:%M:%S")
            dt = dt.replace(tzinfo=timezone.utc)
            return dt.isoformat()
        except Exception:
            return datetime.now(timezone.utc).isoformat()
