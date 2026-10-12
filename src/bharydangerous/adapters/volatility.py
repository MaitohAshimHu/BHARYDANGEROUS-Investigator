"""Volatility 3 memory forensics adapter with native triage fallback."""
import re
from pathlib import Path
from typing import Any, Dict, List

from bharydangerous.adapters.base import is_tool_available, run_command_safely

class VolatilityAdapter:
    """Adapter for Volatility 3 with fallback memory scanning."""

    def __init__(self):
        self.vol_cmd = None
        if is_tool_available("vol"):
            self.vol_cmd = "vol"
        elif is_tool_available("volatility3"):
            self.vol_cmd = "volatility3"

    @property
    def is_available(self) -> bool:
        return self.vol_cmd is not None

    def run_plugin(self, image_path: Path | str, plugin_name: str) -> Dict[str, Any]:
        """Execute a Volatility 3 plugin against a memory image."""
        path = Path(image_path)
        if not path.is_file():
            raise FileNotFoundError(f"Memory dump not found: {path}")

        if not self.vol_cmd:
            return {
                "success": False,
                "method": "volatility_uninstalled",
                "message": "Volatility 3 ('vol') is not installed in PATH. Use 'pip install volatility3'.",
                "raw_output": "",
                "records": [],
            }

        cmd = [self.vol_cmd, "-f", str(path), plugin_name]
        res = run_command_safely(cmd, timeout_seconds=120)
        return {
            "success": res.success,
            "method": f"{self.vol_cmd}_{plugin_name}",
            "raw_output": res.stdout if res.success else res.stderr,
            "records": self._parse_table_output(res.stdout),
        }

    def native_memory_triage(self, image_path: Path | str, max_bytes_scan: int = 50 * 1024 * 1024) -> Dict[str, Any]:
        """
        Native triage of memory dump without Volatility.
        Scans for PE headers, suspicious executable code regions, URLs, and IPv4 addresses.
        """
        path = Path(image_path)
        pe_headers_found = 0
        ips = set()
        urls = set()

        ip_regex = re.compile(rb"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
        url_regex = re.compile(rb"https?://[a-zA-Z0-9\.\-_/:\?=%&#]+")

        with path.open("rb") as f:
            chunk = f.read(max_bytes_scan)

            # Search for MZ headers (DOS executable signature)
            idx = 0
            while True:
                idx = chunk.find(b"MZ", idx)
                if idx == -1 or idx + 64 > len(chunk):
                    break
                # Check e_lfanew offset to PE signature
                try:
                    e_lfanew = int.from_bytes(chunk[idx + 60 : idx + 64], "little")
                    if idx + e_lfanew + 4 <= len(chunk) and chunk[idx + e_lfanew : idx + e_lfanew + 4] == b"PE\x00\x00":
                        pe_headers_found += 1
                except Exception:
                    pass
                idx += 2

            # Search for IPs
            for match in ip_regex.finditer(chunk):
                try:
                    ip_str = match.group(0).decode("ascii")
                    # Simple octet validation
                    octets = [int(p) for p in ip_str.split(".")]
                    if all(0 <= o <= 255 for o in octets) and not ip_str.startswith("0.") and not ip_str == "255.255.255.255":
                        ips.add(ip_str)
                except Exception:
                    continue

            # Search for URLs
            for match in url_regex.finditer(chunk):
                try:
                    urls.add(match.group(0).decode("ascii", errors="ignore"))
                except Exception:
                    continue

        return {
            "method": "native_memory_triage",
            "scanned_bytes": min(path.stat().st_size, max_bytes_scan),
            "pe_headers_detected": pe_headers_found,
            "ip_indicators": sorted(list(ips))[:100],
            "url_indicators": sorted(list(urls))[:100],
        }

    def _parse_table_output(self, output: str) -> List[Dict[str, str]]:
        lines = [ln.strip() for ln in output.splitlines() if ln.strip()]
        if not lines:
            return []
        # Volatility 3 output typically has headers then data lines
        records = []
        for line in lines[:200]:
            records.append({"raw_line": line})
        return records
