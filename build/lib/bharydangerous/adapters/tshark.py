"""TShark network forensics adapter."""
from pathlib import Path
from typing import Any, Dict, List, Optional
from bharydangerous.adapters.base import is_tool_available, run_command_safely

class TSharkAdapter:
    """Adapter for Wireshark CLI (tshark)."""

    def __init__(self):
        self.is_available = is_tool_available("tshark")

    def run_statistics(self, pcap_path: Path | str) -> Dict[str, Any]:
        """Extract conversation and protocol statistics using tshark."""
        path = Path(pcap_path)
        if not path.is_file():
            raise FileNotFoundError(f"PCAP not found: {path}")

        if not self.is_available:
            return {
                "available": False,
                "message": "tshark is not installed. Using native pure-Python PCAP analyzer.",
            }

        # Run conversation stats
        conv_res = run_command_safely(["tshark", "-r", str(path), "-q", "-z", "conv,ip"])
        proto_res = run_command_safely(["tshark", "-r", str(path), "-q", "-z", "io,phs"])

        return {
            "available": True,
            "conversations": conv_res.stdout if conv_res.success else "",
            "protocol_hierarchy": proto_res.stdout if proto_res.success else "",
        }

    def extract_http_requests(self, pcap_path: Path | str) -> List[Dict[str, str]]:
        """Extract HTTP Host, URI, and User-Agent fields using tshark."""
        path = Path(pcap_path)
        if not self.is_available or not path.is_file():
            return []

        cmd = [
            "tshark", "-r", str(path),
            "-Y", "http.request",
            "-T", "fields",
            "-e", "frame.time",
            "-e", "ip.src",
            "-e", "http.host",
            "-e", "http.request.method",
            "-e", "http.request.uri",
            "-e", "http.user_agent",
        ]
        res = run_command_safely(cmd)
        results = []
        if res.success:
            for line in res.stdout.splitlines():
                parts = line.split("\t")
                if len(parts) >= 5:
                    results.append({
                        "time": parts[0],
                        "src_ip": parts[1],
                        "host": parts[2],
                        "method": parts[3],
                        "uri": parts[4],
                        "user_agent": parts[5] if len(parts) > 5 else "",
                    })
        return results
