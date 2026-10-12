"""Binary PCAP network forensics analyzer with protocol dissection."""
import base64
import struct
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

from bharydangerous.core.models import TimelineEventRecord

class PcapAnalyzer:
    """Parser for standard PCAP files without external dependencies."""

    def analyze_pcap(self, pcap_path: Path | str, case_id: str, evidence_id: str) -> Dict[str, Any]:
        path = Path(pcap_path)
        if not path.is_file():
            raise FileNotFoundError(f"PCAP file not found: {path}")

        with path.open("rb") as f:
            header = f.read(24)
            if len(header) < 24:
                return {"valid": False, "error": "File too small to be a valid PCAP"}

            # PCAP Global Header magic
            magic = header[:4]
            if magic == b"\xd4\xc3\xb2\xa1":
                endian = "<"  # Little-endian
            elif magic == b"\xa1\xb2\xc3\xd4":
                endian = ">"  # Big-endian
            elif magic == b"\x0a\x0d\x0d\x0a":
                return self._analyze_pcapng_fallback(path, case_id, evidence_id)
            else:
                return {"valid": False, "error": "Not a standard PCAP file (unrecognized magic)"}

            version_major, version_minor, thiszone, sigfigs, snaplen, network = struct.unpack(
                f"{endian}HHIIII", header[4:24]
            )

            packet_count = 0
            conversations: Dict[str, int] = {}
            dns_queries: Set[str] = set()
            http_requests: List[Dict[str, str]] = []
            credentials: List[Dict[str, str]] = []
            timeline_events: List[TimelineEventRecord] = []

            # Read packet records
            while packet_count < 10_000:  # Cap at 10,000 packets for fast analysis
                pkt_hdr = f.read(16)
                if len(pkt_hdr) < 16:
                    break
                ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{endian}IIII", pkt_hdr)
                pkt_data = f.read(incl_len)
                if len(pkt_data) < incl_len:
                    break

                packet_count += 1
                try:
                    dt = datetime.fromtimestamp(ts_sec, tz=timezone.utc)
                    iso_ts = dt.isoformat()
                except Exception:
                    iso_ts = datetime.now(timezone.utc).isoformat()

                # Parse Ethernet frame (14 bytes) -> IPv4 (20 bytes)
                if len(pkt_data) >= 34:
                    eth_type = struct.unpack("!H", pkt_data[12:14])[0]
                    if eth_type == 0x0800:  # IPv4
                        ip_hdr = pkt_data[14:34]
                        proto = ip_hdr[9]
                        src_ip = ".".join(str(b) for b in ip_hdr[12:16])
                        dst_ip = ".".join(str(b) for b in ip_hdr[16:20])

                        convo_key = f"{src_ip} <-> {dst_ip}"
                        conversations[convo_key] = conversations.get(convo_key, 0) + incl_len

                        # Check TCP (proto 6) / UDP (proto 17)
                        ihl = (ip_hdr[0] & 0x0F) * 4
                        payload_offset = 14 + ihl

                        if proto == 17 and len(pkt_data) >= payload_offset + 8:  # UDP
                            src_port, dst_port, udp_len = struct.unpack("!HHH", pkt_data[payload_offset : payload_offset + 6])
                            udp_payload = pkt_data[payload_offset + 8 :]

                            # DNS Inspection (Port 53)
                            if (src_port == 53 or dst_port == 53) and len(udp_payload) >= 12:
                                qname = self._parse_dns_qname(udp_payload[12:])
                                if qname:
                                    dns_queries.add(qname)
                                    if dst_port == 53:
                                        timeline_events.append(TimelineEventRecord(
                                            event_id=f"EVT-{uuid.uuid4().hex[:12]}",
                                            case_id=case_id,
                                            evidence_id=evidence_id,
                                            timestamp=iso_ts,
                                            timestamp_desc="PacketTime",
                                            source_type="PCAP",
                                            event_type="DNS_Query",
                                            summary=f"DNS query for '{qname}' from {src_ip}",
                                            actor=src_ip,
                                            target=qname,
                                            raw_record_json={"qname": qname, "src": src_ip, "dst": dst_ip},
                                            normalized_json={"protocol": "DNS", "qname": qname},
                                        ))

                        elif proto == 6 and len(pkt_data) >= payload_offset + 20:  # TCP
                            src_port, dst_port = struct.unpack("!HH", pkt_data[payload_offset : payload_offset + 4])
                            tcp_data_offset = ((pkt_data[payload_offset + 12] >> 4) & 0x0F) * 4
                            tcp_payload = pkt_data[payload_offset + tcp_data_offset :]

                            # Check for HTTP text
                            if tcp_payload.startswith((b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ")):
                                http_str = tcp_payload[:1024].decode("utf-8", errors="ignore")
                                lines = http_str.split("\r\n")
                                req_line = lines[0] if lines else ""
                                host = ""
                                for hline in lines:
                                    if hline.lower().startswith("host:"):
                                        host = hline.split(":", 1)[1].strip()
                                    if hline.lower().startswith("authorization: basic "):
                                        b64_cred = hline.split("Basic ", 1)[1].strip()
                                        try:
                                            dec_cred = base64.b64decode(b64_cred).decode("utf-8", errors="ignore")
                                            credentials.append({
                                                "src_ip": src_ip,
                                                "target_host": host or dst_ip,
                                                "credential": dec_cred,
                                            })
                                        except Exception:
                                            pass

                                http_requests.append({
                                    "time": iso_ts,
                                    "src_ip": src_ip,
                                    "dst_ip": dst_ip,
                                    "host": host,
                                    "request": req_line,
                                })

                                timeline_events.append(TimelineEventRecord(
                                    event_id=f"EVT-{uuid.uuid4().hex[:12]}",
                                    case_id=case_id,
                                    evidence_id=evidence_id,
                                    timestamp=iso_ts,
                                    timestamp_desc="PacketTime",
                                    source_type="PCAP",
                                    event_type="HTTP_Request",
                                    summary=f"HTTP: {req_line} to {host or dst_ip}",
                                    actor=src_ip,
                                    target=host or dst_ip,
                                    raw_record_json={"request": req_line, "host": host},
                                    normalized_json={"protocol": "HTTP", "req": req_line},
                                ))

            return {
                "valid": True,
                "packet_count": packet_count,
                "conversations": [{"endpoint_pair": k, "bytes_transferred": v} for k, v in sorted(conversations.items(), key=lambda x: x[1], reverse=True)[:50]],
                "dns_queries": sorted(list(dns_queries))[:100],
                "http_requests": http_requests[:50],
                "plaintext_credentials_found": credentials,
                "timeline_events": timeline_events,
            }

    def _parse_dns_qname(self, data: bytes) -> str:
        """Parse DNS QNAME format: \x03www\x06google\x03com\x00."""
        labels = []
        idx = 0
        while idx < len(data):
            length = data[idx]
            if length == 0:
                break
            idx += 1
            if idx + length > len(data):
                break
            labels.append(data[idx : idx + length].decode("ascii", errors="ignore"))
            idx += length
        return ".".join(labels)

    def _analyze_pcapng_fallback(self, path: Path, case_id: str, evidence_id: str) -> Dict[str, Any]:
        """Basic fallback for PCAPNG format."""
        return {
            "valid": True,
            "format": "PCAPNG",
            "message": "PCAPNG Next-Generation capture detected. For deep block analysis, install tshark.",
            "packet_count": 0,
            "conversations": [],
            "dns_queries": [],
            "http_requests": [],
            "plaintext_credentials_found": [],
            "timeline_events": [],
        }
