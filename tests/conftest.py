"""Pytest configuration and synthetic forensic evidence fixtures."""
import base64
import os
import random
import struct
import tempfile
import zipfile
from pathlib import Path
import pytest

from bharydangerous.core.constants import DEFAULT_DB_FILENAME
from bharydangerous.db.migrations import initialize_database
from bharydangerous.db.repositories import CaseRepository, EvidenceRepository

@pytest.fixture
def temp_workspace(tmp_path: Path):
    """Provide clean temporary workspace directory with initialized database."""
    db_path = tmp_path / DEFAULT_DB_FILENAME
    initialize_database(db_path)
    return tmp_path

@pytest.fixture
def synthetic_windows_xml(tmp_path: Path) -> Path:
    """Generate synthetic Windows Event Log XML export."""
    p = tmp_path / "windows_security.xml"
    content = """<Events>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4625</EventID><TimeCreated SystemTime="2026-10-12T14:00:01.000Z"/><Computer>FINANCE-SRV01</Computer></System>
    <EventData><Data Name="TargetUserName">Administrator</Data><Data Name="WorkstationName">WORKSTATION-X</Data></EventData>
  </Event>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4625</EventID><TimeCreated SystemTime="2026-10-12T14:00:05.000Z"/><Computer>FINANCE-SRV01</Computer></System>
    <EventData><Data Name="TargetUserName">Administrator</Data><Data Name="WorkstationName">WORKSTATION-X</Data></EventData>
  </Event>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4625</EventID><TimeCreated SystemTime="2026-10-12T14:00:10.000Z"/><Computer>FINANCE-SRV01</Computer></System>
    <EventData><Data Name="TargetUserName">Administrator</Data><Data Name="WorkstationName">WORKSTATION-X</Data></EventData>
  </Event>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4624</EventID><TimeCreated SystemTime="2026-10-12T14:01:00.000Z"/><Computer>FINANCE-SRV01</Computer></System>
    <EventData><Data Name="TargetUserName">Administrator</Data><Data Name="WorkstationName">WORKSTATION-X</Data></EventData>
  </Event>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4688</EventID><TimeCreated SystemTime="2026-10-12T14:01:15.000Z"/><Computer>FINANCE-SRV01</Computer></System>
    <EventData><Data Name="SubjectUserName">Administrator</Data><Data Name="NewProcessName">C:\\Windows\\System32\\cmd.exe</Data></EventData>
  </Event>
</Events>"""
    p.write_text(content, encoding="utf-8")
    return p

@pytest.fixture
def synthetic_auth_log(tmp_path: Path) -> Path:
    """Generate synthetic Linux authentication log."""
    p = tmp_path / "auth.log"
    content = """Oct 12 14:10:01 web-server sshd[1023]: Failed password for invalid user root from 198.51.100.22 port 49201 ssh2
Oct 12 14:10:05 web-server sshd[1024]: Failed password for invalid user root from 198.51.100.22 port 49202 ssh2
Oct 12 14:10:10 web-server sshd[1025]: Failed password for invalid user root from 198.51.100.22 port 49203 ssh2
Oct 12 14:10:25 web-server sshd[1026]: Accepted password for deploy from 198.51.100.22 port 49204 ssh2
Oct 12 14:11:00 web-server sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash
"""
    p.write_text(content, encoding="utf-8")
    return p

@pytest.fixture
def synthetic_web_log(tmp_path: Path) -> Path:
    """Generate synthetic web access log with SQL injection and command injection."""
    p = tmp_path / "access.log"
    content = """192.168.1.50 - - [12/Oct/2026:14:15:00 +0000] "GET /index.php HTTP/1.1" 200 4520 "-" "Mozilla/5.0"
192.168.1.50 - - [12/Oct/2026:14:15:10 +0000] "GET /products.php?id=1%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1" 200 8120 "-" "Mozilla/5.0"
192.168.1.50 - - [12/Oct/2026:14:15:30 +0000] "GET /uploads/cmd.php?cmd=whoami HTTP/1.1" 200 120 "-" "curl/7.68.0"
"""
    p.write_text(content, encoding="utf-8")
    return p

@pytest.fixture
def synthetic_pcap(tmp_path: Path) -> Path:
    """Generate synthetic valid PCAP with DNS and HTTP basic auth."""
    p = tmp_path / "sample_traffic.pcap"
    with p.open("wb") as f:
        # PCAP Global Header: Magic 0xa1b2c3d4, v2.4, standard network 1 (Ethernet)
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))

        # Packet 1: UDP DNS Query (192.168.1.100 -> 8.8.8.8:53)
        eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
        src_ip = bytes([192, 168, 1, 100])
        dst_ip = bytes([8, 8, 8, 8])
        dns_hdr = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        qname = b"\x0cmalicious-c2\x07example\x03com\x00\x00\x01\x00\x01"
        dns_payload = dns_hdr + qname
        udp_hdr = struct.pack("!HHHH", 54321, 53, 8 + len(dns_payload), 0)
        ip_total = 20 + 8 + len(dns_payload)
        ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, ip_total, 1, 0, 64, 17, 0, src_ip, dst_ip)
        pkt1 = eth + ip_hdr + udp_hdr + dns_payload
        f.write(struct.pack("<IIII", 1791813600, 100, len(pkt1), len(pkt1)))
        f.write(pkt1)

        # Packet 2: TCP HTTP Request with Basic Auth
        http_text = b"GET /admin/panel HTTP/1.1\r\nHost: finance-srv01.internal\r\nAuthorization: Basic YWRtaW46U3VwZXJTZWNyZXQxMjM=\r\n\r\n"
        tcp_hdr = struct.pack("!HHIIBBHHH", 49152, 80, 100, 100, 0x50, 0x18, 8192, 0, 0)
        ip_total_2 = 20 + 20 + len(http_text)
        ip_hdr_2 = struct.pack("!BBHHHBBH4s4s", 0x45, 0, ip_total_2, 2, 0, 64, 6, 0, src_ip, dst_ip)
        pkt2 = eth + ip_hdr_2 + tcp_hdr + http_text
        f.write(struct.pack("<IIII", 1791813610, 200, len(pkt2), len(pkt2)))
        f.write(pkt2)
    return p

@pytest.fixture
def synthetic_bomb_zip(tmp_path: Path) -> Path:
    """Generate synthetic high-expansion archive (bomb suspect)."""
    p = tmp_path / "bomb_suspect.zip"
    with zipfile.ZipFile(p, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("huge_zeroes.dat", b"\x00" * (12 * 1024 * 1024))
    return p

@pytest.fixture
def synthetic_safe_zip(tmp_path: Path) -> Path:
    """Generate benign archive."""
    p = tmp_path / "safe.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("notes.txt", "Forensic analysis notes.")
        zf.writestr("sub/config.ini", "[Settings]\nmode=test")
    return p

@pytest.fixture
def synthetic_mbr_disk(tmp_path: Path) -> Path:
    """Generate 512-byte raw disk sector with MBR partition table."""
    p = tmp_path / "disk_mbr.raw"
    mbr_bytes = bytearray(512)
    struct.pack_into("<B3sB3sII", mbr_bytes, 446, 0x80, b"\x00\x00\x00", 0x83, b"\x00\x00\x00", 2048, 100000)
    mbr_bytes[510] = 0x55
    mbr_bytes[511] = 0xAA
    p.write_bytes(bytes(mbr_bytes))
    return p

@pytest.fixture
def synthetic_yara_sample(tmp_path: Path) -> Path:
    """Generate synthetic sample with matching rule string without triggering AMSI."""
    p = tmp_path / "suspicious_test.txt"
    p.write_text("// Test payload: BHARYDANGEROUS_FORENSIC_TEST_SIGNATURE\n", encoding="utf-8")
    return p
