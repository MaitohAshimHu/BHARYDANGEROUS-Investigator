"""File identification, header inspection, and entropy calculation."""
import math
import struct
from pathlib import Path
from typing import Any, Dict, List, Optional
from bharydangerous.core.hashing import compute_hashes

def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy (0.0 to 8.0) of a byte sequence."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    byte_counts = [0] * 256
    for b in data:
        byte_counts[b] += 1
    for count in byte_counts:
        if count > 0:
            p_x = float(count) / length
            entropy -= p_x * math.log2(p_x)
    return round(entropy, 4)

Tuple_Type = tuple[str, str]

def detect_mime_and_type(header_bytes: bytes) -> Tuple_Type:
    """Identify MIME and detailed format from magic bytes."""
    if header_bytes.startswith(b"\x7fELF"):
        return "application/x-executable", "ELF (Linux Executable)"
    if header_bytes.startswith(b"MZ"):
        return "application/x-dosexec", "PE/COFF (Windows Executable / DLL)"
    if header_bytes.startswith(b"\xfe\xed\xfa\xce") or header_bytes.startswith(b"\xfe\xed\xfa\xcf") or header_bytes.startswith(b"\xcf\xfa\xed\xfe"):
        return "application/x-mach-binary", "Mach-O (macOS Executable)"
    if header_bytes.startswith(b"PK\x03\x04") or header_bytes.startswith(b"PK\x05\x06"):
        return "application/zip", "ZIP Archive"
    if header_bytes.startswith(b"\x1f\x8b\x08"):
        return "application/gzip", "GZIP Compressed Archive"
    if header_bytes.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "application/x-7z-compressed", "7-Zip Archive"
    if header_bytes.startswith(b"Rar!\x1a\x07"):
        return "application/x-rar-compressed", "RAR Archive"
    if header_bytes.startswith(b"%PDF"):
        return "application/pdf", "PDF Document"
    if header_bytes.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "application/x-ole-storage", "OLE Compound File (Legacy Office Document)"
    if header_bytes.startswith(b"{\\rtf"):
        return "application/rtf", "Rich Text Format (RTF)"
    if header_bytes.startswith(b"SQLite format 3\x00"):
        return "application/vnd.sqlite3", "SQLite Database"
    if header_bytes.startswith(b"\xd4\xc3\xb2\xa1") or header_bytes.startswith(b"\xa1\xb2\xc3\xd4"):
        return "application/vnd.tcpdump.pcap", "PCAP Network Capture"
    if header_bytes.startswith(b"\x0a\x0d\x0d\x0a"):
        return "application/vnd.tcpdump.pcapng", "PCAPNG Next-Generation Capture"
    if header_bytes.startswith(b"ElfFile\x00"):
        return "application/x-evtx", "Windows Event Log (EVTX)"

    # Text / Script detection
    try:
        sample = header_bytes[:512].decode("utf-8")
        if sample.startswith("<?xml"):
            return "application/xml", "XML Document"
        if sample.startswith("<!DOCTYPE html") or "<html" in sample.lower():
            return "text/html", "HTML Document"
        if sample.startswith("#!/bin/bash") or sample.startswith("#!/bin/sh"):
            return "text/x-shellscript", "Shell Script"
        if sample.startswith("#!/usr/bin/env python") or "import " in sample:
            return "text/x-python", "Python Script"
        return "text/plain", "Plain Text / ASCII Log"
    except UnicodeDecodeError:
        return "application/octet-stream", "Generic Binary Data"

def inspect_pe_headers(data: bytes) -> Dict[str, Any]:
    """Basic structural inspection of PE header without third-party dependencies."""
    if not data.startswith(b"MZ") or len(data) < 64:
        return {}
    try:
        e_lfanew = struct.unpack_from("<I", data, 60)[0]
        if e_lfanew + 24 > len(data):
            return {}
        pe_sig = data[e_lfanew : e_lfanew + 4]
        if pe_sig != b"PE\x00\x00":
            return {}
        machine, num_sections, timestamp, _, _, size_opt_header, characteristics = struct.unpack_from(
            "<HHIIIHH", data, e_lfanew + 4
        )
        return {
            "is_pe": True,
            "machine_hex": f"0x{machine:04X}",
            "number_of_sections": num_sections,
            "compile_timestamp": timestamp,
            "characteristics_hex": f"0x{characteristics:04X}",
        }
    except Exception:
        return {}

def triage_file(file_path: Path | str) -> Dict[str, Any]:
    """
    Perform complete triage on a single file:
    - Calculates SHA-256 and MD5 hashes
    - Extracts file size and stat timestamps
    - Reads magic bytes and determines MIME / file format
    - Computes Shannon entropy
    - Inspects binary headers if applicable
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"File not found for triage: {path}")

    stat = path.stat()
    sha256, md5 = compute_hashes(path)

    with path.open("rb") as f:
        header_bytes = f.read(4096)
        f.seek(0)
        # Read up to 1 MB for entropy calculation
        sample_for_entropy = f.read(1024 * 1024)

    mime_type, file_type = detect_mime_and_type(header_bytes)
    entropy = calculate_entropy(sample_for_entropy)

    pe_info = {}
    if file_type.startswith("PE/COFF"):
        pe_info = inspect_pe_headers(header_bytes)

    is_high_entropy = entropy > 7.2
    is_executable = any(kw in file_type for kw in ["PE/COFF", "ELF", "Mach-O", "Shell Script"])

    return {
        "file_name": path.name,
        "file_path": str(path.resolve()),
        "file_size_bytes": stat.st_size,
        "sha256": sha256,
        "md5": md5,
        "mime_type": mime_type,
        "file_type": file_type,
        "entropy": entropy,
        "is_high_entropy": is_high_entropy,
        "is_executable": is_executable,
        "pe_info": pe_info,
        "timestamps": {
            "mtime": stat.st_mtime,
            "atime": stat.st_atime,
            "ctime": stat.st_ctime,
        },
    }
