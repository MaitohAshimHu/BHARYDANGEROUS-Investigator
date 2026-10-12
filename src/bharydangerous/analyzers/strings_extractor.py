"""Streaming string extractor with IOC classification."""
import re
from pathlib import Path
from typing import Any, Dict, List, Set
from bharydangerous.core.constants import DEFAULT_MIN_STRING_LEN, MAX_STRINGS_EXTRACTED

IP_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
URL_REGEX = re.compile(r"https?://[a-zA-Z0-9\.\-_/:\?=%&#@+~]+")
EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
GUID_REGEX = re.compile(r"\b\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?\b")
BASE64_SUSPECT = re.compile(r"\b(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b")

def extract_strings(
    file_path: Path | str,
    min_length: int = DEFAULT_MIN_STRING_LEN,
    max_strings: int = MAX_STRINGS_EXTRACTED,
) -> Dict[str, Any]:
    """
    Extract printable ASCII and UTF-16LE strings up to max_strings.
    Identifies high-value forensic IOCs.
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    ascii_chars = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ "
    ascii_set = set(ascii_chars)

    extracted: List[str] = []
    ips: Set[str] = set()
    urls: Set[str] = set()
    emails: Set[str] = set()
    guids: Set[str] = set()
    base64_blobs: Set[str] = set()

    with path.open("rb") as f:
        # Stream in 1 MB chunks
        chunk = f.read(1024 * 1024)
        current_str = bytearray()

        while chunk and len(extracted) < max_strings:
            for b in chunk:
                if b in ascii_set:
                    current_str.append(b)
                else:
                    if len(current_str) >= min_length:
                        s = current_str.decode("latin1", errors="ignore")
                        extracted.append(s)
                        _classify_string(s, ips, urls, emails, guids, base64_blobs)
                        if len(extracted) >= max_strings:
                            break
                    current_str.clear()
            chunk = f.read(1024 * 1024)

        if len(current_str) >= min_length and len(extracted) < max_strings:
            s = current_str.decode("latin1", errors="ignore")
            extracted.append(s)
            _classify_string(s, ips, urls, emails, guids, base64_blobs)

    return {
        "file_name": path.name,
        "total_extracted": len(extracted),
        "iocs": {
            "ips": sorted(list(ips))[:100],
            "urls": sorted(list(urls))[:100],
            "emails": sorted(list(emails))[:50],
            "guids": sorted(list(guids))[:50],
            "base64_blobs": sorted(list(base64_blobs))[:20],
        },
        "sample_strings": extracted[:200],
    }

def _classify_string(s: str, ips: Set[str], urls: Set[str], emails: Set[str], guids: Set[str], b64: Set[str]) -> None:
    for m in IP_REGEX.finditer(s):
        ip = m.group(0)
        octets = [int(p) for p in ip.split(".")]
        if all(0 <= o <= 255 for o in octets) and not ip.startswith("0.") and ip != "255.255.255.255":
            ips.add(ip)
    for m in URL_REGEX.finditer(s):
        urls.add(m.group(0))
    for m in EMAIL_REGEX.finditer(s):
        emails.add(m.group(0))
    for m in GUID_REGEX.finditer(s):
        guids.add(m.group(0))
    for m in BASE64_SUSPECT.finditer(s):
        b64.add(m.group(0))
