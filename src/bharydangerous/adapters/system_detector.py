"""System tool and environment detector for diagnostics."""
import importlib
import platform
import shutil
import sys
from typing import List

from bharydangerous.adapters.base import is_tool_available
from bharydangerous.core.models import DoctorCheckResult

def check_python_environment() -> List[DoctorCheckResult]:
    """Check Python runtime version and critical standard modules."""
    results = []
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    if sys.version_info >= (3, 11):
        results.append(DoctorCheckResult(
            category="Python Environment",
            name="Python Version",
            status="OK",
            details=f"Python {py_ver} on {platform.system()} {platform.machine()}",
        ))
    else:
        results.append(DoctorCheckResult(
            category="Python Environment",
            name="Python Version",
            status="WARNING",
            details=f"Python {py_ver} (Python 3.11+ recommended)",
            remediation="Upgrade Python to 3.11 or newer.",
        ))

    # Check SQLite WAL support
    try:
        import sqlite3
        results.append(DoctorCheckResult(
            category="Python Environment",
            name="SQLite Library",
            status="OK",
            details=f"sqlite3 version {sqlite3.sqlite_version}",
        ))
    except Exception as exc:
        results.append(DoctorCheckResult(
            category="Python Environment",
            name="SQLite Library",
            status="MISSING",
            details=str(exc),
            remediation="Ensure standard sqlite3 module is available.",
        ))

    # Check AI SDK
    try:
        importlib.import_module("google.genai")
        results.append(DoctorCheckResult(
            category="Python Libraries",
            name="google-genai",
            status="OK",
            details="Installed and available for Gemini API reasoning",
        ))
    except ImportError:
        results.append(DoctorCheckResult(
            category="Python Libraries",
            name="google-genai",
            status="OPTIONAL",
            details="Not installed. Deterministic forensics will function offline.",
            remediation="Run: pip install google-genai",
        ))

    return results

def check_forensic_tools() -> List[DoctorCheckResult]:
    """Inspect external forensic command-line utilities."""
    tools = [
        (
            "fls (The Sleuth Kit)",
            "fls",
            "Disk and filesystem metadata analysis",
            "Install SleuthKit: 'apt install sleuthkit' (Linux) or 'brew install sleuthkit' (macOS). Pure-Python partition fallback active.",
        ),
        (
            "fsstat (The Sleuth Kit)",
            "fsstat",
            "Filesystem superblock inspection",
            "Install SleuthKit: 'apt install sleuthkit' or 'brew install sleuthkit'. Pure-Python fallback active.",
        ),
        (
            "vol (Volatility 3)",
            "vol",
            "Advanced memory dump forensics",
            "Install Volatility 3: 'pip install volatility3'. Built-in memory string/header triage fallback active.",
        ),
        (
            "tshark (Wireshark CLI)",
            "tshark",
            "Deep packet inspection and dissections",
            "Install Wireshark/tshark: 'apt install tshark' or 'brew install wireshark'. Pure-Python PCAP stream fallback active.",
        ),
        (
            "yara (YARA Scanner CLI)",
            "yara",
            "Signature-based malware pattern matching",
            "Install YARA: 'apt install yara' or 'pip install yara-python'. Pure-Python regex IOC matcher fallback active.",
        ),
        (
            "file (libmagic CLI)",
            "file",
            "File identification via magic numbers",
            "Standard on Linux/macOS. Pure-Python binary header sniffer active.",
        ),
        (
            "strings (Binary strings)",
            "strings",
            "ASCII and Unicode string extraction",
            "Standard on Linux/macOS. Pure-Python streaming string extractor active.",
        ),
    ]

    results = []
    for display_name, binary_name, purpose, remediation in tools:
        if is_tool_available(binary_name):
            path = shutil.which(binary_name)
            results.append(DoctorCheckResult(
                category="Forensic Utilities",
                name=display_name,
                status="OK",
                details=f"Available at {path} ({purpose})",
            ))
        else:
            results.append(DoctorCheckResult(
                category="Forensic Utilities",
                name=display_name,
                status="OPTIONAL",
                details=f"Not in PATH. {purpose}",
                remediation=remediation,
            ))

    return results

def run_all_doctor_checks() -> List[DoctorCheckResult]:
    """Execute all diagnostic checks."""
    return check_python_environment() + check_forensic_tools()
