"""Cryptographic hashing engine for forensic evidence."""
import hashlib
from pathlib import Path
from typing import Dict, Tuple

CHUNK_SIZE = 1024 * 1024  # 1 MB chunk for streaming hashing

def compute_hashes(file_path: Path | str) -> Tuple[str, str]:
    """
    Compute SHA-256 and MD5 hashes using chunked streaming.
    Returns (sha256_hex, md5_hex).
    Never loads entire file into memory.
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    sha256 = hashlib.sha256()
    md5 = hashlib.md5()

    with path.open("rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            sha256.update(chunk)
            md5.update(chunk)

    return sha256.hexdigest(), md5.hexdigest()

def compute_sha256_bytes(data: bytes) -> str:
    """Compute SHA-256 hex digest of raw bytes."""
    return hashlib.sha256(data).hexdigest()

def verify_file_hashes(file_path: Path | str, expected_sha256: str, expected_md5: str | None = None) -> Dict[str, bool]:
    """
    Verify whether file matches expected hashes.
    Returns a dict with 'sha256_match' and 'md5_match' (if expected_md5 provided).
    """
    actual_sha256, actual_md5 = compute_hashes(file_path)
    results = {
        "sha256_match": actual_sha256.lower() == expected_sha256.lower(),
        "actual_sha256": actual_sha256,
        "expected_sha256": expected_sha256,
        "actual_md5": actual_md5,
    }
    if expected_md5:
        results["md5_match"] = actual_md5.lower() == expected_md5.lower()
        results["expected_md5"] = expected_md5
    return results

def set_file_readonly(file_path: Path | str) -> bool:
    """Set file to read-only permissions to prevent accidental modification."""
    import os
    import stat
    path = Path(file_path)
    if not path.is_file():
        return False
    try:
        os.chmod(path, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)
        return True
    except Exception:
        return False

def is_file_readonly(file_path: Path | str) -> bool:
    """Check if file has read-only permissions."""
    import os
    import stat
    path = Path(file_path)
    if not path.is_file():
        return False
    mode = os.stat(path).st_mode
    return not bool(mode & stat.S_IWUSR)

