"""Bomb-protected archive inspector for forensic triage."""
import os
import tarfile
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional
from bharydangerous.core.constants import (
    MAX_ARCHIVE_BYTES,
    MAX_ARCHIVE_ENTRIES,
    MAX_DECOMPRESSION_RATIO,
)
from bharydangerous.core.exceptions import DecompressionBombError, PathTraversalSecurityError

class ArchiveInspector:
    """Safe inspection of ZIP and TAR archives without extracting to disk."""

    def inspect_archive(self, archive_path: Path | str) -> Dict[str, Any]:
        path = Path(archive_path)
        if not path.is_file():
            raise FileNotFoundError(f"Archive not found: {path}")

        compressed_size = path.stat().st_size
        if compressed_size == 0:
            return {"valid": False, "error": "Archive file is empty (0 bytes)", "entries": []}

        if zipfile.is_zipfile(path):
            return self._inspect_zip(path, compressed_size)
        elif tarfile.is_tarfile(path):
            return self._inspect_tar(path, compressed_size)
        else:
            return {
                "valid": False,
                "error": "Unsupported archive format. Only standard ZIP and TAR (.tar, .tar.gz, .tgz) are supported.",
                "entries": [],
            }

    def _inspect_zip(self, path: Path, compressed_size: int) -> Dict[str, Any]:
        entries: List[Dict[str, Any]] = []
        total_uncompressed = 0
        warnings: List[str] = []
        has_path_traversal = False

        try:
            with zipfile.ZipFile(path, "r") as zf:
                infolist = zf.infolist()
                if len(infolist) > MAX_ARCHIVE_ENTRIES:
                    raise DecompressionBombError(
                        f"Archive entry count ({len(infolist)}) exceeds maximum safety quota ({MAX_ARCHIVE_ENTRIES})."
                    )

                for info in infolist:
                    # Path traversal detection
                    if ".." in info.filename or info.filename.startswith("/") or info.filename.startswith("\\"):
                        has_path_traversal = True
                        warnings.append(f"Suspicious path traversal in entry: {info.filename}")

                    total_uncompressed += info.file_size
                    ratio = (info.file_size / max(info.compress_size, 1)) if info.compress_size > 0 else 1.0

                    if ratio > MAX_DECOMPRESSION_RATIO and info.file_size > 10 * 1024 * 1024:
                        warnings.append(
                            f"Suspicious compression ratio {ratio:.1f}:1 for '{info.filename}' ({info.file_size} bytes)"
                        )

                    entries.append({
                        "filename": info.filename,
                        "file_size": info.file_size,
                        "compress_size": info.compress_size,
                        "is_dir": info.is_dir(),
                        "ratio": round(ratio, 2),
                        "date_time": f"{info.date_time[0]:04d}-{info.date_time[1]:02d}-{info.date_time[2]:02d} {info.date_time[3]:02d}:{info.date_time[4]:02d}:{info.date_time[5]:02d}",
                    })

                total_ratio = total_uncompressed / max(compressed_size, 1)
                is_bomb = total_ratio > MAX_DECOMPRESSION_RATIO or total_uncompressed > MAX_ARCHIVE_BYTES

                if is_bomb:
                    warnings.append(
                        f"CRITICAL: Potential zip bomb detected! Expansion ratio: {total_ratio:.1f}:1, Total size: {total_uncompressed} bytes"
                    )

                return {
                    "valid": True,
                    "format": "ZIP",
                    "entry_count": len(entries),
                    "compressed_size_bytes": compressed_size,
                    "uncompressed_size_bytes": total_uncompressed,
                    "overall_ratio": round(total_ratio, 2),
                    "is_bomb_suspect": is_bomb,
                    "has_path_traversal": has_path_traversal,
                    "warnings": warnings,
                    "entries": entries[:500],  # Return up to 500 entries in summary
                }
        except DecompressionBombError:
            raise
        except Exception as exc:
            return {"valid": False, "error": f"Failed to inspect ZIP: {exc}", "entries": []}

    def _inspect_tar(self, path: Path, compressed_size: int) -> Dict[str, Any]:
        entries: List[Dict[str, Any]] = []
        total_uncompressed = 0
        warnings: List[str] = []
        has_path_traversal = False

        try:
            with tarfile.open(path, "r:*") as tf:
                count = 0
                for member in tf:
                    count += 1
                    if count > MAX_ARCHIVE_ENTRIES:
                        raise DecompressionBombError(
                            f"Archive entry count exceeded maximum safety limit ({MAX_ARCHIVE_ENTRIES})."
                        )

                    if ".." in member.name or member.name.startswith("/") or member.name.startswith("\\"):
                        has_path_traversal = True
                        warnings.append(f"Suspicious path traversal in entry: {member.name}")

                    total_uncompressed += member.size
                    entries.append({
                        "filename": member.name,
                        "file_size": member.size,
                        "is_dir": member.isdir(),
                        "is_symlink": member.issym(),
                        "linkname": member.linkname if member.issym() else "",
                        "mtime": member.mtime,
                    })

                total_ratio = total_uncompressed / max(compressed_size, 1)
                is_bomb = total_ratio > MAX_DECOMPRESSION_RATIO or total_uncompressed > MAX_ARCHIVE_BYTES

                if is_bomb:
                    warnings.append(
                        f"CRITICAL: Potential tar bomb detected! Expansion ratio: {total_ratio:.1f}:1, Total size: {total_uncompressed} bytes"
                    )

                return {
                    "valid": True,
                    "format": "TAR",
                    "entry_count": len(entries),
                    "compressed_size_bytes": compressed_size,
                    "uncompressed_size_bytes": total_uncompressed,
                    "overall_ratio": round(total_ratio, 2),
                    "is_bomb_suspect": is_bomb,
                    "has_path_traversal": has_path_traversal,
                    "warnings": warnings,
                    "entries": entries[:500],
                }
        except DecompressionBombError:
            raise
        except Exception as exc:
            return {"valid": False, "error": f"Failed to inspect TAR: {exc}", "entries": []}
