"""The Sleuth Kit (TSK) forensic adapter with pure-Python MBR/GPT fallback."""
import struct
from pathlib import Path
from typing import Any, Dict, List, Optional

from bharydangerous.adapters.base import is_tool_available, run_command_safely

class SleuthKitAdapter:
    """Adapter for The Sleuth Kit utilities with native fallback."""

    def __init__(self):
        self.has_mmls = is_tool_available("mmls")
        self.has_fls = is_tool_available("fls")
        self.has_fsstat = is_tool_available("fsstat")

    def inspect_partitions(self, image_path: Path | str) -> Dict[str, Any]:
        """
        Inspect partition layout of a raw disk image.
        Uses mmls if available; otherwise parses MBR/GPT natively.
        """
        path = Path(image_path)
        if not path.is_file():
            raise FileNotFoundError(f"Disk image not found: {path}")

        if self.has_mmls:
            res = run_command_safely(["mmls", str(path)])
            if res.success:
                return {
                    "method": "sleuthkit_mmls",
                    "raw_output": res.stdout,
                    "partitions": self._parse_mmls_output(res.stdout),
                }

        # Pure-Python fallback: parse Master Boot Record (MBR) and GPT header
        return self._native_partition_parse(path)

    def list_files(self, image_path: Path | str, offset_sectors: Optional[int] = None) -> Dict[str, Any]:
        """
        List directory contents from a filesystem image or partition offset.
        Uses fls if available.
        """
        path = Path(image_path)
        if self.has_fls:
            cmd = ["fls", "-r", "-p"]
            if offset_sectors is not None:
                cmd.extend(["-o", str(offset_sectors)])
            cmd.append(str(path))
            res = run_command_safely(cmd)
            if res.success:
                return {
                    "method": "sleuthkit_fls",
                    "file_entries": self._parse_fls_output(res.stdout),
                }

        return {
            "method": "native_fallback",
            "message": "TSK 'fls' utility not installed. Install sleuthkit for deep filesystem tree carving.",
            "file_entries": [],
        }

    def _parse_mmls_output(self, output: str) -> List[Dict[str, Any]]:
        partitions = []
        for line in output.splitlines():
            parts = line.strip().split()
            if len(parts) >= 6 and parts[0].isdigit():
                partitions.append({
                    "slot": parts[0],
                    "start_sector": parts[2],
                    "end_sector": parts[3],
                    "length_sectors": parts[4],
                    "description": " ".join(parts[5:]),
                })
        return partitions

    def _parse_fls_output(self, output: str) -> List[Dict[str, Any]]:
        entries = []
        for line in output.splitlines()[:1000]:  # Cap at 1000 entries
            parts = line.strip().split(maxsplit=2)
            if len(parts) >= 2:
                entries.append({
                    "type": parts[0],
                    "inode": parts[1] if len(parts) > 1 else "",
                    "name": parts[2] if len(parts) > 2 else "",
                })
        return entries

    def _native_partition_parse(self, path: Path) -> Dict[str, Any]:
        """Native parser for MBR partition table (Sector 0) and GPT signature check."""
        with path.open("rb") as f:
            mbr_data = f.read(512)

        if len(mbr_data) < 512:
            return {
                "method": "native_mbr",
                "valid": False,
                "error": "Image is smaller than 512 bytes (one sector)",
                "partitions": [],
            }

        # Check MBR boot signature 0x55AA at offset 510
        magic = struct.unpack_from("<H", mbr_data, 510)[0]
        has_mbr_magic = (magic == 0xAA55)

        partitions = []
        # Check standard 4 MBR partition table entries at offset 446
        if has_mbr_magic:
            for i in range(4):
                offset = 446 + (i * 16)
                entry = mbr_data[offset : offset + 16]
                bootable, start_chs, ptype, end_chs, lba_start, num_sectors = struct.unpack("<B3sB3sII", entry)
                if ptype != 0:
                    partitions.append({
                        "slot": f"MBR-{i+1}",
                        "bootable": bool(bootable & 0x80),
                        "partition_type_hex": f"0x{ptype:02X}",
                        "start_sector": lba_start,
                        "length_sectors": num_sectors,
                        "description": self._get_mbr_type_name(ptype),
                    })

        # Check GPT Header at sector 1 (offset 512)
        with path.open("rb") as f:
            f.seek(512)
            gpt_data = f.read(512)
        is_gpt = gpt_data.startswith(b"EFI PART")

        return {
            "method": "native_mbr_gpt",
            "has_mbr_magic": has_mbr_magic,
            "is_gpt": is_gpt,
            "partitions": partitions,
        }

    def _get_mbr_type_name(self, ptype: int) -> str:
        types = {
            0x07: "NTFS / exFAT",
            0x0B: "FAT32 (CHS)",
            0x0C: "FAT32 (LBA)",
            0x83: "Linux Native (ext2/3/4)",
            0x82: "Linux Swap",
            0xEE: "GPT Protective Partition",
        }
        return types.get(ptype, f"Type 0x{ptype:02X}")
