"""Disk image and filesystem forensic inspector."""
from pathlib import Path
from typing import Any, Dict, List
import uuid

from bharydangerous.adapters.sleuthkit import SleuthKitAdapter
from bharydangerous.core.models import FindingRecord

class DiskInspector:
    """Forensic disk image inspector using Sleuth Kit with native fallback."""

    def __init__(self):
        self.tsk_adapter = SleuthKitAdapter()

    def inspect_disk(self, image_path: Path | str, evidence_id: str) -> Dict[str, Any]:
        path = Path(image_path)
        if not path.is_file():
            raise FileNotFoundError(f"Disk image not found: {path}")

        part_info = self.tsk_adapter.inspect_partitions(path)
        file_list_info = self.tsk_adapter.list_files(path)

        findings: List[FindingRecord] = []

        # Check for suspicious partitions (e.g. non-standard, hidden, or GPT protective)
        partitions = part_info.get("partitions", [])
        for p in partitions:
            desc = p.get("description", "")
            if "hidden" in desc.lower() or "protective" in desc.lower():
                findings.append(FindingRecord(
                    finding_id=f"FND-{uuid.uuid4().hex[:8].upper()}",
                    evidence_id=evidence_id,
                    artifact_id=None,
                    title=f"Suspicious / Special Partition: {p.get('slot')} ({desc})",
                    category="ANOMALY",
                    severity="LOW",
                    confidence="CONFIRMED_FACT",
                    facts_json=p,
                    analyst_notes="Special partition structure identified on disk image.",
                    source_artifact=str(path.name),
                ))

        return {
            "image_name": path.name,
            "image_size_bytes": path.stat().st_size,
            "partition_info": part_info,
            "filesystem_files": file_list_info,
            "findings": findings,
        }
