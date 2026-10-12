"""Memory dump forensic analyzer."""
import uuid
from pathlib import Path
from typing import Any, Dict, List

from bharydangerous.adapters.volatility import VolatilityAdapter
from bharydangerous.core.models import FindingRecord

class MemoryInspector:
    """Forensic memory dump inspector."""

    def __init__(self):
        self.vol_adapter = VolatilityAdapter()

    def inspect_memory(self, dump_path: Path | str, evidence_id: str) -> Dict[str, Any]:
        path = Path(dump_path)
        if not path.is_file():
            raise FileNotFoundError(f"Memory dump not found: {path}")

        findings: List[FindingRecord] = []
        vol_results = {}

        if self.vol_adapter.is_available:
            pslist_res = self.vol_adapter.run_plugin(path, "windows.pslist")
            malfind_res = self.vol_adapter.run_plugin(path, "windows.malfind")
            vol_results["pslist"] = pslist_res
            vol_results["malfind"] = malfind_res

            # Check if malfind found injected code
            if malfind_res.get("records"):
                findings.append(FindingRecord(
                    finding_id=f"FND-{uuid.uuid4().hex[:8].upper()}",
                    evidence_id=evidence_id,
                    artifact_id=None,
                    title="Injected Memory Section Detected (Volatility malfind)",
                    category="MALWARE",
                    severity="HIGH",
                    confidence="CONFIRMED_FACT",
                    facts_json={"malfind_hits": len(malfind_res["records"])},
                    analyst_notes="Volatility malfind plugin identified executable pages with RWX protection.",
                    source_artifact=str(path.name),
                ))

        # Always run native memory triage for string indicators and embedded headers
        native_triage = self.vol_adapter.native_memory_triage(path)
        if native_triage.get("pe_headers_detected", 0) > 0:
            findings.append(FindingRecord(
                finding_id=f"FND-{uuid.uuid4().hex[:8].upper()}",
                evidence_id=evidence_id,
                artifact_id=None,
                title=f"Embedded Portable Executables in Memory ({native_triage['pe_headers_detected']} PE headers)",
                category="SUSPICIOUS_EXEC",
                severity="MEDIUM",
                confidence="CONFIRMED_FACT",
                facts_json={"pe_count": native_triage["pe_headers_detected"]},
                analyst_notes="Identified raw PE headers in unallocated memory pages.",
                source_artifact=str(path.name),
            ))

        return {
            "dump_name": path.name,
            "dump_size_bytes": path.stat().st_size,
            "volatility_executed": self.vol_adapter.is_available,
            "volatility_results": vol_results,
            "native_triage": native_triage,
            "findings": findings,
        }
