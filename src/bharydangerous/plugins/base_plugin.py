"""Base plugin interface for BHARYDANGEROUS-Investigator."""
from abc import ABC
from typing import Any, Dict, List, Optional
from bharydangerous.core.models import FindingRecord, TimelineEventRecord

class BaseForensicPlugin(ABC):
    """Base class for third-party forensic extension plugins."""

    name: str = "BasePlugin"
    version: str = "1.0.0"
    author: str = "Community"
    description: str = "Generic forensic plugin"

    def on_evidence_intake(self, evidence_metadata: Dict[str, Any]) -> None:
        """Hook called when new evidence is ingested."""
        pass

    def on_custom_triage(self, file_path: str) -> List[FindingRecord]:
        """Custom triage analyzer hook."""
        return []

    def on_timeline_generation(self, case_id: str) -> List[TimelineEventRecord]:
        """Custom timeline event generator hook."""
        return []
