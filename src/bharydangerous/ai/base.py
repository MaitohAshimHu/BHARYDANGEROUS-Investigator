"""Abstract interface for AI reasoning providers."""
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from bharydangerous.core.models import FindingRecord, TimelineEventRecord

class AIProviderResponse:
    def __init__(self, text: str, model_name: str, cited_finding_ids: List[str], raw_response: Optional[Any] = None):
        self.text = text
        self.model_name = model_name
        self.cited_finding_ids = cited_finding_ids
        self.raw_response = raw_response

class BaseAIProvider(ABC):
    """Abstract base class for all AI reasoning adapters."""

    @abstractmethod
    def explain_finding(self, finding: FindingRecord, context_events: List[TimelineEventRecord]) -> AIProviderResponse:
        """Generate structured technical explanation for a specific finding."""
        pass

    @abstractmethod
    def summarize_investigation(
        self,
        case_name: str,
        findings: List[FindingRecord],
        timeline_events: List[TimelineEventRecord],
    ) -> AIProviderResponse:
        """Generate comprehensive executive and technical summary of case findings."""
        pass

    @abstractmethod
    def suggest_next_steps(self, findings: List[FindingRecord]) -> AIProviderResponse:
        """Suggest actionable forensic hypotheses and verification steps."""
        pass
