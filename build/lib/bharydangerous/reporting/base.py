"""Base reporter interface."""
from abc import ABC, abstractmethod
from pathlib import Path
from bharydangerous.core.models import ReportModel

class BaseReporter(ABC):
    """Abstract base reporter."""

    @abstractmethod
    def generate(self, report_data: ReportModel, output_path: Path | str) -> Path:
        """Render and save forensic report to target path."""
        pass
