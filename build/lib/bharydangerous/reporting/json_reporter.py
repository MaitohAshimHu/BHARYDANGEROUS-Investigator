"""Machine-readable JSON forensic reporter."""
import json
from pathlib import Path
from bharydangerous.core.models import ReportModel
from bharydangerous.reporting.base import BaseReporter

class JsonReporter(BaseReporter):
    """Outputs standardized JSON report."""

    def generate(self, report_data: ReportModel, output_path: Path | str) -> Path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", encoding="utf-8") as f:
            f.write(report_data.model_dump_json(indent=2))
        return out
