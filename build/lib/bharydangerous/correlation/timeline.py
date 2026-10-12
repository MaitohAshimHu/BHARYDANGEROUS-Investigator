"""Timeline aggregator and query engine."""
from typing import Any, Dict, List, Optional
from bharydangerous.core.models import TimelineEventRecord
from bharydangerous.db.repositories import TimelineRepository

class TimelineEngine:
    """Timeline manager for querying and synthesizing events."""

    def __init__(self, timeline_repo: TimelineRepository):
        self.repo = timeline_repo

    def query(
        self,
        case_id: str,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        source_type: Optional[str] = None,
        limit: int = 1000,
    ) -> List[TimelineEventRecord]:
        """Fetch chronologically sorted timeline records with optional filters."""
        return self.repo.list_by_case(
            case_id=case_id,
            start_time=start_time,
            end_time=end_time,
            source_type=source_type,
            limit=limit,
        )

    def get_summary_stats(self, case_id: str) -> Dict[str, Any]:
        """Compute distribution of event sources and total counts."""
        events = self.repo.list_by_case(case_id, limit=10_000)
        source_counts: Dict[str, int] = {}
        for ev in events:
            source_counts[ev.source_type] = source_counts.get(ev.source_type, 0) + 1

        first_seen = events[0].timestamp if events else None
        last_seen = events[-1].timestamp if events else None

        return {
            "total_events": len(events),
            "sources": source_counts,
            "first_event_utc": first_seen,
            "last_event_utc": last_seen,
        }
