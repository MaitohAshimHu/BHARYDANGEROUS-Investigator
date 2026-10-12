"""Cross-artifact incident correlation engine."""
import uuid
from typing import Any, Dict, List
from bharydangerous.core.models import CorrelationRecord, TimelineEventRecord
from bharydangerous.db.repositories import CorrelationRepository, TimelineRepository

class CorrelationEngine:
    """Heuristic engine that correlates events across disparate forensic artifacts."""

    def __init__(self, timeline_repo: TimelineRepository, correlation_repo: CorrelationRepository):
        self.timeline_repo = timeline_repo
        self.correlation_repo = correlation_repo

    def run_correlations(self, case_id: str) -> List[CorrelationRecord]:
        """Execute all correlation rules against the case timeline."""
        events = self.timeline_repo.list_by_case(case_id, limit=10_000)
        correlations: List[CorrelationRecord] = []

        correlations.extend(self._rule_bruteforce_logon(case_id, events))
        correlations.extend(self._rule_webshell_exploitation(case_id, events))
        correlations.extend(self._rule_privileged_execution(case_id, events))
        correlations.extend(self._rule_dns_beaconing(case_id, events))

        # Persist new correlations
        for c in correlations:
            self.correlation_repo.add(c)

        return correlations

    def _rule_bruteforce_logon(self, case_id: str, events: List[TimelineEventRecord]) -> List[CorrelationRecord]:
        """Detect multiple failed logins followed by a successful login."""
        results = []
        failed_events_by_actor: Dict[str, List[TimelineEventRecord]] = {}

        for ev in events:
            if "Failed" in ev.event_type or "4625" in ev.summary:
                actor = ev.actor or "Unknown"
                failed_events_by_actor.setdefault(actor, []).append(ev)
            elif "Success" in ev.event_type or "4624" in ev.summary:
                actor = ev.actor or "Unknown"
                if actor in failed_events_by_actor and len(failed_events_by_actor[actor]) >= 3:
                    failed_list = failed_events_by_actor[actor]
                    event_ids = [e.event_id for e in failed_list] + [ev.event_id]
                    results.append(CorrelationRecord(
                        correlation_id=f"CORR-{uuid.uuid4().hex[:8].upper()}",
                        case_id=case_id,
                        rule_name="CORR-BRUTEFORCE-LOGON",
                        score=0.90,
                        event_ids=event_ids,
                        summary=f"Brute-force attack detected: {len(failed_list)} failed logons followed by successful logon by actor '{actor}'",
                        details_json={
                            "actor": actor,
                            "failed_attempts": len(failed_list),
                            "success_event_id": ev.event_id,
                        },
                    ))
                    # Reset
                    del failed_events_by_actor[actor]

        return results

    def _rule_webshell_exploitation(self, case_id: str, events: List[TimelineEventRecord]) -> List[CorrelationRecord]:
        """Detect web attack/webshell access followed by process or command execution."""
        results = []
        recent_web_attacks: List[TimelineEventRecord] = []

        for ev in events:
            if ev.source_type == "WEBLOG" and "ATTACK" in ev.summary:
                recent_web_attacks.append(ev)
            elif ev.event_type in ("Process_Created", "Sudo_Execution", "PowerShell_ScriptBlock"):
                if recent_web_attacks:
                    # Correlate
                    attack_ev = recent_web_attacks[-1]
                    results.append(CorrelationRecord(
                        correlation_id=f"CORR-{uuid.uuid4().hex[:8].upper()}",
                        case_id=case_id,
                        rule_name="CORR-WEBSHELL-EXPLOITATION",
                        score=0.95,
                        event_ids=[attack_ev.event_id, ev.event_id],
                        summary=f"Web exploitation attempt followed by command execution: '{attack_ev.summary}' -> '{ev.summary}'",
                        details_json={
                            "web_attack": attack_ev.summary,
                            "execution": ev.summary,
                        },
                    ))
                    recent_web_attacks.clear()

        return results

    def _rule_privileged_execution(self, case_id: str, events: List[TimelineEventRecord]) -> List[CorrelationRecord]:
        """Detect rapid privilege escalations or service installations."""
        results = []
        for ev in events:
            if ev.event_type in ("Service_Installed", "User_Created"):
                results.append(CorrelationRecord(
                    correlation_id=f"CORR-{uuid.uuid4().hex[:8].upper()}",
                    case_id=case_id,
                    rule_name="CORR-PERSISTENCE-ESTABLISHED",
                    score=0.85,
                    event_ids=[ev.event_id],
                    summary=f"Persistence mechanism identified: {ev.summary}",
                    details_json={"event_id": ev.event_id, "summary": ev.summary},
                ))
        return results

    def _rule_dns_beaconing(self, case_id: str, events: List[TimelineEventRecord]) -> List[CorrelationRecord]:
        """Detect repeated DNS queries to the same domain (beaconing indicator)."""
        results = []
        domain_counts: Dict[str, List[str]] = {}

        for ev in events:
            if ev.event_type == "DNS_Query" and ev.target:
                domain_counts.setdefault(ev.target, []).append(ev.event_id)

        for domain, e_ids in domain_counts.items():
            if len(e_ids) >= 5:
                results.append(CorrelationRecord(
                    correlation_id=f"CORR-{uuid.uuid4().hex[:8].upper()}",
                    case_id=case_id,
                    rule_name="CORR-DNS-REPETITIVE-QUERY",
                    score=0.70,
                    event_ids=e_ids[:10],
                    summary=f"Repetitive DNS queries ({len(e_ids)} requests) for domain '{domain}' (Potential C2 beaconing)",
                    details_json={"domain": domain, "query_count": len(e_ids)},
                ))

        return results
