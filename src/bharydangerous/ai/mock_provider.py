"""Deterministic offline mock AI provider for testing and validation."""
from typing import List
from bharydangerous.ai.base import BaseAIProvider, AIProviderResponse
from bharydangerous.ai.consent import extract_and_verify_cited_finding_ids
from bharydangerous.core.models import FindingRecord, TimelineEventRecord

class MockAIProvider(BaseAIProvider):
    """Deterministic offline mock AI provider."""

    def __init__(self, model_name: str = "mock-forensic-flash"):
        self.model_name = model_name

    def explain_finding(self, finding: FindingRecord, context_events: List[TimelineEventRecord]) -> AIProviderResponse:
        text = f"""### Technical Finding Analysis: [{finding.finding_id}]

**Technical Significance**:
The finding '{finding.title}' represents a confirmed forensic indicator in category {finding.category} with severity {finding.severity}. Source artifact examined: {finding.source_artifact}.

**Attack Lifecycle Stage**:
Corresponds to initial execution or persistence phase under MITRE ATT&CK guidelines.

**Forensic Verification**:
1. Confirm byte offset and cryptographic hash of source artifact [{finding.finding_id}].
2. Inspect correlated timeline events around {finding.created_at}.

**Actionable Next Steps**:
- Isolate the source host immediately.
- Preserve volatile memory and snapshot active network state.
Citing finding: [{finding.finding_id}].
"""
        return AIProviderResponse(
            text=text,
            model_name=self.model_name,
            cited_finding_ids=[finding.finding_id],
        )

    def summarize_investigation(
        self, case_name: str, findings: List[FindingRecord], timeline_events: List[TimelineEventRecord]
    ) -> AIProviderResponse:
        f_ids = [f.finding_id for f in findings]
        cited_str = ", ".join(f"[{fid}]" for fid in f_ids[:5])
        text = f"""# Executive Incident Investigation Summary: {case_name}

## 1. Executive Summary
During the forensic investigation of case '{case_name}', our deterministic analysis identified {len(findings)} notable findings and {len(timeline_events)} normalized timeline events.

## 2. Technical Incident Narrative
Evidence analysis revealed indicators across multiple endpoints. Initial anomalous activity was flagged in findings {cited_str}.

## 3. Threat Assessment & Compromise Indicators
The severity distribution indicates high-priority containment is required. Key finding records:
"""
        for f in findings[:5]:
            text += f"\n- [{f.finding_id}] ({f.severity}): {f.title}"

        text += """

## 4. Prioritized Recommendations
1. Revoke active credential tokens associated with flagged user accounts.
2. Block external indicators identified during packet and string extraction.
"""
        return AIProviderResponse(
            text=text,
            model_name=self.model_name,
            cited_finding_ids=f_ids[:5],
        )

    def suggest_next_steps(self, findings: List[FindingRecord]) -> AIProviderResponse:
        f_ids = [f.finding_id for f in findings]
        text = f"""### Prioritized Forensic Next Steps

1. **Evidence Preservation**: Secure full disk bitstream images and unallocated sectors for all flagged endpoints.
2. **Account Audit**: Verify all authentication records associated with findings: {', '.join(f'[{x}]' for x in f_ids[:3])}.
3. **Network Quarantine**: Configure egress filtering for identified foreign IP addresses.
"""
        return AIProviderResponse(
            text=text,
            model_name=self.model_name,
            cited_finding_ids=f_ids[:3],
        )
