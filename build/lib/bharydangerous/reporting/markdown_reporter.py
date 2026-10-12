"""Executive and technical Markdown forensic reporter."""
from pathlib import Path
from bharydangerous.core.models import ReportModel
from bharydangerous.reporting.base import BaseReporter

class MarkdownReporter(BaseReporter):
    """Generates structured Markdown forensic report."""

    def generate(self, report_data: ReportModel, output_path: Path | str) -> Path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)

        md = []
        md.append(f"# {report_data.product_name} — Forensic Investigation Report")
        md.append(f"**Generated:** {report_data.generated_at} | **Tool Version:** {report_data.version}\n")
        md.append("---\n")

        # 1. Case Information
        c = report_data.case
        md.append("## 1. Case Metadata")
        md.append(f"- **Case ID:** `{c.case_id}`")
        md.append(f"- **Case Name:** {c.name}")
        md.append(f"- **Lead Investigator:** {c.investigator}")
        md.append(f"- **Status:** `{c.status}`")
        md.append(f"- **Created At:** {c.created_at}")
        if c.description:
            md.append(f"- **Description:** {c.description}")
        md.append("")

        # 2. Evidence Inventory
        md.append("## 2. Evidence Inventory & Verification")
        if not report_data.evidence_list:
            md.append("*No evidence recorded.*")
        else:
            md.append("| Evidence ID | Label | Type | File Size | SHA-256 | Verification Status |")
            md.append("|---|---|---|---|---|---|")
            for ev in report_data.evidence_list:
                md.append(
                    f"| `{ev.evidence_id}` | {ev.label} | {ev.evidence_type} | {ev.file_size_bytes:,} bytes | `{ev.sha256[:16]}...` | **{ev.verification_status}** |"
                )
        md.append("")

        # 3. Findings Summary
        md.append("## 3. Forensic Findings Summary")
        if not report_data.findings_list:
            md.append("*No suspicious findings identified.*")
        else:
            md.append("| Finding ID | Severity | Category | Confidence | Title | Source Artifact |")
            md.append("|---|---|---|---|---|---|")
            for f in report_data.findings_list:
                md.append(
                    f"| `{f.finding_id}` | **{f.severity}** | {f.category} | `{f.confidence}` | {f.title} | {f.source_artifact} |"
                )
        md.append("")

        # 4. Cross-Artifact Correlations
        md.append("## 4. Cross-Artifact Correlated Incidents")
        if not report_data.correlations:
            md.append("*No cross-artifact correlation chains triggered.*")
        else:
            for corr in report_data.correlations:
                md.append(f"### Correlation: {corr.rule_name} (Confidence: {int(corr.score * 100)}%)")
                md.append(f"- **Summary:** {corr.summary}")
                md.append(f"- **Linked Event IDs:** {', '.join(f'`{eid}`' for eid in corr.event_ids)}")
                md.append("")

        # 5. Timeline Statistics
        md.append("## 5. Timeline Statistics")
        ts = report_data.timeline_summary
        md.append(f"- **Total Normalized Events:** {ts.get('total_events', 0)}")
        md.append(f"- **Earliest Observed Event:** {ts.get('first_event_utc', 'N/A')}")
        md.append(f"- **Latest Observed Event:** {ts.get('last_event_utc', 'N/A')}")
        if ts.get("sources"):
            md.append("\n**Event Distribution by Source:**")
            for src, count in ts["sources"].items():
                md.append(f"- `{src}`: {count} events")
        md.append("")

        # 6. AI-Assisted Interpretations (Explicitly Separated)
        md.append("## 6. AI-Assisted Interpretations & Hypotheses")
        md.append("> **Note on Epistemic Integrity:** The following section contains generative AI analysis. Observations are anchored to specific Finding IDs, but hypotheses should be independently verified before presentation as legal facts.\n")
        if not report_data.ai_annotations:
            md.append("*No AI annotations recorded.*")
        else:
            for annot in report_data.ai_annotations:
                md.append(f"### AI Analysis: {annot.target_type} (Model: `{annot.model_identifier}`)")
                md.append(f"- **Generated:** {annot.created_at}")
                if annot.cited_finding_ids:
                    md.append(f"- **Verified Finding Citations:** {', '.join(f'`{cid}`' for cid in annot.cited_finding_ids)}")
                md.append(f"\n{annot.response_text}\n")

        # 7. Tool Diagnostics
        md.append("## 7. Forensic Tooling Diagnostics")
        md.append("| Tool / Runtime | Status | Details |")
        md.append("|---|---|---|")
        for diag in report_data.tool_diagnostics:
            md.append(f"| {diag.name} | **{diag.status}** | {diag.details} |")
        md.append("")

        with out.open("w", encoding="utf-8") as f:
            f.write("\n".join(md))
        return out
