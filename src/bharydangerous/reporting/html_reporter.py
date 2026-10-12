"""Standalone, zero-CDN, responsive HTML forensic reporter."""
from pathlib import Path
from bharydangerous.core.models import ReportModel
from bharydangerous.reporting.base import BaseReporter

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{{ report.product_name }} — {{ report.case.name }}</title>
  <style>
    :root {
      --bg-dark: #0f172a;
      --bg-card: #1e293b;
      --bg-hover: #334155;
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
      --accent: #38bdf8;
      --accent-glow: rgba(56, 189, 248, 0.2);
      --crit: #ef4444;
      --high: #f97316;
      --med: #eab308;
      --low: #3b82f6;
      --info: #10b981;
      --border: #334155;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background-color: var(--bg-dark);
      color: var(--text-main);
      padding: 2rem 1rem;
      line-height: 1.6;
    }
    .container { max-width: 1200px; margin: 0 auto; }
    header {
      background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 2rem;
      margin-bottom: 2rem;
      box-shadow: 0 4px 20px rgba(0,0,0,0.5);
    }
    h1 { color: var(--accent); font-size: 2rem; margin-bottom: 0.5rem; }
    h2 { color: var(--accent); font-size: 1.4rem; margin: 2rem 0 1rem 0; border-bottom: 2px solid var(--border); padding-bottom: 0.4rem; }
    h3 { font-size: 1.1rem; margin-top: 1rem; color: #e2e8f0; }
    .meta-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 1rem;
      margin-top: 1rem;
    }
    .meta-item {
      background: var(--bg-card);
      padding: 1rem;
      border-radius: 8px;
      border: 1px solid var(--border);
    }
    .meta-label { color: var(--text-muted); font-size: 0.85rem; text-transform: uppercase; }
    .meta-val { font-weight: bold; font-size: 1.1rem; margin-top: 0.2rem; }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 1rem;
      background: var(--bg-card);
      border-radius: 8px;
      overflow: hidden;
      border: 1px solid var(--border);
    }
    th, td { padding: 0.85rem 1rem; text-align: left; border-bottom: 1px solid var(--border); }
    th { background: #111827; color: var(--text-muted); font-weight: 600; font-size: 0.9rem; }
    tr:hover { background-color: var(--bg-hover); }
    .badge {
      display: inline-block;
      padding: 0.2rem 0.6rem;
      border-radius: 9999px;
      font-size: 0.75rem;
      font-weight: bold;
      text-transform: uppercase;
    }
    .badge-CRITICAL { background: var(--crit); color: #fff; }
    .badge-HIGH { background: var(--high); color: #fff; }
    .badge-MEDIUM { background: var(--med); color: #000; }
    .badge-LOW { background: var(--low); color: #fff; }
    .badge-INFORMATIONAL { background: var(--info); color: #fff; }
    .badge-VERIFIED { background: #166534; color: #4ade80; }
    .badge-MISMATCH { background: #991b1b; color: #fca5a5; }
    .card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.5rem;
      margin-bottom: 1.5rem;
    }
    .alert-box {
      background: rgba(56, 189, 248, 0.1);
      border-left: 4px solid var(--accent);
      padding: 1rem;
      margin: 1rem 0;
      border-radius: 4px;
      font-size: 0.95rem;
    }
    code {
      background: #090d16;
      padding: 0.2rem 0.4rem;
      border-radius: 4px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.85rem;
      color: #38bdf8;
    }
    .search-bar {
      width: 100%;
      padding: 0.75rem 1rem;
      background: #0f172a;
      border: 1px solid var(--border);
      border-radius: 6px;
      color: #fff;
      margin-bottom: 1rem;
      font-size: 0.95rem;
    }
    footer {
      text-align: center;
      color: var(--text-muted);
      margin-top: 3rem;
      font-size: 0.85rem;
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>{{ report.product_name }}</h1>
      <p style="color: var(--text-muted);">Digital Forensics & Incident Response Investigation Report</p>
      <div class="meta-grid">
        <div class="meta-item">
          <div class="meta-label">Case ID / Name</div>
          <div class="meta-val">{{ report.case.name }} (<code>{{ report.case.case_id }}</code>)</div>
        </div>
        <div class="meta-item">
          <div class="meta-label">Lead Investigator</div>
          <div class="meta-val">{{ report.case.investigator }}</div>
        </div>
        <div class="meta-item">
          <div class="meta-label">Case Status</div>
          <div class="meta-val"><span class="badge" style="background:#3b82f6;">{{ report.case.status }}</span></div>
        </div>
        <div class="meta-item">
          <div class="meta-label">Report Generated</div>
          <div class="meta-val" style="font-size:0.95rem;">{{ report.generated_at }}</div>
        </div>
      </div>
    </header>

    {% if report.incomplete_analysis_warnings %}
    <div class="alert-box" style="border-left-color: #ef4444; background: rgba(239, 68, 68, 0.1);">
      <strong style="color: #ef4444;">⚠ Incomplete Analysis & Environment Warnings:</strong>
      <ul style="margin-left: 1.5rem; margin-top: 0.5rem;">
        {% for w in report.incomplete_analysis_warnings %}
        <li>{{ w }}</li>
        {% endfor %}
      </ul>
    </div>
    {% endif %}

    <h2>1. Evidence Inventory & Verification</h2>
    <table>
      <thead>
        <tr>
          <th>Evidence ID</th>
          <th>Label</th>
          <th>Type</th>
          <th>Size</th>
          <th>SHA-256</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        {% for ev in report.evidence_list %}
        <tr>
          <td><code>{{ ev.evidence_id }}</code></td>
          <td>{{ ev.label }}</td>
          <td>{{ ev.evidence_type }}</td>
          <td>{{ "{:,}".format(ev.file_size_bytes) }} bytes</td>
          <td><code>{{ ev.sha256[:16] }}...</code></td>
          <td><span class="badge badge-{{ ev.verification_status }}">{{ ev.verification_status }}</span></td>
        </tr>
        {% endfor %}
      </tbody>
    </table>

    <h2>2. Forensic Findings</h2>
    <input type="text" id="findingSearch" class="search-bar" placeholder="Filter findings by keyword, severity, or title..." onkeyup="filterFindings()">
    <table id="findingsTable">
      <thead>
        <tr>
          <th>Finding ID</th>
          <th>Severity</th>
          <th>Category</th>
          <th>Confidence</th>
          <th>Title</th>
          <th>Source</th>
        </tr>
      </thead>
      <tbody>
        {% for f in report.findings_list %}
        <tr>
          <td><code>{{ f.finding_id }}</code></td>
          <td><span class="badge badge-{{ f.severity }}">{{ f.severity }}</span></td>
          <td>{{ f.category }}</td>
          <td><code>{{ f.confidence }}</code></td>
          <td><strong>{{ f.title }}</strong></td>
          <td>{{ f.source_artifact }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>

    <h2>3. Cross-Artifact Incident Correlations</h2>
    {% if not report.correlations %}
      <div class="card"><p style="color:var(--text-muted);">No cross-artifact correlation chains triggered.</p></div>
    {% else %}
      {% for corr in report.correlations %}
      <div class="card">
        <h3>{{ corr.rule_name }} <span class="badge" style="background:#8b5cf6;">Score: {{ "{:.0%}".format(corr.score) }}</span></h3>
        <p style="margin: 0.5rem 0;">{{ corr.summary }}</p>
        <p style="color: var(--text-muted); font-size: 0.85rem;">Linked Event IDs:
          {% for eid in corr.event_ids %}<code>{{ eid }}</code> {% endfor %}
        </p>
      </div>
      {% endfor %}
    {% endif %}

    <h2>4. AI-Assisted Interpretations</h2>
    <div class="alert-box">
      <strong>Epistemic Separation Notice:</strong> Observations below were generated by AI and anchored to specific verified Finding IDs. Hypotheses must be independently validated before presentation as definitive facts.
    </div>
    {% if not report.ai_annotations %}
      <div class="card"><p style="color:var(--text-muted);">No AI interpretations recorded for this case.</p></div>
    {% else %}
      {% for annot in report.ai_annotations %}
      <div class="card">
        <h3>{{ annot.target_type }} <span class="badge" style="background:#0284c7;">Model: {{ annot.model_identifier }}</span></h3>
        <p style="color:var(--text-muted); font-size:0.85rem; margin-bottom: 0.5rem;">Citations:
          {% for cid in annot.cited_finding_ids %}<code>{{ cid }}</code> {% endfor %}
        </p>
        <div style="white-space: pre-wrap; font-size: 0.95rem;">{{ annot.response_text }}</div>
      </div>
      {% endfor %}
    {% endif %}

    <h2>5. Tool & Environment Diagnostics</h2>
    <table>
      <thead>
        <tr>
          <th>Diagnostic Check</th>
          <th>Status</th>
          <th>Details</th>
        </tr>
      </thead>
      <tbody>
        {% for diag in report.tool_diagnostics %}
        <tr>
          <td><strong>{{ diag.name }}</strong></td>
          <td><span class="badge badge-{{ diag.status }}">{{ diag.status }}</span></td>
          <td>{{ diag.details }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>

    <footer>
      <p>{{ report.product_name }} v{{ report.version }} &bull; Created by {{ report.product_name.split('-')[0] }} &bull; Open-Source Digital Forensics</p>
    </footer>
  </div>

  <script>
    function filterFindings() {
      var input = document.getElementById("findingSearch");
      var filter = input.value.toLowerCase();
      var table = document.getElementById("findingsTable");
      var trs = table.getElementsByTagName("tr");
      for (var i = 1; i < trs.length; i++) {
        var text = trs[i].innerText.toLowerCase();
        trs[i].style.display = text.indexOf(filter) > -1 ? "" : "none";
      }
    }
  </script>
</body>
</html>
"""

class HtmlReporter(BaseReporter):
    """Outputs standalone, offline, zero-CDN HTML report."""

    def generate(self, report_data: ReportModel, output_path: Path | str) -> Path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)

        try:
            from jinja2 import Template
            template = Template(HTML_TEMPLATE, autoescape=True)
            html_content = template.render(report=report_data)
        except Exception:
            import html as html_lib
            # Fallback basic HTML without jinja2
            html_content = f"<html><body><h1>{html_lib.escape(report_data.product_name)} Report</h1><p>Case: {html_lib.escape(report_data.case.name)}</p></body></html>"

        with out.open("w", encoding="utf-8") as f:
            f.write(html_content)
        return out
