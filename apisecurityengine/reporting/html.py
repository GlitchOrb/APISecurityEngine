import json
from html import escape

from apisecurityengine.models.schemas import RunSummary


class HtmlReporter:
    """Generates an interactive HTML interactive report directly from a RunSummary payload."""

    TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>APISecurityEngine Report - {target_url}</title>
    <style>
        :root {{
            --bg: #f8f9fa;
            --surface: #ffffff;
            --text-primary: #1f2937;
            --text-secondary: #4b5563;
            --border: #e5e7eb;
            
            --critical: #dc2626;
            --high: #f97316;
            --medium: #f59e0b;
            --low: #3b82f6;
            --info: #64748b;
        }}
        
        * {{ box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }}
        body {{ background-color: var(--bg); color: var(--text-primary); margin: 0; padding: 2rem; }}
        
        table {{
            width: 100%; border-collapse: collapse; margin-top: 1.5rem; background: var(--surface);
            box-shadow: 0 1px 3px rgba(0,0,0,0.1); border-radius: 8px; overflow: hidden;
        }}
        th, td {{ padding: 1rem; text-align: left; border-bottom: 1px solid var(--border); }}
        th {{ background-color: #f3f4f6; font-weight: 600; }}
        tr.finding-row:hover {{ background-color: #f9fafb; cursor: pointer; }}
        
        .severity-badge {{
            padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.875rem; font-weight: 600; color: white;
            display: inline-block; text-align: center; min-width: 80px;
        }}
        .badge-critical {{ background-color: var(--critical); }}
        .badge-high {{ background-color: var(--high); }}
        .badge-medium {{ background-color: var(--medium); }}
        .badge-low {{ background-color: var(--low); }}
        .badge-informational {{ background-color: var(--info); }}
        
        .header {{ margin-bottom: 2rem; display: flex; justify-content: space-between; align-items: flex-end; }}
        .metrics-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
        .metric-card {{ background: var(--surface); padding: 1.5rem; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); text-align: center; }}
        .metric-card h3 {{ margin: 0; font-size: 0.875rem; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.05em; }}
        .metric-card p {{ margin: 0.5rem 0 0 0; font-size: 2rem; font-weight: bold; color: var(--text-primary); }}
        
        .filters {{ margin-bottom: 1rem; display: flex; gap: 1rem; flex-wrap: wrap; }}
        select, button {{ padding: 0.5rem 1rem; border: 1px solid var(--border); border-radius: 6px; font-size: 0.875rem; background: var(--surface); cursor: pointer; }}
        button:hover, select:hover {{ background-color: #f3f4f6; }}
        
        /* Modal */
        .modal-overlay {{ position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); display: none; padding: 2rem; z-index: 50; }}
        .modal-content {{ background: var(--surface); max-width: 800px; margin: 0 auto; border-radius: 8px; overflow-y: auto; max-height: 100%; box-shadow: 0 4px 6px rgba(0,0,0,0.1); position: relative; }}
        .modal-header {{ padding: 1.5rem; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: flex-start; }}
        .modal-header h2 {{ margin: 0; font-size: 1.5rem; }}
        .modal-body {{ padding: 1.5rem; }}
        .close-btn {{ background: none; border: none; font-size: 1.5rem; cursor: pointer; padding: 0; line-height: 1; color: var(--text-secondary); }}
        
        pre {{ background: #1e1e1e; color: #d4d4d4; padding: 1rem; border-radius: 6px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; margin: 0.5rem 0 1.5rem; }}
        .label {{ font-weight: 600; margin-top: 1.5rem; margin-bottom: 0.5rem; color: var(--text-primary); display: block; }}
        .tag {{ display: inline-block; background: #e2e8f0; color: #475569; padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; margin-right: 0.5rem; margin-bottom: 0.5rem; }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>APISecurityEngine Executive Summary</h1>
            <p style="color: var(--text-secondary); margin-top: 0.5rem;">Target: <a href="{target_url}" target="_blank">{target_url}</a></p>
        </div>
        <div style="text-align: right; color: var(--text-secondary);">
            <p>Run ID: {run_id}</p>
            <p>Duration: {duration_secs} seconds</p>
        </div>
    </div>

    <div class="metrics-grid">
        <div class="metric-card"><h3>Endpoints Scanned</h3><p>{total_endpoints}</p></div>
        <div class="metric-card" style="border-bottom: 4px solid var(--critical);"><h3>Critical</h3><p>{critical}</p></div>
        <div class="metric-card" style="border-bottom: 4px solid var(--high);"><h3>High</h3><p>{high}</p></div>
        <div class="metric-card" style="border-bottom: 4px solid var(--medium);"><h3>Medium</h3><p>{medium}</p></div>
        <div class="metric-card" style="border-bottom: 4px solid var(--low);"><h3>Low</h3><p>{low}</p></div>
        <div class="metric-card" style="border-bottom: 4px solid var(--info);"><h3>Informational</h3><p>{info}</p></div>
    </div>

    <div class="filters">
        <select id="severityFilter" onchange="filterFindings()">
            <option value="ALL">All Severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
            <option value="Informational">Informational</option>
        </select>
        <select id="owaspFilter" onchange="filterFindings()">
            <option value="ALL">All OWASP Categories</option>
            {owasp_options}
        </select>
    </div>

    <table id="findingsTable">
        <thead>
            <tr>
                <th>Severity</th>
                <th>Vulnerability Title</th>
                <th>OWASP Mapping</th>
                <th>CWE</th>
                <th>Confidence</th>
            </tr>
        </thead>
        <tbody>
            {finding_rows}
        </tbody>
    </table>

    <!-- Modal for Evidence Viewer -->
    <div id="evidenceModal" class="modal-overlay" onclick="if(event.target === this) closeModal()">
        <div class="modal-content">
            <div class="modal-header">
                <div style="padding-right: 2rem;">
                    <div id="modalSeverity" class="severity-badge badge-high" style="margin-bottom: 0.5rem;">HIGH</div>
                    <h2 id="modalTitle">Vulnerability Title</h2>
                </div>
                <button class="close-btn" onclick="closeModal()">&times;</button>
            </div>
            <div class="modal-body">
                <div>
                    <span id="modalOwasp" class="tag">API1:2023</span>
                    <span id="modalCwe" class="tag">CWE-000</span>
                    <span id="modalConfidence" class="tag">CONFIRMED</span>
                </div>
                
                <span class="label">Description</span>
                <p id="modalDesc" style="line-height: 1.5;"></p>
                
                <span class="label">Remediation Recommendation</span>
                <p id="modalRemediation" style="line-height: 1.5; background: #ecfdf5; padding: 1rem; border-radius: 6px; border: 1px solid #a7f3d0; color: #065f46;"></p>
                
                <div id="modalProofSection">
                    <hr style="border: 0; border-top: 1px solid var(--border); margin: 2rem 0;">
                    <h3 style="margin-bottom: 1rem;">Evidence Viewer (Sanitized)</h3>
                    
                    <span class="label" id="modalRequestLine">Request</span>
                    <pre id="modalRequestText">GET / HTTP/1.1</pre>

                    <span class="label" id="modalResponseLine">Response</span>
                    <pre id="modalResponseText">HTTP/1.1 200 OK</pre>
                </div>
            </div>
        </div>
    </div>

    <script>
        const findingsData = {json_data};

        function getSeverityClass(severity) {{
            const s = severity.toLowerCase();
            if (s === 'critical') return 'badge-critical';
            if (s === 'high') return 'badge-high';
            if (s === 'medium') return 'badge-medium';
            if (s === 'low') return 'badge-low';
            return 'badge-informational';
        }}

        function viewEvidence(id) {{
            const finding = findingsData.find(f => f.id === id);
            if (!finding) return;

            document.getElementById('modalTitle').textContent = finding.title;
            
            const sevEl = document.getElementById('modalSeverity');
            sevEl.textContent = finding.severity.toUpperCase();
            sevEl.className = 'severity-badge ' + getSeverityClass(finding.severity);

            document.getElementById('modalOwasp').textContent = finding.owasp_api_2023_mapping;
            document.getElementById('modalCwe').textContent = finding.cwe_mapping;
            document.getElementById('modalConfidence').textContent = finding.confidence.toUpperCase();
            
            document.getElementById('modalDesc').textContent = finding.description;
            document.getElementById('modalRemediation').textContent = finding.remediation;

            const proofSec = document.getElementById('modalProofSection');
            if (finding.proof) {{
                proofSec.style.display = 'block';
                const p = finding.proof;
                
                document.getElementById('modalRequestLine').textContent = `Request [${{p.request_method}} ${{p.request_url}}]`;
                
                let reqText = `${{p.request_method}} ${{p.request_url}} HTTP/1.1\\n`;
                for (const [k, v] of Object.entries(p.sanitized_request_headers)) {{
                    reqText += `${{k}}: ${{v}}\\n`;
                }}
                reqText += `\\n${{p.sanitized_request_body || ''}}`;
                document.getElementById('modalRequestText').textContent = reqText;

                document.getElementById('modalResponseLine').textContent = `Response [Status: ${{p.response_status_code}}]`;
                
                let respText = `HTTP/1.1 ${{p.response_status_code}}\\n`;
                for (const [k, v] of Object.entries(p.sanitized_response_headers)) {{
                    respText += `${{k}}: ${{v}}\\n`;
                }}
                respText += `\\n${{p.sanitized_response_body || ''}}`;
                document.getElementById('modalResponseText').textContent = respText;

            }} else {{
                proofSec.style.display = 'none';
            }}

            const modal = document.getElementById('evidenceModal');
            modal.style.display = 'block';
            document.body.style.overflow = 'hidden';
        }}

        function closeModal() {{
            document.getElementById('evidenceModal').style.display = 'none';
            document.body.style.overflow = 'auto';
        }}

        function filterFindings() {{
            const sevFilter = document.getElementById('severityFilter').value;
            const owaspFilter = document.getElementById('owaspFilter').value;
            const rows = document.querySelectorAll('.finding-row');

            rows.forEach(row => {{
                const rSev = row.getAttribute('data-severity');
                const rOwasp = row.getAttribute('data-owasp');
                
                const sevMatch = (sevFilter === 'ALL' || rSev === sevFilter);
                const owaspMatch = (owaspFilter === 'ALL' || rOwasp === owaspFilter);
                
                row.style.display = (sevMatch && owaspMatch) ? '' : 'none';
            }});
        }}
        
        // Escape key to close modal
        document.addEventListener('keydown', function(event) {{
            if (event.key === 'Escape') closeModal();
        }});
    </script>
</body>
</html>"""

    @classmethod
    def generate(cls, summary: RunSummary) -> str:
        duration = summary.end_time - summary.start_time

        unique_owasp = sorted(list(set([f.owasp_api_2023_mapping for f in summary.findings])))
        owasp_options = "\n".join(
            [f'<option value="{escape(cat)}">{escape(cat)}</option>' for cat in unique_owasp]
        )

        rows = []
        for f in summary.findings:
            row = (
                f'<tr class="finding-row" data-severity="{escape(f.severity.value)}" data-owasp="{escape(f.owasp_api_2023_mapping)}" onclick="viewEvidence(\'{escape(f.id)}\')">'
                f'<td><span class="severity-badge {cls._badge_class(f.severity.value)}">{escape(f.severity.value).upper()}</span></td>'
                f"<td><strong>{escape(f.title)}</strong></td>"
                f'<td><span class="tag">{escape(f.owasp_api_2023_mapping)}</span></td>'
                f"<td>{escape(f.cwe_mapping)}</td>"
                f"<td>{escape(f.confidence.value).upper()}</td>"
                "</tr>"
            )
            rows.append(row)

        findings_json = summary.model_dump_json(include={"findings"})
        # Extract just the array natively for JS consumption
        findings_json_array = json.loads(findings_json).get("findings", [])

        html = cls.TEMPLATE.format(
            target_url=escape(summary.target_url),
            run_id=escape(summary.run_id),
            duration_secs=f"{duration.total_seconds():.2f}",
            total_endpoints=summary.stats.total_endpoints_discovered,
            critical=summary.stats.critical_findings,
            high=summary.stats.high_findings,
            medium=summary.stats.medium_findings,
            low=summary.stats.low_findings,
            info=summary.stats.informational_findings,
            owasp_options=owasp_options,
            finding_rows="\n".join(rows),
            json_data=json.dumps(findings_json_array),  # Inject safely
        )
        return html

    @staticmethod
    def _badge_class(severity: str) -> str:
        s = severity.lower()
        if s == "critical":
            return "badge-critical"
        if s == "high":
            return "badge-high"
        if s == "medium":
            return "badge-medium"
        if s == "low":
            return "badge-low"
        return "badge-informational"
