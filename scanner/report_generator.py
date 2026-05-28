import json
import os
from datetime import datetime, timezone
from pathlib import Path


class ReportGenerator:
    """
    Takes the gap analysis summary and generates two outputs:
        1. JSON report — machine-readable, CI/CD artifact, audit trail
        2. HTML report — human-readable, visual, shareable with auditors

    Both are written to the reports/ directory (gitignored).
    GitHub Actions uploads them as pipeline artifacts.
    """

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    def generate_json(self, summary: dict, account_id: str, region: str) -> str:
        """
        Writes the full gap analysis summary to a timestamped JSON file.

        Args:
            summary: output of GapAnalyzer.get_summary()
            account_id: AWS account ID being scanned
            region: AWS region scanned

        Returns:
            Path to the written JSON file
        """
        report = {
            "report_metadata": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "account_id": account_id,
                "region": region,
                "scanner_version": "1.0.0"
            },
            **summary
        }

        output_path = self.output_dir / f"compliance_report_{self.timestamp}.json"
        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)

        return str(output_path)

    def generate_html(self, summary: dict, account_id: str, region: str) -> str:
        """
        Generates a styled HTML compliance report.

        Structure:
            - Header with scan metadata
            - Overall compliance score
            - Per-framework scores with visual progress bars
            - Priority gaps table (the Option C differentiator)
            - Full failing controls table
            - Footer

        Args:
            summary: output of GapAnalyzer.get_summary()
            account_id: AWS account ID being scanned
            region: AWS region scanned

        Returns:
            Path to the written HTML file
        """
        overall = summary["overall"]
        framework_scores = summary["framework_scores"]
        priority_gaps = summary["priority_gaps"]
        failing_controls = summary["failing_controls"]

        # Severity badge colors
        severity_colors = {
            "CRITICAL": "#dc2626",
            "HIGH": "#ea580c",
            "MEDIUM": "#ca8a04",
            "LOW": "#16a34a",
            "UNKNOWN": "#6b7280"
        }

        # Score color — red < 60, amber 60-80, green > 80
        def score_color(pct):
            if pct >= 80:
                return "#16a34a"
            elif pct >= 60:
                return "#ca8a04"
            return "#dc2626"

        # Build framework score cards
        framework_cards = ""
        for fw, data in framework_scores.items():
            color = score_color(data["score_pct"])
            framework_cards += f"""
            <div class="score-card">
                <div class="fw-name">{fw.replace('_', ' ')}</div>
                <div class="fw-score" style="color: {color}">{data['score_pct']}%</div>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: {data['score_pct']}%; background: {color}"></div>
                </div>
                <div class="fw-detail">{data['compliant']} / {data['total_rules']} controls compliant</div>
            </div>"""

        # Build priority gaps rows
        priority_rows = ""
        for i, gap in enumerate(priority_gaps, 1):
            color = severity_colors.get(gap["severity"], "#6b7280")
            frameworks_list = ", ".join(gap.get("frameworks", {}).keys()).replace("_", " ")
            resources = ", ".join(gap.get("non_compliant_resources", [])) or "N/A"
            priority_rows += f"""
            <tr>
                <td>#{i}</td>
                <td>{gap['rule_name']}</td>
                <td>{gap['description']}</td>
                <td><span class="badge" style="background:{color}">{gap['severity']}</span></td>
                <td>{frameworks_list}</td>
                <td>{gap['frameworks_affected_count']}</td>
                <td>{resources}</td>
            </tr>"""

        # Build failing controls rows
        failing_rows = ""
        for ctrl in failing_controls:
            color = severity_colors.get(ctrl["severity"], "#6b7280")
            frameworks_list = ", ".join(ctrl.get("frameworks", {}).keys()).replace("_", " ")
            resources = ", ".join(ctrl.get("non_compliant_resources", [])) or "N/A"
            failing_rows += f"""
            <tr>
                <td>{ctrl['rule_name']}</td>
                <td>{ctrl['description']}</td>
                <td><span class="badge" style="background:{color}">{ctrl['severity']}</span></td>
                <td>{frameworks_list}</td>
                <td>{resources}</td>
            </tr>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cloud Compliance Report — {account_id}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0f172a; color: #e2e8f0; padding: 2rem; }}
        h1 {{ font-size: 1.8rem; font-weight: 700; color: #f8fafc; margin-bottom: 0.25rem; }}
        h2 {{ font-size: 1.2rem; font-weight: 600; color: #94a3b8; margin: 2rem 0 1rem; text-transform: uppercase; letter-spacing: 0.05em; }}
        .meta {{ color: #64748b; font-size: 0.875rem; margin-bottom: 2rem; }}
        .overall-score {{ font-size: 3rem; font-weight: 800; color: {score_color(overall['overall_score_pct'])}; }}
        .overall-card {{ background: #1e293b; border-radius: 0.75rem; padding: 1.5rem; margin-bottom: 1rem; display: inline-block; min-width: 200px; }}
        .overall-label {{ color: #94a3b8; font-size: 0.875rem; margin-bottom: 0.5rem; }}
        .overall-detail {{ color: #64748b; font-size: 0.875rem; margin-top: 0.5rem; }}
        .framework-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem; margin-bottom: 2rem; }}
        .score-card {{ background: #1e293b; border-radius: 0.75rem; padding: 1.5rem; }}
        .fw-name {{ font-weight: 600; color: #cbd5e1; margin-bottom: 0.5rem; }}
        .fw-score {{ font-size: 2rem; font-weight: 800; margin-bottom: 0.5rem; }}
        .progress-bar {{ background: #334155; border-radius: 9999px; height: 8px; margin-bottom: 0.5rem; }}
        .progress-fill {{ height: 8px; border-radius: 9999px; transition: width 0.3s; }}
        .fw-detail {{ color: #64748b; font-size: 0.8rem; }}
        table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 0.75rem; overflow: hidden; margin-bottom: 2rem; }}
        th {{ background: #334155; padding: 0.75rem 1rem; text-align: left; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; color: #94a3b8; }}
        td {{ padding: 0.75rem 1rem; border-top: 1px solid #334155; font-size: 0.875rem; vertical-align: top; }}
        tr:hover td {{ background: #243044; }}
        .badge {{ display: inline-block; padding: 0.2rem 0.6rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; color: white; }}
        .section-highlight {{ border-left: 3px solid #3b82f6; padding-left: 1rem; margin-bottom: 0.5rem; }}
        footer {{ color: #475569; font-size: 0.8rem; margin-top: 2rem; text-align: center; }}
    </style>
</head>
<body>
    <h1>Cloud Compliance Scanner</h1>
    <div class="meta">
        Account: {account_id} &nbsp;|&nbsp; Region: {region} &nbsp;|&nbsp;
        Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
    </div>

    <h2>Overall Compliance Score</h2>
    <div class="overall-card">
        <div class="overall-label">Overall Score</div>
        <div class="overall-score">{overall['overall_score_pct']}%</div>
        <div class="overall-detail">{overall['compliant']} compliant / {overall['non_compliant']} non-compliant / {overall['total_rules_evaluated']} total evaluated</div>
    </div>

    <h2>Framework Scores</h2>
    <div class="framework-grid">
        {framework_cards}
    </div>

    <h2>Priority Gaps — Maximum Cross-Framework Impact</h2>
    <p style="color:#64748b; font-size:0.875rem; margin-bottom:1rem;">
        These {len(priority_gaps)} controls, if remediated, close the most compliance gaps across GDPR, UAE PDPL, and Essential Eight simultaneously.
    </p>
    <table>
        <thead>
            <tr>
                <th>#</th>
                <th>Rule</th>
                <th>Description</th>
                <th>Severity</th>
                <th>Frameworks</th>
                <th>Frameworks Affected</th>
                <th>Non-Compliant Resources</th>
            </tr>
        </thead>
        <tbody>
            {priority_rows}
        </tbody>
    </table>

    <h2>All Failing Controls</h2>
    <table>
        <thead>
            <tr>
                <th>Rule</th>
                <th>Description</th>
                <th>Severity</th>
                <th>Frameworks</th>
                <th>Non-Compliant Resources</th>
            </tr>
        </thead>
        <tbody>
            {failing_rows}
        </tbody>
    </table>

    <footer>
        Cloud Compliance Scanner v1.0.0 &nbsp;|&nbsp; Frameworks: GDPR · UAE PDPL · Essential Eight
    </footer>
</body>
</html>"""

        output_path = self.output_dir / f"compliance_report_{self.timestamp}.html"
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)

        return str(output_path)