"""
HTML Report Generator.

Generates professional HTML reports with:
- Executive summary
- Vulnerability details
- Charts and statistics
- Remediation guidance
"""

import json
import os
from datetime import datetime
from pathlib import Path
from string import Template
from typing import Dict, List, Optional

from ..core.config import Config
from ..core.logger import get_logger
from ..core.models import ScanSession, Severity, Vulnerability

logger = get_logger(__name__)


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EmberScan Report - ${session_name}</title>
    <style>
        :root {
            --critical: #dc3545;
            --high: #fd7e14;
            --medium: #ffc107;
            --low: #17a2b8;
            --info: #6c757d;
            --bg-dark: #1a1a2e;
            --bg-card: #16213e;
            --text-primary: #eee;
            --text-secondary: #aaa;
            --accent: #0f3460;
        }
        
        * { box-sizing: border-box; margin: 0; padding: 0; }
        
        body {
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: var(--bg-dark);
            color: var(--text-primary);
            line-height: 1.6;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        header {
            background: linear-gradient(135deg, var(--bg-card) 0%, var(--accent) 100%);
            padding: 40px 20px;
            text-align: center;
            border-bottom: 3px solid var(--critical);
        }
        
        header h1 {
            font-size: 2.5rem;
            margin-bottom: 10px;
        }
        
        header .logo {
            font-size: 3rem;
            margin-bottom: 15px;
        }
        
        .meta-info {
            display: flex;
            justify-content: center;
            gap: 30px;
            flex-wrap: wrap;
            margin-top: 20px;
            color: var(--text-secondary);
        }
        
        .meta-info span {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }
        
        .card {
            background: var(--bg-card);
            border-radius: 12px;
            padding: 25px;
            text-align: center;
            border: 1px solid rgba(255,255,255,0.1);
            transition: transform 0.2s;
        }
        
        .card:hover {
            transform: translateY(-5px);
        }
        
        .card.critical { border-left: 4px solid var(--critical); }
        .card.high { border-left: 4px solid var(--high); }
        .card.medium { border-left: 4px solid var(--medium); }
        .card.low { border-left: 4px solid var(--low); }
        .card.info { border-left: 4px solid var(--info); }
        
        .card .count {
            font-size: 3rem;
            font-weight: bold;
            margin-bottom: 10px;
        }
        
        .card.critical .count { color: var(--critical); }
        .card.high .count { color: var(--high); }
        .card.medium .count { color: var(--medium); }
        .card.low .count { color: var(--low); }
        .card.info .count { color: var(--info); }
        
        .section {
            background: var(--bg-card);
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 30px;
            border: 1px solid rgba(255,255,255,0.1);
        }
        
        .section h2 {
            color: var(--text-primary);
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid var(--accent);
        }
        
        .firmware-info {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
        }
        
        .firmware-info .item {
            display: flex;
            flex-direction: column;
        }
        
        .firmware-info .label {
            color: var(--text-secondary);
            font-size: 0.85rem;
            text-transform: uppercase;
        }
        
        .firmware-info .value {
            font-size: 1.1rem;
            font-family: monospace;
        }
        
        .vulnerability {
            background: rgba(0,0,0,0.2);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 15px;
            border-left: 4px solid;
        }
        
        .vulnerability.critical { border-color: var(--critical); }
        .vulnerability.high { border-color: var(--high); }
        .vulnerability.medium { border-color: var(--medium); }
        .vulnerability.low { border-color: var(--low); }
        .vulnerability.info { border-color: var(--info); }
        
        .vulnerability .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        
        .vulnerability .title {
            font-size: 1.2rem;
            font-weight: 600;
        }
        
        .severity-badge {
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: bold;
            text-transform: uppercase;
        }
        
        .severity-badge.critical { background: var(--critical); }
        .severity-badge.high { background: var(--high); color: #000; }
        .severity-badge.medium { background: var(--medium); color: #000; }
        .severity-badge.low { background: var(--low); }
        .severity-badge.info { background: var(--info); }
        
        .vulnerability .details {
            display: grid;
            gap: 10px;
        }
        
        .vulnerability .detail-row {
            display: grid;
            grid-template-columns: 150px 1fr;
            gap: 10px;
        }
        
        .vulnerability .detail-label {
            color: var(--text-secondary);
            font-weight: 500;
        }
        
        .vulnerability .evidence {
            background: rgba(0,0,0,0.3);
            padding: 10px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.9rem;
            overflow-x: auto;
        }
        
        .cve-list {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }
        
        .cve-tag {
            background: var(--accent);
            padding: 3px 10px;
            border-radius: 4px;
            font-size: 0.85rem;
        }
        
        .cve-tag a {
            color: var(--text-primary);
            text-decoration: none;
        }
        
        .cve-tag a:hover {
            text-decoration: underline;
        }
        
        .scanner-results {
            margin-top: 15px;
        }
        
        .scanner-badge {
            display: inline-block;
            background: var(--accent);
            padding: 3px 10px;
            border-radius: 4px;
            font-size: 0.8rem;
            margin-bottom: 10px;
        }
        
        footer {
            text-align: center;
            padding: 30px;
            color: var(--text-secondary);
            font-size: 0.9rem;
        }
        
        @media print {
            body { background: #fff; color: #000; }
            .card, .section { border: 1px solid #ddd; }
            header { background: #f5f5f5; border-bottom-color: #dc3545; }
        }
    </style>
</head>
<body>
    <header>
        <div class="logo">🔥</div>
        <h1>EmberScan Security Report</h1>
        <p>${session_name}</p>
        <div class="meta-info">
            <span>📅 ${scan_date}</span>
            <span>⏱️ Duration: ${duration}</span>
            <span>🔍 ${total_vulns} Findings</span>
        </div>
    </header>
    
    <div class="container">
        <div class="summary-cards">
            <div class="card critical">
                <div class="count">${critical_count}</div>
                <div class="label">Critical</div>
            </div>
            <div class="card high">
                <div class="count">${high_count}</div>
                <div class="label">High</div>
            </div>
            <div class="card medium">
                <div class="count">${medium_count}</div>
                <div class="label">Medium</div>
            </div>
            <div class="card low">
                <div class="count">${low_count}</div>
                <div class="label">Low</div>
            </div>
            <div class="card info">
                <div class="count">${info_count}</div>
                <div class="label">Info</div>
            </div>
        </div>
        
        <div class="section">
            <h2>📋 Firmware Information</h2>
            <div class="firmware-info">
                ${firmware_info}
            </div>
        </div>
        
        <div class="section">
            <h2>🔴 Critical & High Vulnerabilities</h2>
            ${critical_high_vulns}
        </div>
        
        <div class="section">
            <h2>🟡 Medium Vulnerabilities</h2>
            ${medium_vulns}
        </div>
        
        <div class="section">
            <h2>🔵 Low & Informational</h2>
            ${low_info_vulns}
        </div>
        
        <div class="section">
            <h2>📊 Scanner Results Summary</h2>
            ${scanner_summary}
        </div>
    </div>
    
    <footer>
        <p>Generated by EmberScan v1.0.0 | ${generation_time}</p>
        <p>This report is confidential. Handle according to your organization's security policies.</p>
    </footer>
</body>
</html>"""


VULN_TEMPLATE = """
<div class="vulnerability ${severity_class}">
    <div class="header">
        <span class="title">${title}</span>
        <span class="severity-badge ${severity_class}">${severity}</span>
    </div>
    <div class="details">
        <div class="detail-row">
            <span class="detail-label">Description</span>
            <span>${description}</span>
        </div>
        ${file_path}
        ${endpoint}
        ${cve_ids}
        <div class="detail-row">
            <span class="detail-label">Evidence</span>
            <div class="evidence">${evidence}</div>
        </div>
        <div class="detail-row">
            <span class="detail-label">Remediation</span>
            <span>${remediation}</span>
        </div>
        <div class="scanner-badge">Scanner: ${scanner}</div>
    </div>
</div>
"""


class HTMLReporter:
    """Generate HTML security reports."""

    def __init__(self, config: Config):
        self.config = config

    def generate(self, session: ScanSession, output_dir: str) -> str:
        """Generate HTML report for scan session."""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        report_file = output_path / f"emberscan_report_{session.id[:8]}.html"

        # Prepare template variables
        variables = self._prepare_variables(session)

        # Generate HTML
        template = Template(HTML_TEMPLATE)
        html_content = template.safe_substitute(variables)

        # Write file
        report_file.write_text(html_content)

        logger.info(f"HTML report generated: {report_file}")
        return str(report_file)

    def _prepare_variables(self, session: ScanSession) -> Dict:
        """Prepare template variables from session data."""
        summary = session.get_summary()

        # Calculate duration
        if session.started_at and session.completed_at:
            duration = session.completed_at - session.started_at
            duration_str = f"{duration.total_seconds():.1f}s"
        else:
            duration_str = "N/A"

        # Group vulnerabilities by severity
        all_vulns = session.all_vulnerabilities

        critical_high = [v for v in all_vulns if v.severity in [Severity.CRITICAL, Severity.HIGH]]
        medium = [v for v in all_vulns if v.severity == Severity.MEDIUM]
        low_info = [v for v in all_vulns if v.severity in [Severity.LOW, Severity.INFO]]

        # Generate firmware info HTML
        firmware_html = self._generate_firmware_info(session.firmware)

        # Generate vulnerability HTML
        critical_high_html = (
            self._generate_vuln_list(critical_high)
            or "<p>No critical or high severity findings.</p>"
        )
        medium_html = self._generate_vuln_list(medium) or "<p>No medium severity findings.</p>"
        low_info_html = (
            self._generate_vuln_list(low_info) or "<p>No low or informational findings.</p>"
        )

        # Generate scanner summary
        scanner_html = self._generate_scanner_summary(session.scan_results)

        return {
            "session_name": session.name,
            "scan_date": session.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            "duration": duration_str,
            "total_vulns": len(all_vulns),
            "critical_count": summary["by_severity"]["critical"],
            "high_count": summary["by_severity"]["high"],
            "medium_count": summary["by_severity"]["medium"],
            "low_count": summary["by_severity"]["low"],
            "info_count": summary["by_severity"]["info"],
            "firmware_info": firmware_html,
            "critical_high_vulns": critical_high_html,
            "medium_vulns": medium_html,
            "low_info_vulns": low_info_html,
            "scanner_summary": scanner_html,
            "generation_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

    def _generate_firmware_info(self, firmware) -> str:
        """Generate firmware information HTML."""
        if not firmware:
            return "<p>No firmware information available.</p>"

        items = [
            ("Name", firmware.name or "Unknown"),
            ("Vendor", firmware.vendor or "Unknown"),
            ("Version", firmware.version or "Unknown"),
            ("Architecture", firmware.architecture.value if firmware.architecture else "Unknown"),
            ("Device Type", firmware.device_type or "Unknown"),
            ("MD5", firmware.md5 or "N/A"),
            ("SHA256", firmware.sha256[:32] + "..." if firmware.sha256 else "N/A"),
            ("File Size", f"{firmware.file_size:,} bytes" if firmware.file_size else "N/A"),
        ]

        html = ""
        for label, value in items:
            html += f"""
            <div class="item">
                <span class="label">{label}</span>
                <span class="value">{value}</span>
            </div>
            """

        return html

    def _generate_vuln_list(self, vulnerabilities: List[Vulnerability]) -> str:
        """Generate vulnerability list HTML."""
        if not vulnerabilities:
            return ""

        html = ""
        template = Template(VULN_TEMPLATE)

        for vuln in sorted(vulnerabilities, key=lambda v: v.severity, reverse=True):
            # Prepare optional fields
            file_path = ""
            if vuln.file_path:
                file_path = f"""
                <div class="detail-row">
                    <span class="detail-label">File Path</span>
                    <span>{vuln.file_path}{f":{vuln.line_number}" if vuln.line_number else ""}</span>
                </div>
                """

            endpoint = ""
            if vuln.endpoint:
                endpoint = f"""
                <div class="detail-row">
                    <span class="detail-label">Endpoint</span>
                    <span>{vuln.endpoint}</span>
                </div>
                """

            cve_ids = ""
            if vuln.cve_ids:
                cve_tags = "".join(
                    [
                        f'<span class="cve-tag"><a href="https://nvd.nist.gov/vuln/detail/{cve}" target="_blank">{cve}</a></span>'
                        for cve in vuln.cve_ids
                    ]
                )
                cve_ids = f"""
                <div class="detail-row">
                    <span class="detail-label">CVE IDs</span>
                    <div class="cve-list">{cve_tags}</div>
                </div>
                """

            html += template.safe_substitute(
                {
                    "severity_class": vuln.severity.value.lower(),
                    "title": self._escape_html(vuln.title),
                    "severity": vuln.severity.value.upper(),
                    "description": self._escape_html(vuln.description),
                    "file_path": file_path,
                    "endpoint": endpoint,
                    "cve_ids": cve_ids,
                    "evidence": self._escape_html(vuln.evidence or "N/A"),
                    "remediation": self._escape_html(
                        vuln.remediation
                        or "Review and remediate according to security best practices."
                    ),
                    "scanner": vuln.scanner_name,
                }
            )

        return html

    def _generate_scanner_summary(self, scan_results) -> str:
        """Generate scanner summary HTML."""
        if not scan_results:
            return "<p>No scanner results available.</p>"

        html = '<div class="firmware-info">'

        for result in scan_results:
            vuln_count = len(result.vulnerabilities)
            status_icon = "✅" if result.status.name == "COMPLETED" else "❌"

            html += f"""
            <div class="item">
                <span class="label">{result.scanner_name}</span>
                <span class="value">{status_icon} {vuln_count} findings ({result.duration:.1f}s)</span>
            </div>
            """

        html += "</div>"
        return html

    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters."""
        if not text:
            return ""
        return (
            text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;")
        )
