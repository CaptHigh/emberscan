"""
JSON Report Generator.

Generates machine-readable JSON reports for scan results,
suitable for integration with other tools and pipelines.
"""

import json
from pathlib import Path
from datetime import datetime
from typing import Optional

from ..core.config import Config
from ..core.logger import get_logger
from ..core.models import ScanSession

logger = get_logger(__name__)


class JSONReporter:
    """Generate JSON reports from scan results."""

    def __init__(self, config: Config):
        self.config = config

    def generate(self, session: ScanSession, output_dir: str) -> str:
        """
        Generate JSON report.

        Args:
            session: Completed scan session
            output_dir: Output directory path

        Returns:
            Path to generated report
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        report_file = output_path / f"emberscan_report_{session.id}.json"

        # Build report structure
        report = {
            "report_metadata": {
                "tool": "EmberScan",
                "version": "1.0.0",
                "generated_at": datetime.now().isoformat(),
                "report_id": session.id,
            },
            "scan_info": {
                "session_id": session.id,
                "session_name": session.name,
                "status": session.status.name,
                "started_at": session.started_at.isoformat() if session.started_at else None,
                "completed_at": session.completed_at.isoformat() if session.completed_at else None,
                "duration_seconds": (
                    (session.completed_at - session.started_at).total_seconds()
                    if session.completed_at and session.started_at
                    else None
                ),
            },
            "target": self._build_target_info(session),
            "summary": session.get_summary(),
            "vulnerabilities": self._build_vulnerabilities(session),
            "scan_results": [r.to_dict() for r in session.scan_results],
        }

        # Write JSON file
        with open(report_file, "w") as f:
            json.dump(report, f, indent=2, default=str)

        logger.info(f"JSON report generated: {report_file}")

        # Also generate SARIF format if requested
        if self.config.reporter.output_formats and "sarif" in self.config.reporter.output_formats:
            sarif_file = self._generate_sarif(session, output_path)
            logger.info(f"SARIF report generated: {sarif_file}")

        return str(report_file)

    def _build_target_info(self, session: ScanSession) -> dict:
        """Build target information section."""
        if session.firmware:
            return {
                "type": "firmware",
                "firmware": session.firmware.to_dict(),
            }
        elif session.target_ip:
            return {
                "type": "network",
                "ip": session.target_ip,
                "port": session.target_port,
            }
        return {"type": "unknown"}

    def _build_vulnerabilities(self, session: ScanSession) -> list:
        """Build vulnerabilities section with severity grouping."""
        vulns = session.all_vulnerabilities

        # Sort by severity (critical first)
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        vulns_sorted = sorted(vulns, key=lambda v: severity_order.get(v.severity.value, 5))

        return [v.to_dict() for v in vulns_sorted]

    def _generate_sarif(self, session: ScanSession, output_path: Path) -> str:
        """Generate SARIF format report for integration with code analysis tools."""
        sarif_file = output_path / f"emberscan_report_{session.id}.sarif"

        sarif_report = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "EmberScan",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/emberscan/emberscan",
                            "rules": self._build_sarif_rules(session),
                        }
                    },
                    "results": self._build_sarif_results(session),
                }
            ],
        }

        with open(sarif_file, "w") as f:
            json.dump(sarif_report, f, indent=2)

        return str(sarif_file)

    def _build_sarif_rules(self, session: ScanSession) -> list:
        """Build SARIF rules from vulnerability types."""
        rules = {}

        for vuln in session.all_vulnerabilities:
            rule_id = vuln.vuln_type.value
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": vuln.vuln_type.value.replace("_", " ").title(),
                    "shortDescription": {"text": f"{vuln.vuln_type.value} vulnerability"},
                    "defaultConfiguration": {
                        "level": self._severity_to_sarif_level(vuln.severity.value)
                    },
                }

        return list(rules.values())

    def _build_sarif_results(self, session: ScanSession) -> list:
        """Build SARIF results from vulnerabilities."""
        results = []

        for vuln in session.all_vulnerabilities:
            result = {
                "ruleId": vuln.vuln_type.value,
                "level": self._severity_to_sarif_level(vuln.severity.value),
                "message": {"text": vuln.description},
                "locations": [],
            }

            if vuln.file_path:
                result["locations"].append(
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": vuln.file_path},
                            "region": {"startLine": vuln.line_number or 1},
                        }
                    }
                )

            results.append(result)

        return results

    def _severity_to_sarif_level(self, severity: str) -> str:
        """Convert severity to SARIF level."""
        mapping = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "info": "note",
        }
        return mapping.get(severity, "note")
