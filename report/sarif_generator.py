"""
report/sarif_generator.py — Exports static analysis results to SARIF v2.1.0 format.

Provides seamless integration with GitHub Advanced Security and GitLab SAST.
Outputs strict JSON conforming to the structural requirement of standard CI/CD scanning.
"""

import json
from typing import Any, Dict, List

from core.config import Config
from models.analysis_result import AnalysisResult
from models.issue import Issue


class SarifGenerator:
    """
    Transforms an internal AnalysisResult metric block into SARIF format.
    """

    def __init__(self, config: Config) -> None:
        self._config = config

    def _map_severity(self, raw_severity: str) -> str:
        """Map DockCheck severities to SARIF level enumerations."""
        mapping = {"critical": "error", "medium": "warning", "low": "note"}
        return mapping.get(raw_severity.lower(), "note")

    def _build_rule(self, issue: Issue) -> Dict[str, Any]:
        """Convert an issue into a SARIF reportingDescriptor."""
        return {
            "id": issue.id,
            "name": issue.id.replace("-", ""),
            "shortDescription": {"text": issue.description},
            "help": {"text": issue.recommendation},
        }

    def _build_result(self, issue: Issue) -> Dict[str, Any]:
        """Convert an issue into a SARIF result."""
        return {
            "ruleId": issue.id,
            "level": self._map_severity(issue.severity),
            "message": {"text": issue.description},
            "locations": [
                {"physicalLocation": {"artifactLocation": {"uri": issue.component}}}
            ],
        }

    def generate(self, analysis_result: AnalysisResult) -> str:
        """
        Creates the SARIF JSON payload and writes it to disk based on config.
        Returns the absolute payload string if debugging, or writes to path.
        """
        rules = []
        rule_ids = set()
        results = []

        for issue in analysis_result.issues:
            if issue.id not in rule_ids:
                rules.append(self._build_rule(issue))
                rule_ids.add(issue.id)
            results.append(self._build_result(issue))

        sarif_payload = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "DockCheck SAST",
                            "informationUri": "https://github.com/dockcheck/dockcheck",
                            "version": "1.0.0",
                            "rules": rules,
                        }
                    },
                    "results": results,
                }
            ],
        }

        output_path = self._config.get_option("sarif_output", "dockcheck_report.sarif")

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(sarif_payload, f, indent=4)

        return output_path
