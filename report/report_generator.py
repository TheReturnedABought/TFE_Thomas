"""
report/report_generator.py — HTML report generation.

Renders an AnalysisResult into a self-contained HTML report using a
Jinja2 template.  Reports include a summary dashboard, metadata, issues
ranked by severity, and recommendations — as required by TFE spec §7.
"""

from __future__ import annotations

import os
from datetime import datetime

from jinja2 import Environment, FileSystemLoader

from core.config import Config
from core.i18n import get_text
from models.analysis_result import AnalysisResult

_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")


class ReportGenerator:
    """
    Generates HTML reports from AnalysisResult objects.

    Args:
        config: The DockCheck runtime configuration.
    """

    def __init__(self, config: Config) -> None:
        self._config = config
        self._env = Environment(
            loader=FileSystemLoader(_TEMPLATE_DIR),
            autoescape=True,
        )

    # ------------------------------------------------------------------

    def generate_html_report(self, result: AnalysisResult) -> str:
        """
        Render the analysis result into an HTML file.

        Args:
            result: The AnalysisResult to render.

        Returns:
            str: The absolute path to the generated HTML file.
        """
        template = self._env.get_template("report.html.j2")

        # Organise issues by severity for the template
        issues_by_severity = {"critical": [], "medium": [], "low": []}
        for issue in result.issues:
            issues_by_severity.setdefault(issue.severity, []).append(issue)

        # Extract unique recommendations
        recommendations = []
        seen = set()
        for issue in result.issues:
            if issue.recommendation not in seen:
                recommendations.append(
                    {
                        "id": issue.id,
                        "severity": issue.severity,
                        "text": issue.recommendation,
                    }
                )
                seen.add(issue.recommendation)

        html = template.render(
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            metadata=result.metadata,
            total_issues=result.total_issues(),
            severity_levels=result.severity_levels,
            issues=result.issues,
            issues_by_severity=issues_by_severity,
            recommendations=recommendations,
            performance=result.performance_metrics,
            get_text=get_text,
        )

        output_path = self._config.output_path
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(html)

        return os.path.abspath(output_path)
