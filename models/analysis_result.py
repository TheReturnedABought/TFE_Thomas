"""
models/analysis_result.py — AnalysisResult dataclass.

Aggregates everything produced by one or more analyzers:
  - metadata about the analysed target
  - the list of Issue objects found
  - a severity breakdown counter
  - performance metrics (analysis duration)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from models.issue import Issue


@dataclass
class AnalysisResult:
    """Container for the full output of a DockCheck analysis."""

    metadata: Dict[str, Any] = field(default_factory=dict)
    issues: List[Issue] = field(default_factory=list)
    performance_metrics: Dict[str, Any] = field(default_factory=dict)

    # Computed on first access via property
    _severity_levels: Dict[str, int] = field(
        default_factory=dict, repr=False, init=False
    )

    # ------------------------------------------------------------------
    # Severity breakdown
    # ------------------------------------------------------------------

    @property
    def severity_levels(self) -> Dict[str, int]:
        """
        Return a count of issues per severity level dynamically evaluated.

        Returns:
            Dict[str, int]: Mapping of severity levels to their respective counts.
        """
        counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for issue in self.issues:
            counts[issue.severity] = counts.get(issue.severity, 0) + 1
        return counts

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    def add_issue(self, issue: Issue) -> None:
        """
        Append an Issue finding to the result set.

        Args:
            issue (Issue): The detected analysis issue to add.
        """
        self.issues.append(issue)

    def merge(self, other: AnalysisResult) -> None:
        """
        Merge another AnalysisResult's issues, metadata, and performance metrics into this one.
        Useful when the Analyzer aggregates results from multiple sub-analyzers.

        Args:
            other (AnalysisResult): The other result container to merge.
        """
        self.issues.extend(other.issues)
        self.metadata.update(other.metadata)
        # Sum durations if both track them
        if "duration_s" in other.performance_metrics:
            existing = self.performance_metrics.get("duration_s", 0.0)
            self.performance_metrics["duration_s"] = (
                existing + other.performance_metrics["duration_s"]
            )

    def has_critical(self) -> bool:
        """
        Check if any critical-severity issues were detected.

        Returns:
            bool: True if there is at least one critical issue, False otherwise.
        """
        return self.severity_levels.get("critical", 0) > 0

    def total_issues(self) -> int:
        """
        Get the total number of detected issues.

        Returns:
            int: The total count of issues.
        """
        return len(self.issues)

    def __repr__(self) -> str:  # pragma: no cover
        sv = self.severity_levels
        return (
            f"AnalysisResult(issues={self.total_issues()}, "
            f"critical={sv['critical']}, medium={sv['medium']}, low={sv['low']})"
        )
