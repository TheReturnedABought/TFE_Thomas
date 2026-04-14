"""
core/analyzer.py — Orchestrates all sub-analyzers and aggregates results.

The Analyzer reads the command from Config and dispatches to the appropriate
sub-analyzer(s), returning a single unified AnalysisResult.
"""

from __future__ import annotations

import os
from typing import Optional

from core.config import Config
from models.analysis_result import AnalysisResult
from models.issue import Issue
from utils.performance_monitor import PerformanceMonitor


class Analyzer:
    """
    Top-level orchestrator.

    Delegates to DockerfileAnalyzer, ComposeAnalyzer or DockerImageAnalyzer
    depending on Config.command, then merges the results into one
    AnalysisResult.
    """

    def __init__(self, config: Config) -> None:
        self._config = config
        self._monitor = PerformanceMonitor()

    # ------------------------------------------------------------------

    def aggregate_results(self) -> AnalysisResult:
        """
        Run the appropriate analyzer(s) and return the combined result.

        Applies the severity threshold from Config so that only issues at or
        above the configured level are included in the final result.
        """
        self._monitor.start_timer()
        result = AnalysisResult()

        command = self._config.command

        try:
            if command == "image":
                result.merge(self._run_image())

            elif command == "dockerfile":
                result.merge(self._run_dockerfile())

            elif command == "compose":
                result.merge(self._run_compose())

            elif command == "all":
                if self._config.get_option("image_name"):
                    result.merge(self._run_image())
                if self._config.get_option("dockerfile_path"):
                    result.merge(self._run_dockerfile())
                if self._config.get_option("compose_path"):
                    result.merge(self._run_compose())
                if self._config.get_option("swarm_path"):
                    result.merge(self._run_swarm())

            elif command == "swarm":
                result.merge(self._run_swarm())

        finally:
            self._monitor.stop_timer()
            result.performance_metrics["duration_s"] = self._monitor.get_duration()

        # Apply severity filter
        self._config.get_option("severity", "low")
        result.issues = [
            issue
            for issue in result.issues
            if self._config.severity_passes(issue.severity)
        ]

        return result

    # ------------------------------------------------------------------
    # Private dispatch helpers
    # ------------------------------------------------------------------

    def _run_dockerfile(self) -> AnalysisResult:
        from analyzers.dockerfile_analyzer import DockerfileAnalyzer

        path = self._config.get_option("dockerfile_path")
        rules = self._config.rules_path

        validation_issue = self._validate_path(path, "dockerfile")
        if validation_issue:
            result = AnalysisResult(metadata={"dockerfile_path": path})
            result.issues.append(validation_issue)
            return result

        try:
            analyzer = DockerfileAnalyzer(path, rules_path=rules)
            issues = analyzer.detect_bad_practices()
        except Exception as e:
            result = AnalysisResult(metadata={"dockerfile_path": path})
            result.issues.append(
                Issue(
                    id="RUNTIME-ERROR",
                    severity="critical",
                    component="dockerfile",
                    description=f"Dockerfile Error: {e}",
                    recommendation="Check the Dockerfile syntax and ensure rules/default_rules.json exists.",
                )
            )
            return result

        meta = {"dockerfile_path": path}
        result = AnalysisResult(metadata=meta)
        result.issues = issues
        return result

    def _run_compose(self) -> AnalysisResult:
        from analyzers.compose_analyzer import ComposeAnalyzer

        path = self._config.get_option("compose_path")
        rules = self._config.rules_path

        validation_issue = self._validate_path(path, "compose")
        if validation_issue:
            result = AnalysisResult(metadata={"compose_path": path})
            result.issues.append(validation_issue)
            return result

        try:
            analyzer = ComposeAnalyzer(path, rules_path=rules)
            security_issues = analyzer.check_security_rules()
            redundancy_issues = analyzer.detect_redundancies()
        except Exception as e:
            result = AnalysisResult(metadata={"compose_path": path})
            result.issues.append(
                Issue(
                    id="RUNTIME-ERROR",
                    severity="critical",
                    component="compose",
                    description=f"Compose Error: {e}",
                    recommendation="Check the Compose YAML syntax and ensure rules/default_rules.json exists.",
                )
            )
            return result

        result = AnalysisResult(metadata={"compose_path": path})
        result.issues = security_issues + redundancy_issues
        return result

    def _run_image(self) -> AnalysisResult:
        from analyzers.image_analyzer import DockerImageAnalyzer

        image_name = self._config.get_option("image_name")
        rules = self._config.rules_path

        try:
            analyzer = DockerImageAnalyzer(image_name, rules_path=rules)
            meta = analyzer.extract_metadata()
            issues = analyzer.detect_bad_practices()
        except Exception as e:
            # Report failure to extract image metadata
            result = AnalysisResult(metadata={"image_name": image_name})
            result.issues.append(
                Issue(
                    id="IMAGE-ERROR",
                    severity="critical",
                    component="image",
                    description=f"Image Error: {e}",
                    recommendation="Ensure the Docker daemon is running and the image name is valid.",
                )
            )
            return result

        result = AnalysisResult(metadata=meta)
        result.issues = issues
        return result

    def _run_swarm(self) -> AnalysisResult:
        from analyzers.swarm_analyzer import SwarmAnalyzer

        path = self._config.get_option("swarm_path")
        rules = self._config.rules_path

        validation_issue = self._validate_path(path, "swarm")
        if validation_issue:
            result = AnalysisResult(metadata={"swarm_path": path})
            result.issues.append(validation_issue)
            return result

        try:
            analyzer = SwarmAnalyzer(path, rules_path=rules)
            issues = analyzer.detect_bad_practices()
        except Exception as e:
            result = AnalysisResult(metadata={"swarm_path": path})
            result.issues.append(
                Issue(
                    id="RUNTIME-ERROR",
                    severity="critical",
                    component="swarm",
                    description=f"Swarm Error: {e}",
                    recommendation="Check the Swarm YAML syntax and ensure rules/default_rules.json exists.",
                )
            )
            return result

        result = AnalysisResult(metadata={"swarm_path": path})
        result.issues = issues
        return result

    def _validate_path(self, path: str, component: str) -> Optional[Issue]:
        """
        Hardened path validation to prevent crashes before analysis begins.
        Checks for existence, file type, permissions, and size limits.
        """
        # Defensive type coercion (discovered via Deep Chaos Monte Carlo)
        if not isinstance(path, str):
            path = str(path) if path is not None else ""
        if not isinstance(component, str):
            component = str(component) if component is not None else "unknown"

        if not path:
            return Issue(
                id="SYS-001",
                severity="critical",
                component=component,
                description="Analysis path is empty or null.",
                recommendation="Provide a valid file path for analysis.",
            )

        if not os.path.exists(path):
            return Issue(
                id="SYS-002",
                severity="critical",
                component=component,
                description=f"Path does not exist: {path}",
                recommendation="Verify the file path is correct.",
            )

        if not os.path.isfile(path):
            return Issue(
                id="SYS-003",
                severity="critical",
                component=component,
                description=f"Path is not a regular file: {path}",
                recommendation=(
                    "DockCheck only supports static file analysis, "
                    "not directory-wide recursive analysis yet."
                ),
            )

        if not os.access(path, os.R_OK):
            return Issue(
                id="SYS-004",
                severity="critical",
                component=component,
                description=f"Permission denied: {path}",
                recommendation="Ensure the current user has read permissions for the file.",
            )

        # Sanity check: limit file size to 5MB to prevent memory exhaustion/hangs
        # (A typical Dockerfile/Compose file is < 100KB)
        MAX_SIZE = 5 * 1024 * 1024
        if os.path.getsize(path) > MAX_SIZE:
            return Issue(
                id="SYS-005",
                severity="critical",
                component=component,
                description=f"File is too large ({os.path.getsize(path)} bytes).",
                recommendation="Split the file or remove excessive comments/redundant definitions.",
            )

        return None
