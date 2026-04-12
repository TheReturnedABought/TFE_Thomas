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
        threshold = self._config.get_option("severity", "low")
        result.issues = [
            issue for issue in result.issues
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

        analyzer = DockerfileAnalyzer(path, rules_path=rules)
        issues = analyzer.detect_bad_practices()
        meta = {"dockerfile_path": path}

        result = AnalysisResult(metadata=meta)
        result.issues = issues
        return result

    def _run_compose(self) -> AnalysisResult:
        from analyzers.compose_analyzer import ComposeAnalyzer
        path = self._config.get_option("compose_path")
        rules = self._config.rules_path
        analyzer = ComposeAnalyzer(path, rules_path=rules)
        security_issues = analyzer.check_security_rules()
        redundancy_issues = analyzer.detect_redundancies()
        result = AnalysisResult(metadata={"compose_path": path})
        result.issues = security_issues + redundancy_issues
        return result

    def _run_image(self) -> AnalysisResult:
        from analyzers.image_analyzer import DockerImageAnalyzer
        image_name = self._config.get_option("image_name")
        rules = self._config.rules_path
        analyzer = DockerImageAnalyzer(image_name, rules_path=rules)
        meta = analyzer.extract_metadata()
        issues = analyzer.detect_bad_practices()
        result = AnalysisResult(metadata=meta)
        result.issues = issues
        return result

    def _run_swarm(self) -> AnalysisResult:
        from analyzers.swarm_analyzer import SwarmAnalyzer
        path = self._config.get_option("swarm_path")
        rules = self._config.rules_path
        analyzer = SwarmAnalyzer(path, rules_path=rules)
        issues = analyzer.detect_bad_practices()
        result = AnalysisResult(metadata={"swarm_path": path})
        result.issues = issues
        return result
