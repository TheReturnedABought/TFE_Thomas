"""
analyzers/dockerfile_analyzer.py — Static analysis of Dockerfile files.

Parses a Dockerfile into a list of instructions and runs all Dockerfile-related
rules from the RulesEngine against the extracted context.

No Docker daemon is required — this is pure file-level static analysis.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from core.ast import (
    AddNode,
    CopyNode,
    DockerNode,
    EnvNode,
    FromNode,
    HealthcheckNode,
    LabelNode,
    RunNode,
    UserNode,
    WorkdirNode,
)
from core.parser.dockerfile_parser import DockerfileParser
from core.rules_engine import RulesEngine
from models.issue import Issue

# Default rules file relative to the project root
_DEFAULT_RULES = os.path.join(
    os.path.dirname(__file__), "..", "rules", "default_rules.json"
)


class DockerfileAnalyzer:
    """
    Analyses a Dockerfile for bad practices and misconfigurations.

    Args:
        dockerfile_path: Path to the Dockerfile to analyse.
        rules_path:      Optional path to a custom rules JSON file.
    """

    def __init__(self, dockerfile_path: str, rules_path: Optional[str] = None) -> None:
        self._path = dockerfile_path
        self._rules_path = rules_path or _DEFAULT_RULES
        self._content: Optional[str] = None
        self._instructions: Optional[List[Dict[str, str]]] = None
        self._engine = RulesEngine(self._rules_path)
        self._engine.load_rules()
        self._load()

    # ------------------------------------------------------------------
    # Internal loading
    # ------------------------------------------------------------------

    def _load(self) -> None:
        with open(self._path, encoding="utf-8") as fh:
            self._content = fh.read()

    # ------------------------------------------------------------------
    # Public: parsing
    # ------------------------------------------------------------------

    def parse_dockerfile(self) -> List[DockerNode]:
        """
        Parse the Dockerfile into a list of AST Node objects.

        Returns:
            list of DockerNode derivatives (empty list for an empty Dockerfile).
        """
        if self._instructions is not None:
            return self._instructions

        if not self._content:
            self._instructions = []
            return self._instructions

        parser = DockerfileParser()
        self._instructions = parser.parse(self._content)
        return self._instructions

    # ------------------------------------------------------------------
    # Public: analysis
    # ------------------------------------------------------------------

    def detect_bad_practices(self) -> List[Issue]:
        """
        Run all Dockerfile rules and return a list of Issue objects.

        Returns:
            list of Issue objects (empty list if no problems found).
        """
        instructions = self.parse_dockerfile()
        context = self._build_context(instructions)
        return self._engine.evaluate_all(context, component_filter="dockerfile")

    # ------------------------------------------------------------------
    # Context builder — translates parsed instructions into rule inputs
    # ------------------------------------------------------------------

    def _build_context(self, instructions: List[DockerNode]) -> Dict[str, Any]:
        """Convert the AST node list into a context dict for the RulesEngine."""

        if not isinstance(instructions, list):
            return {"component": "dockerfile"}

        context: Dict[str, Any] = {
            "component": "dockerfile",
            "base_image": "",
            "user": "",  # last USER instruction value
            "has_workdir": False,
            "has_add": False,
            "multiple_run": False,
            "apt_get_split": False,
            "has_healthcheck": False,
            "apt_get_missing_no_recommends": False,
            "pip_missing_no_cache_dir": False,
            "env_vars": [],
            "user_is_explicit": False,
        }

        has_apt_update = False
        has_apt_install = False
        run_count = 0

        for node in instructions:
            if not isinstance(node, DockerNode):
                continue

            if isinstance(node, FromNode):
                if node.image:
                    context["base_image"] = (
                        f"{node.image}:{node.tag}" if node.tag else node.image
                    )

            elif isinstance(node, UserNode):
                context["user"] = node.user
                context["user_is_explicit"] = True

            elif isinstance(node, WorkdirNode):
                context["has_workdir"] = True

            elif isinstance(node, AddNode):
                context["has_add"] = True

            elif isinstance(node, HealthcheckNode):
                context["has_healthcheck"] = True

            elif isinstance(node, EnvNode):
                context["env_vars"].append(f"{node.key}={node.value}")

            elif isinstance(node, RunNode):
                run_count += 1
                for cmd in node.commands:
                    val = cmd.lower()
                    if "apt-get update" in val and "apt-get install" not in val:
                        has_apt_update = True
                    if "apt-get install" in val and "apt-get update" not in val:
                        has_apt_install = True

                    # DF-008: apt-get install without --no-install-recommends
                    if (
                        "apt-get install" in val
                        and "--no-install-recommends" not in val
                    ):
                        context["apt_get_missing_no_recommends"] = True

                    # DF-009: pip install without --no-cache-dir
                    if "pip install" in val and "--no-cache-dir" not in val:
                        context["pip_missing_no_cache_dir"] = True

        context["multiple_run"] = run_count > 2
        context["apt_get_split"] = has_apt_update and has_apt_install

        if not context["user"]:
            context["user"] = "root"

        return context
