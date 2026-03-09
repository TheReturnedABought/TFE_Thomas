"""
analyzers/dockerfile_analyzer.py — Static analysis of Dockerfile files.

Parses a Dockerfile into a list of instructions and runs all Dockerfile-related
rules from the RulesEngine against the extracted context.

No Docker daemon is required — this is pure file-level static analysis.
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional

from models.issue import Issue
from core.rules_engine import RulesEngine

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

    def parse_dockerfile(self) -> List[Dict[str, str]]:
        """
        Parse the Dockerfile into a list of instruction dicts.

        Each dict has:
            "command" — the Dockerfile keyword (FROM, RUN, COPY, …)
            "value"   — the rest of the line (argument)

        Returns:
            list of instruction dicts (empty list for an empty Dockerfile).
        """
        if self._instructions is not None:
            return self._instructions

        instructions: List[Dict[str, str]] = []
        if not self._content:
            self._instructions = instructions
            return instructions

        # Join continuation lines (backslash at end of line)
        joined = re.sub(r"\\\n", " ", self._content)

        for raw_line in joined.splitlines():
            line = raw_line.strip()
            # Skip blank lines and comments
            if not line or line.startswith("#"):
                continue
            # Split on first whitespace to separate keyword from value
            parts = line.split(None, 1)
            instructions.append({
                "command": parts[0].upper(),
                "value":   parts[1] if len(parts) > 1 else "",
            })

        self._instructions = instructions
        return instructions

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

    def _build_context(self, instructions: List[Dict[str, str]]) -> Dict[str, Any]:
        """Convert the instruction list into a context dict for the RulesEngine."""

        context: Dict[str, Any] = {
            "component":             "dockerfile",
            "base_image":            "",
            "user":                  "",       # last USER instruction value
            "has_workdir":           False,
            "has_add":               False,
            "multiple_run":          False,
            "apt_get_split":         False,
            "env_vars":              [],
        }

        run_instructions: List[str] = []
        has_apt_update = False
        has_apt_install = False
        apt_update_run_index: Optional[int] = None

        for i, instr in enumerate(instructions):
            cmd = instr["command"]
            val = instr["value"].strip()

            if cmd == "FROM":
                # Handle "FROM image AS alias" — take only the image part
                context["base_image"] = val.split()[0] if val else ""

            elif cmd == "USER":
                context["user"] = val.split()[0] if val else ""

            elif cmd == "WORKDIR":
                context["has_workdir"] = True

            elif cmd == "ADD":
                context["has_add"] = True

            elif cmd == "ENV":
                # ENV KEY=VALUE  or  ENV KEY VALUE
                if "=" in val:
                    context["env_vars"].append(val.split("=", 1)[0] + "=" + val.split("=", 1)[1])
                else:
                    # Legacy "ENV KEY VALUE" syntax
                    parts = val.split(None, 1)
                    if len(parts) == 2:
                        context["env_vars"].append(f"{parts[0]}={parts[1]}")

            elif cmd == "RUN":
                run_instructions.append(val)
                # Check for split apt-get update / install
                if "apt-get update" in val and "apt-get install" not in val:
                    has_apt_update = True
                    apt_update_run_index = i
                if "apt-get install" in val and "apt-get update" not in val:
                    has_apt_install = True

        # Multiple RUN: more than 2 consecutive RUN instructions
        run_count = sum(1 for i in instructions if i["command"] == "RUN")
        context["multiple_run"] = run_count > 2

        # Split apt-get
        context["apt_get_split"] = has_apt_update and has_apt_install

        # If no USER was ever set, default to root
        if not context["user"]:
            context["user"] = "root"

        return context
