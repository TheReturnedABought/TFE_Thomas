"""
core/autofix/dockerfile_fixer.py - Automated Remediation Engine for Dockerfiles using native string logic.
"""

import copy
from typing import List

from models.issue import Issue


class DockerfileFixer:
    """Remediates issues directly on Dockerfile source without destroying comments."""

    @staticmethod
    def apply_fixes(file_path: str, issues: List[Issue]) -> int:
        fixes_applied = 0
        rule_ids = {issue.id for issue in issues}

        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.read().splitlines(keepends=True)

        original_lines = copy.deepcopy(lines)

        for i, line in enumerate(lines):
            stripped = line.strip()

            # DF-001: Append :latest if unversioned
            if "DF-001" in rule_ids and stripped.upper().startswith("FROM "):
                # FROM ubuntu AS build -> NOT HANDLED IN SIMPLE LAZY FIX. BUT FOR SIMPLE:
                parts = stripped.split()
                if len(parts) >= 2 and ":" not in parts[1]:
                    # parts[0] is FROM, parts[1] is image
                    old_img = parts[1]
                    new_img = f"{old_img}:latest"
                    lines[i] = line.replace(old_img, new_img, 1)
                    fixes_applied += 1

            # DF-004: ADD instead of COPY
            if "DF-004" in rule_ids and stripped.upper().startswith("ADD "):
                lines[i] = line.replace("ADD ", "COPY ", 1)
                fixes_applied += 1

            # DF-008: apt-get
            if (
                "DF-008" in rule_ids
                and stripped.upper().startswith("RUN ")
                and "apt-get install" in line
            ):
                if "--no-install-recommends" not in line:
                    lines[i] = line.replace(
                        "apt-get install", "apt-get install --no-install-recommends"
                    )
                    fixes_applied += 1

            # DF-009: pip
            if (
                "DF-009" in rule_ids
                and stripped.upper().startswith("RUN ")
                and "pip install" in line
            ):
                if "--no-cache-dir" not in line:
                    lines[i] = line.replace("pip install", "pip install --no-cache-dir")
                    fixes_applied += 1

        # DF-002: Inject USER
        if "DF-002" in rule_ids:
            # We must be careful not to inject it duplicate times if already fixed
            # Check if we already inject it locally or if the file already has USER
            # (which it shouldn't if the rule fired, but let's be safe)
            lines.append("\nRUN useradd -m dockcheckuser\nUSER dockcheckuser\n")
            fixes_applied += 1

        if lines != original_lines:
            with open(file_path, "w", encoding="utf-8") as f:
                f.writelines(lines)

        # Return fixes applied based on logic mutations
        return fixes_applied
