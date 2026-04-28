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
            "apt_get_missing_cleanup": False,
            "apk_missing_no_cache": False,
            "yum_missing_cleanup": False,
            "curl_missing_fsl": False,
            "wget_missing_qO": False,
            "sudo_in_run": False,
            "has_expose": False,
            "maintainer_used": False,
            "cd_used_in_run": False,
            "npm_missing_cleanup": False,
            "df_system_upgrade": False,
            "df_missing_setuid_cleanup": False,
            "df_arg_secrets": False,
            "df_entrypoint_shell_form": False,
            "df_cmd_shell_form": False,
            "df_expose_port_22": False,
            "df_missing_checksum": False,
            "df_apk_unpinned": False,
            "df_apt_unpinned": False,
            "df_healthcheck_no_interval": False,
            "df_copy_run_chown": False,
            "df_untrusted_registry": False,
            "df_no_multi_stage": False,
            "df_user_switched_to_root": False,
            "df_http_package_repo": False,
            "df_workdir_relative": False,
            "df_gem_unpinned": False,
            "df_npm_unpinned": False,
            "df_yum_no_y": False,
            "df_yum_unpinned": False,
            "df_zypper_no_y": False,
            "df_zypper_no_clean": False,
            "df_zypper_unpinned": False,
            "df_dnf_no_y": False,
            "df_dnf_no_clean": False,
            "df_dnf_unpinned": False,
            "df_multiple_healthcheck": False,
            "df_invalid_expose": False,
            "df_copy_bad_dest": False,
            "df_copy_bad_from": False,
            "df_from_not_unique": False,
            "df_apt_used": False,

        }

        has_apt_update = False
        has_apt_install = False
        run_count = 0
        from_count = 0
        user_switched = False
        healthcheck_count = 0
        from_aliases = set()


        for node in instructions:
            if not isinstance(node, DockerNode):
                continue


            if isinstance(node, FromNode):
                from_count += 1
                if node.alias:
                    if node.alias in from_aliases:
                        context["df_from_not_unique"] = True
                    from_aliases.add(node.alias)

                if node.image:
                    context["base_image"] = (
                        f"{node.image}:{node.tag}" if node.tag else node.image
                    )
                    if "://" not in node.image and "/" not in node.image and node.image not in ["ubuntu", "alpine", "debian", "python", "node", "golang", "ruby", "openjdk", "nginx", "redis", "postgres", "mysql", "mongo", "busybox"]:
                        context["df_untrusted_registry"] = True


            elif isinstance(node, UserNode):
                context["user"] = node.user
                context["user_is_explicit"] = True

            elif isinstance(node, WorkdirNode):
                context["has_workdir"] = True
                if node.path and not node.path.startswith("/"):
                    context["df_workdir_relative"] = True



            elif isinstance(node, CopyNode):
                if len(node.src) > 1 and not node.dst.endswith("/"):
                    # Check if the first src is --from, and if so, don't count it as a "real" file if len(src) is 2 (1 flag + 1 file)
                    real_srcs = [s for s in node.src if not s.startswith("--from=")]
                    if len(real_srcs) > 1:
                        context["df_copy_bad_dest"] = True
                for s in node.src:
                    if s.startswith("--from="):
                        stage = s.split("=", 1)[1]
                        if stage not in from_aliases and not stage.isdigit():
                            context["df_copy_bad_from"] = True

            elif isinstance(node, AddNode):
                context["has_add"] = True

            elif isinstance(node, HealthcheckNode):
                context["has_healthcheck"] = True
                healthcheck_count += 1


            elif isinstance(node, EnvNode):
                context["env_vars"].append(f"{node.key}={node.value}")

            elif isinstance(node, RunNode):
                run_count += 1
                full_run_val = " ".join(node.commands).lower()
                
                if "apt-get update" in full_run_val and "apt-get install" not in full_run_val:
                    has_apt_update = True
                if "apt-get install" in full_run_val and "apt-get update" not in full_run_val:
                    has_apt_install = True

                # DF-008: apt-get install without --no-install-recommends
                if "apt-get install" in full_run_val and "--no-install-recommends" not in full_run_val:
                    context["apt_get_missing_no_recommends"] = True

                # DF-009: pip install without --no-cache-dir
                if "pip install" in full_run_val and "--no-cache-dir" not in full_run_val:
                    context["pip_missing_no_cache_dir"] = True
                    
                # Evaluate rules that should be checked per individual command
                for cmd in node.commands:
                    val = cmd.lower()
                    if val.strip().startswith("curl ") and not any(f in val for f in ["-f", "--fail"]):
                        context["curl_missing_fsl"] = True
                    if val.strip().startswith("wget ") and not any(f in val for f in ["-qo-", "-q -o -"]):
                        context["wget_missing_qO"] = True
                    if "sudo" in val.split():
                        context["sudo_in_run"] = True
                    if val.strip().startswith("cd "):
                        context["cd_used_in_run"] = True

                # Evaluate package managers
                if "gem install" in full_run_val and ":" not in full_run_val and "-v" not in full_run_val:
                    context["df_gem_unpinned"] = True
                if "npm install" in full_run_val and "@" not in full_run_val:
                    context["df_npm_unpinned"] = True
                if "yum install" in full_run_val and "-y" not in full_run_val:
                    context["df_yum_no_y"] = True
                if "yum install" in full_run_val and "-" not in full_run_val: # crude pinning check
                    context["df_yum_unpinned"] = True
                if "zypper install" in full_run_val or "zypper in " in full_run_val:
                    if "-y" not in full_run_val and "--non-interactive" not in full_run_val:
                        context["df_zypper_no_y"] = True
                    if "=" not in full_run_val and "-" not in full_run_val:
                        context["df_zypper_unpinned"] = True
                if "zypper" in full_run_val and "clean" not in full_run_val:
                    context["df_zypper_no_clean"] = True
                if "dnf install" in full_run_val:
                    if "-y" not in full_run_val:
                        context["df_dnf_no_y"] = True
                    if "-" not in full_run_val:
                        context["df_dnf_unpinned"] = True
                if "dnf" in full_run_val and "clean all" not in full_run_val:
                    context["df_dnf_no_clean"] = True
                
                for cmd in node.commands:
                    val = cmd.lower()
                    if val.strip().startswith("apt ") or " apt " in val:
                        context["df_apt_used"] = True

                # Evaluate rules that span the full RUN structure like apt-get chaining
                if "apt-get install" in full_run_val and "rm -rf /var/lib/apt/lists" not in full_run_val:
                    context["apt_get_missing_cleanup"] = True
                if "apk add" in full_run_val and "--no-cache" not in full_run_val:
                    context["apk_missing_no_cache"] = True
                if "yum install" in full_run_val and "yum clean all" not in full_run_val:
                    context["yum_missing_cleanup"] = True
                if "npm install" in full_run_val and "npm cache clean" not in full_run_val:
                    context["npm_missing_cleanup"] = True
                    
            elif type(node).__name__ == "GenericNode":
                if node.instruction == "EXPOSE":
                    context["has_expose"] = True
                    try:
                        port = int(node.raw_value.split("/")[0])
                        if port < 1 or port > 65535:
                            context["df_invalid_expose"] = True
                    except:
                        context["df_invalid_expose"] = True

                elif node.instruction == "MAINTAINER":
                    context["maintainer_used"] = True

        context["multiple_run"] = run_count > 2
        context["apt_get_split"] = has_apt_update and has_apt_install
        context["df_multiple_healthcheck"] = healthcheck_count > 1

        if not context["user"]:
            context["user"] = "root"

        return context
