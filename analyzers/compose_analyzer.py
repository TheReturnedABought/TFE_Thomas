"""
analyzers/compose_analyzer.py — Static analysis of Docker Compose files.

Parses a docker-compose.yml file and runs all Compose-related rules
from the RulesEngine against each service's configuration.

No Docker daemon is required — this is pure file-level static analysis.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

import yaml

from core.rules_engine import RulesEngine
from models.issue import Issue

# Default rules file relative to the project root
_DEFAULT_RULES = os.path.join(
    os.path.dirname(__file__), "..", "rules", "default_rules.json"
)


class ComposeAnalyzer:
    """
    Analyses a Docker Compose file for bad practices and misconfigurations.

    Args:
        compose_path: Path to the docker-compose.yml file.
        rules_path:   Optional path to a custom rules JSON file.
    """

    def __init__(self, compose_path: str, rules_path: Optional[str] = None) -> None:
        self._path = compose_path
        self._rules_path = rules_path or _DEFAULT_RULES
        self._engine = RulesEngine(self._rules_path)
        self._engine.load_rules()
        self._data: Dict[str, Any] = {}
        self._load()

    # ------------------------------------------------------------------
    # Internal loading
    # ------------------------------------------------------------------

    def _load(self) -> None:
        with open(self._path, encoding="utf-8") as fh:
            self._data = yaml.safe_load(fh) or {}

    # ------------------------------------------------------------------
    # Public: service listing
    # ------------------------------------------------------------------

    def analyze_services(self) -> List[str]:
        """
        Return a list of service names defined in the Compose file.

        Returns:
            list of service name strings (empty list if no services section).
        """
        services = self._data.get("services", {})
        if not services:
            return []
        return list(services.keys())

    # ------------------------------------------------------------------
    # Public: security analysis
    # ------------------------------------------------------------------

    def check_security_rules(self) -> List[Issue]:
        """
        Run per-service security rules (DC-001 … DC-004) and return issues.

        Each service is evaluated independently. Issues include the service
        name in the component field for traceability.

        Returns:
            list of Issue objects.
        """
        issues: List[Issue] = []
        services = self._data.get("services", {})

        for svc_name, svc_config in services.items():
            if not isinstance(svc_config, dict):
                continue
            context = self._build_service_context(svc_name, svc_config)
            svc_issues = self._engine.evaluate_all(context, component_filter="compose")
            # Tag each issue with the service name
            for issue in svc_issues:
                issue.component = f"compose/{svc_name}"
            issues.extend(svc_issues)

        return issues

    # ------------------------------------------------------------------
    # Public: redundancy detection
    # ------------------------------------------------------------------

    def detect_redundancies(self) -> List[Issue]:
        """
        Detect redundant / duplicate service images (DC-005).

        Returns:
            list of Issue objects (empty if no duplicates found).
        """
        services = self._data.get("services", {})
        image_map: Dict[str, List[str]] = {}

        for svc_name, svc_config in services.items():
            if not isinstance(svc_config, dict):
                continue
            image = svc_config.get("image", "")
            if image:
                image_map.setdefault(image, []).append(svc_name)

        issues: List[Issue] = []
        for image, svc_names in image_map.items():
            if len(svc_names) > 1:
                context = {
                    "component": "compose",
                    "has_duplicate_images": True,
                }
                dup_issues = self._engine.evaluate_all(
                    context, component_filter="compose"
                )
                for issue in dup_issues:
                    if issue.id == "DC-005":
                        issue.component = f"compose/{','.join(svc_names)}"
                        issues.append(issue)

        return issues

    # ------------------------------------------------------------------
    # Context builder — per-service
    # ------------------------------------------------------------------

    def _build_service_context(
        self, svc_name: str, svc_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Build a context dict for a single Compose service."""
        if not isinstance(svc_config, dict):
            return {"component": "compose"}

        image = svc_config.get("image", "")
        user = str(svc_config.get("user", "")).strip()

        # Build env_vars list from environment section
        env_vars: List[str] = []
        env_section = svc_config.get("environment", {})
        if isinstance(env_section, dict):
            for key, value in env_section.items():
                env_vars.append(f"{key}={value}")
        elif isinstance(env_section, list):
            env_vars = list(env_section)

        # Build ports list
        ports = svc_config.get("ports", [])
        volumes = svc_config.get("volumes", [])
        # --- DC-018 to DC-033 Extractions ---
        cap_drop = svc_config.get("cap_drop", [])
        dc_missing_cap_drop_all = "ALL" not in [str(c).upper() for c in cap_drop]
        
        sec_opt = svc_config.get("security_opt", [])
        dc_missing_no_new_privileges = not any("no-new-privileges" in str(s).lower() for s in sec_opt)
        
        dc_mounts_sensitive_files = False
        dc_exposes_docker_sock = False
        dc_mounts_root = False
        dc_mounts_etc = False
        for vol in volumes:
            vol_str = str(vol).lower()
            if ".env" in vol_str or "id_rsa" in vol_str:
                dc_mounts_sensitive_files = True
            if "docker.sock" in vol_str:
                dc_exposes_docker_sock = True
            if vol_str.startswith("/:") or vol_str.startswith("/ ") or vol_str == "/":
                dc_mounts_root = True
            if vol_str.startswith("/etc:") or vol_str.startswith("/etc "):
                dc_mounts_etc = True
                
        networks = svc_config.get("networks", {})
        dc_no_custom_network = len(networks) == 0
        dc_explicit_bridge = str(svc_config.get("network_mode", "")).lower() == "bridge"
        dc_missing_read_only = not bool(svc_config.get("read_only", False))
        dc_uses_env_file = bool(svc_config.get("env_file"))
        
        logging = svc_config.get("logging", {})
        dc_missing_logging_config = "max-size" not in str(logging)
        
        tmpfs = svc_config.get("tmpfs", [])
        dc_tmpfs_no_size = bool(tmpfs) and not isinstance(tmpfs, dict) # simplistic check
        
        dc_privileged_ports = False
        for p in ports:
            p_str = str(p)
            parts = p_str.split(":")
            host_port = parts[0]
            if host_port.isdigit() and int(host_port) < 1024:
                dc_privileged_ports = True
                
        dc_missing_depends_on = not bool(svc_config.get("depends_on"))
        dc_uses_cgroup_parent = bool(svc_config.get("cgroup_parent"))
        dc_userns_host = str(svc_config.get("userns_mode", "")).lower() == "host"
        # DC-006: privileged mode
        privileged = svc_config.get("privileged", False)

        # DC-007: writable volumes (bind mounts without :ro suffix)
        has_writable_volumes = False
        volumes = svc_config.get("volumes", [])
        for vol in volumes:
            vol_str = str(vol)
            if ":" in vol_str and not vol_str.endswith(":ro"):
                # Check if it's a bind mount (starts with / or ./)
                source = vol_str.split(":")[0]
                if (
                    source.startswith("/")
                    or source.startswith("./")
                    or source.startswith("../")
                ):
                    has_writable_volumes = True
                    break

        return {
            "component": "compose",
            "base_image": image,
            "user": user if user else "root",
            "env_vars": env_vars,
            "ports": [str(p) for p in ports],
            "has_duplicate_images": False,
            "privileged": privileged,
            "has_writable_volumes": has_writable_volumes,
            "has_restart": bool(svc_config.get("restart")),
            "has_healthcheck": bool(svc_config.get("healthcheck")),
            "network_mode": str(svc_config.get("network_mode", "")).lower(),
            "pid_mode": str(svc_config.get("pid", "")).lower(),
            "has_resource_limits": "limits" in (svc_config.get("deploy", {}).get("resources", {}) or {}),
            "has_container_name": bool(svc_config.get("container_name")),
            "has_dangerous_caps": bool(set(svc_config.get("cap_add", [])) & {"ALL", "SYS_ADMIN"}),
            "ipc_mode": str(svc_config.get("ipc", "")).lower(),
            "has_mac_address": bool(svc_config.get("mac_address")),
            "has_dns": bool(svc_config.get("dns")),
            "dc_missing_cap_drop_all": dc_missing_cap_drop_all,
            "dc_missing_no_new_privileges": dc_missing_no_new_privileges,
            "dc_mounts_sensitive_files": dc_mounts_sensitive_files,
            "dc_no_custom_network": dc_no_custom_network,
            "dc_exposes_docker_sock": dc_exposes_docker_sock,
            "dc_missing_read_only": dc_missing_read_only,
            "dc_explicit_bridge": dc_explicit_bridge,
            "dc_mounts_root": dc_mounts_root,
            "dc_mounts_etc": dc_mounts_etc,
            "dc_uses_env_file": dc_uses_env_file,
            "dc_missing_logging_config": dc_missing_logging_config,
            "dc_tmpfs_no_size": dc_tmpfs_no_size,
            "dc_privileged_ports": dc_privileged_ports,
            "dc_missing_depends_on": dc_missing_depends_on,
            "dc_uses_cgroup_parent": dc_uses_cgroup_parent,
            "dc_userns_host": dc_userns_host,

        }
