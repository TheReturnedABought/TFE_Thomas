"""
analyzers/swarm_analyzer.py — Static analysis of Docker Swarm stack files.

Parses a Docker Swarm stack file (docker-stack.yml / docker-compose.yml with
deploy keys) and runs all Swarm-related rules from the RulesEngine against
each service's deployment configuration.

No Docker daemon or live Swarm cluster is required — this is pure file-level
static analysis.

Reference: Docker official Swarm documentation, TFE AnalyseTFE §1.4.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

import yaml

from models.issue import Issue
from core.rules_engine import RulesEngine

# Default rules file relative to the project root
_DEFAULT_RULES = os.path.join(
    os.path.dirname(__file__), "..", "rules", "default_rules.json"
)


class SwarmAnalyzer:
    """
    Analyses a Docker Swarm stack file for misconfigurations and deviations
    from best practices at the orchestration level.

    Args:
        swarm_path:  Path to the Swarm stack file (YAML).
        rules_path:  Optional path to a custom rules JSON file.
    """

    def __init__(self, swarm_path: str, rules_path: Optional[str] = None) -> None:
        self._path = swarm_path
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
        """Return the list of service names in the stack file."""
        services = self._data.get("services", {})
        if not services:
            return []
        return list(services.keys())

    # ------------------------------------------------------------------
    # Public: analysis
    # ------------------------------------------------------------------

    def detect_bad_practices(self) -> List[Issue]:
        """
        Run all Swarm rules against every service and return found issues.

        Returns:
            list of Issue objects.
        """
        issues: List[Issue] = []
        services = self._data.get("services", {})
        top_level_networks = self._data.get("networks", {})

        for svc_name, svc_config in services.items():
            if not isinstance(svc_config, dict):
                continue
            context = self._build_service_context(
                svc_name, svc_config, top_level_networks
            )
            svc_issues = self._engine.evaluate_all(
                context, component_filter="swarm"
            )
            # Tag each issue with the service name
            for issue in svc_issues:
                issue.component = f"swarm/{svc_name}"
            issues.extend(svc_issues)

        return issues

    # ------------------------------------------------------------------
    # Context builder — per-service
    # ------------------------------------------------------------------

    def _build_service_context(
        self,
        svc_name: str,
        svc_config: Dict[str, Any],
        top_level_networks: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Build a context dict for a single Swarm service."""

        deploy = svc_config.get("deploy", {}) or {}
        resources = deploy.get("resources", {}) or {}
        restart_policy = deploy.get("restart_policy", {}) or {}
        placement = deploy.get("placement", {}) or {}
        update_config = deploy.get("update_config", {}) or {}

        image = svc_config.get("image", "")

        # Environment variables
        env_vars: List[str] = []
        env_section = svc_config.get("environment", {})
        if isinstance(env_section, dict):
            for key, value in env_section.items():
                env_vars.append(f"{key}={value}")
        elif isinstance(env_section, list):
            env_vars = list(env_section)

        # Secrets — check if service uses docker secrets mechanism
        uses_secrets = bool(svc_config.get("secrets"))

        # Networks — determine if service uses explicitly defined overlay networks
        svc_networks = svc_config.get("networks", [])
        uses_explicit_network = False
        if isinstance(svc_networks, list) and svc_networks:
            # Check each referenced network is defined at top level
            for net in svc_networks:
                if net in (top_level_networks or {}):
                    uses_explicit_network = True
                    break
        elif isinstance(svc_networks, dict) and svc_networks:
            for net in svc_networks.keys():
                if net in (top_level_networks or {}):
                    uses_explicit_network = True
                    break

        # Healthcheck
        has_healthcheck = bool(svc_config.get("healthcheck"))

        # SW-011: Logging configuration
        has_logging = bool(svc_config.get("logging"))

        # SW-012: Privileged mode
        privileged = svc_config.get("privileged", False)

        # Deploy mode
        deploy_mode = deploy.get("mode", "replicated")

        return {
            "component": "swarm",
            "base_image": image,
            # Replicas
            "has_replicas": "replicas" in deploy,
            "replicas": deploy.get("replicas", 0),
            # Resource limits
            "has_resource_limits": bool(resources.get("limits")),
            "has_resource_reservations": bool(resources.get("reservations")),
            # Restart policy
            "has_restart_policy": bool(restart_policy),
            "restart_max_attempts": restart_policy.get("max_attempts"),
            # Placement constraints
            "has_placement_constraints": bool(placement.get("constraints")),
            # Update config
            "has_update_config": bool(update_config),
            # Secrets
            "env_vars": env_vars,
            "uses_secrets": uses_secrets,
            # Network
            "uses_explicit_network": uses_explicit_network,
            # Healthcheck
            "has_healthcheck": has_healthcheck,
            # Logging
            "has_logging": has_logging,
            # Deploy mode
            "deploy_mode": deploy_mode,
            # User
            "user": str(svc_config.get("user", "")).strip() or "root",
            # Privileged
            "privileged": privileged,
        }
