"""
core/rules_engine.py — Loads analysis rules and evaluates them against a context.

Rules are stored in a JSON file (default: rules/default_rules.json).
Each rule has a 'check' identifier that maps to an evaluator function defined
in this module.  The engine is intentionally kept simple: no plugin system,
no external DSL — just plain Python functions keyed by check name.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional

from models.issue import Issue

# ---------------------------------------------------------------------------
# Type alias
# ---------------------------------------------------------------------------
CheckFn = Callable[[Dict[str, Any]], bool]

# ---------------------------------------------------------------------------
# Check implementations
# Signature: (context: dict) -> bool   (True = rule fires = issue created)
# ---------------------------------------------------------------------------


def _safe_check(fn: CheckFn) -> CheckFn:
    """Decorator: silently returns False if ctx is not a dict."""

    def wrapper(ctx: Dict[str, Any]) -> bool:
        if not isinstance(ctx, dict):
            return False
        return fn(ctx)

    wrapper.__name__ = fn.__name__
    wrapper.__doc__ = fn.__doc__
    return wrapper


@_safe_check
def _base_image_unversioned(ctx: Dict[str, Any]) -> bool:
    base = ctx.get("base_image", "")
    if not base:
        return True
    if ":" not in base:
        return True
    tag = base.split(":")[-1]
    return tag.lower() == "latest"


@_safe_check
def _running_as_root(ctx: Dict[str, Any]) -> bool:
    user = ctx.get("user", "").strip().lower()
    # Explicitly check for root/0 OR check if no USER was defined (implicitly root)
    if user in ("root", "0"):
        return True
    if not ctx.get("user_is_explicit", True) and user == "root":
        # This handles the case where the context builder defaulted to 'root'
        return True
    return False


@_safe_check
def _multiple_run_instructions(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("multiple_run", False))


@_safe_check
def _add_instead_of_copy(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("has_add", False))


@_safe_check
def _missing_workdir(ctx: Dict[str, Any]) -> bool:
    return not ctx.get("has_workdir", False)


@_safe_check
def _apt_get_split(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("apt_get_split", False))


@_safe_check
def _missing_healthcheck_dockerfile(ctx: Dict[str, Any]) -> bool:
    """DF-007: No HEALTHCHECK instruction in Dockerfile. Source: IBM."""
    return not ctx.get("has_healthcheck", False)


@_safe_check
def _apt_get_no_recommends(ctx: Dict[str, Any]) -> bool:
    """DF-008: apt-get install without --no-install-recommends. Source: Medium/0xfujin."""
    return bool(ctx.get("apt_get_missing_no_recommends", False))


@_safe_check
def _pip_no_cache_dir(ctx: Dict[str, Any]) -> bool:
    """DF-009: pip install without --no-cache-dir. Source: Medium/0xfujin."""
    return bool(ctx.get("pip_missing_no_cache_dir", False))


@_safe_check
def _missing_labels(ctx: Dict[str, Any]) -> bool:
    labels = ctx.get("labels", {})
    return not labels


@_safe_check
def _sensitive_env_vars(ctx: Dict[str, Any]) -> bool:
    sensitive_keywords = {
        "password",
        "passwd",
        "secret",
        "api_key",
        "token",
        "private_key",
    }
    for env in ctx.get("env_vars", []):
        key = env.split("=")[0].lower()
        # Skip Docker secrets file references (e.g. POSTGRES_PASSWORD_FILE)
        if key.endswith("_file"):
            continue
        if any(kw in key for kw in sensitive_keywords):
            return True
    return False


@_safe_check
def _excessive_layers(ctx: Dict[str, Any]) -> bool:
    return ctx.get("num_layers", 0) > 20


@_safe_check
def _image_running_as_root(ctx: Dict[str, Any]) -> bool:
    return _running_as_root(ctx)


@_safe_check
def _image_base_unversioned(ctx: Dict[str, Any]) -> bool:
    return _base_image_unversioned(ctx)


@_safe_check
def _compose_image_unversioned(ctx: Dict[str, Any]) -> bool:
    return _base_image_unversioned(ctx)


@_safe_check
def _compose_root_user(ctx: Dict[str, Any]) -> bool:
    return _running_as_root(ctx)


@_safe_check
def _compose_sensitive_env(ctx: Dict[str, Any]) -> bool:
    return _sensitive_env_vars(ctx)


@_safe_check
def _compose_exposed_ports(ctx: Dict[str, Any]) -> bool:
    sensitive_ports = {"22", "23", "3389", "5900"}
    for port in ctx.get("ports", []):
        port_str = str(port)
        if "0.0.0.0" in port_str:
            return True
        # Extract host port
        parts = port_str.split(":")
        host_port = parts[-2] if len(parts) >= 2 else parts[0]
        if host_port.strip() in sensitive_ports:
            return True
    return False


@_safe_check
def _compose_duplicate_images(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("has_duplicate_images", False))


@_safe_check
def _compose_privileged_mode(ctx: Dict[str, Any]) -> bool:
    """DC-006: Container runs in privileged mode. Source: IBM."""
    return bool(ctx.get("privileged", False))


@_safe_check
def _compose_volume_not_readonly(ctx: Dict[str, Any]) -> bool:
    """DC-007: Volume not mounted as read-only. Source: IBM."""
    return bool(ctx.get("has_writable_volumes", False))


# --- Swarm checks -----------------------------------------------------------


@_safe_check
def _swarm_missing_replicas(ctx: Dict[str, Any]) -> bool:
    return not ctx.get("has_replicas", False)


@_safe_check
def _swarm_no_resource_limits(ctx: Dict[str, Any]) -> bool:
    return not ctx.get("has_resource_limits", False)


@_safe_check
def _swarm_no_resource_reservations(ctx: Dict[str, Any]) -> bool:
    return not ctx.get("has_resource_reservations", False)


@_safe_check
def _swarm_no_restart_policy(ctx: Dict[str, Any]) -> bool:
    if not ctx.get("has_restart_policy", False):
        return True
    # Also flag if max_attempts is not set (unbounded retries)
    return ctx.get("restart_max_attempts") is None


@_safe_check
def _swarm_no_placement_constraints(ctx: Dict[str, Any]) -> bool:
    return not ctx.get("has_placement_constraints", False)


@_safe_check
def _swarm_no_update_config(ctx: Dict[str, Any]) -> bool:
    return not ctx.get("has_update_config", False)


@_safe_check
def _swarm_secrets_in_env(ctx: Dict[str, Any]) -> bool:
    """Flag if sensitive data is in env vars instead of Docker secrets."""
    return _sensitive_env_vars(ctx)


@_safe_check
def _swarm_image_unversioned(ctx: Dict[str, Any]) -> bool:
    return _base_image_unversioned(ctx)


@_safe_check
def _swarm_default_network(ctx: Dict[str, Any]) -> bool:
    return not ctx.get("uses_explicit_network", False)


@_safe_check
def _swarm_no_healthcheck(ctx: Dict[str, Any]) -> bool:
    return not ctx.get("has_healthcheck", False)


@_safe_check
def _swarm_no_logging(ctx: Dict[str, Any]) -> bool:
    """SW-011: No logging configuration. Source: AccuWeb, IBM."""
    return not ctx.get("has_logging", False)


@_safe_check
def _swarm_privileged_mode(ctx: Dict[str, Any]) -> bool:
    """SW-012: Service runs in privileged mode. Source: IBM."""
    return bool(ctx.get("privileged", False))


# ---------------------------------------------------------------------------
# Registry: check name → evaluator function
# ---------------------------------------------------------------------------

_CHECK_REGISTRY: Dict[str, CheckFn] = {
    "base_image_unversioned": _base_image_unversioned,
    "running_as_root": _running_as_root,
    "multiple_run_instructions": _multiple_run_instructions,
    "add_instead_of_copy": _add_instead_of_copy,
    "missing_workdir": _missing_workdir,
    "apt_get_split": _apt_get_split,
    "missing_healthcheck": _missing_healthcheck_dockerfile,
    "apt_get_no_recommends": _apt_get_no_recommends,
    "pip_no_cache_dir": _pip_no_cache_dir,
    "missing_labels": _missing_labels,
    "sensitive_env_vars": _sensitive_env_vars,
    "excessive_layers": _excessive_layers,
    "image_running_as_root": _image_running_as_root,
    "image_base_unversioned": _image_base_unversioned,
    "compose_image_unversioned": _compose_image_unversioned,
    "compose_root_user": _compose_root_user,
    "compose_sensitive_env": _compose_sensitive_env,
    "compose_exposed_ports": _compose_exposed_ports,
    "compose_duplicate_images": _compose_duplicate_images,
    "compose_privileged_mode": _compose_privileged_mode,
    "compose_volume_not_readonly": _compose_volume_not_readonly,
    # Swarm checks
    "swarm_missing_replicas": _swarm_missing_replicas,
    "swarm_no_resource_limits": _swarm_no_resource_limits,
    "swarm_no_resource_reservations": _swarm_no_resource_reservations,
    "swarm_no_restart_policy": _swarm_no_restart_policy,
    "swarm_no_placement_constraints": _swarm_no_placement_constraints,
    "swarm_no_update_config": _swarm_no_update_config,
    "swarm_secrets_in_env": _swarm_secrets_in_env,
    "swarm_image_unversioned": _swarm_image_unversioned,
    "swarm_default_network": _swarm_default_network,
    "swarm_no_healthcheck": _swarm_no_healthcheck,
    "swarm_no_logging": _swarm_no_logging,
    "swarm_privileged_mode": _swarm_privileged_mode,
}


# ---------------------------------------------------------------------------
# RulesEngine
# ---------------------------------------------------------------------------


class RulesEngine:
    """
    Loads a rules JSON file and evaluates individual rules against a context dict.

    Usage::

        engine = RulesEngine("rules/default_rules.json")
        engine.load_rules()
        issues = engine.evaluate("DF-001", {"base_image": "ubuntu:latest"})
    """

    def __init__(self, rules_path: str) -> None:
        self._rules_path = rules_path
        self._rules: List[Dict[str, Any]] = []
        self._rules_by_id: Dict[str, Dict[str, Any]] = {}

    # ------------------------------------------------------------------

    def load_rules(self) -> List[Dict[str, Any]]:
        """
        Load and parse the rules JSON file.

        Returns:
            list of rule dicts.

        Raises:
            IOError: if the rules file cannot be read.
            json.JSONDecodeError: if the file is not valid JSON.
        """
        try:
            with open(self._rules_path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError) as e:
            # Re-raise with a more descriptive message that Analyzers can catch
            raise IOError(f"Failed to load rules from {self._rules_path}: {e}") from e

        self._rules = data.get("rules", [])
        self._rules_by_id = {r["id"]: r for r in self._rules}
        return self._rules

    # ------------------------------------------------------------------

    def evaluate(self, rule_id: str, context: Dict[str, Any]) -> List[Issue]:
        """
        Evaluate a single rule against *context*.

        Returns a list containing one Issue if the rule fires, or an empty list.
        """
        # Defensive type guards (discovered via Deep Chaos Monte Carlo)
        if not isinstance(rule_id, str):
            return []
        if not isinstance(context, dict):
            return []

        rule = self._rules_by_id.get(rule_id)
        if rule is None:
            return []

        check_fn = _CHECK_REGISTRY.get(rule["check"])
        if check_fn is None:
            return []

        if check_fn(context):
            return [
                Issue(
                    id=rule["id"],
                    description=rule["description"],
                    severity=rule["severity"],
                    component=context.get(
                        "component", rule.get("component", "unknown")
                    ),
                    recommendation=rule["recommendation"],
                )
            ]
        return []

    def evaluate_all(
        self,
        context: Dict[str, Any],
        component_filter: Optional[str] = None,
    ) -> List[Issue]:
        """
        Evaluate all loaded rules against *context*.

        Args:
            context:          dict passed to each check function.
            component_filter: if given, only rules matching this component are run.

        Returns:
            list of Issue objects for every rule that fired.
        """
        issues: List[Issue] = []
        for rule in self._rules:
            if component_filter and rule.get("component") != component_filter:
                continue
            issues.extend(self.evaluate(rule["id"], context))
        return issues

    @property
    def rules(self) -> List[Dict[str, Any]]:
        return list(self._rules)
