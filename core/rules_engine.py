"""
core/rules_engine.py — Loads analysis rules and evaluates them against a context.

Rules are stored in a JSON file (default: rules/default_rules.json).
Each rule has a 'check' identifier that maps to an evaluator function defined
in this module.  The engine is intentionally kept simple: no plugin system,
no external DSL — just plain Python functions keyed by check name.
"""

from __future__ import annotations

import json
import os
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

def _base_image_unversioned(ctx: Dict[str, Any]) -> bool:
    base = ctx.get("base_image", "")
    if not base:
        return True
    if ":" not in base:
        return True
    tag = base.split(":")[-1]
    return tag.lower() == "latest"


def _running_as_root(ctx: Dict[str, Any]) -> bool:
    user = ctx.get("user", "").strip().lower()
    return user in ("", "root", "0")


def _multiple_run_instructions(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("multiple_run", False))


def _add_instead_of_copy(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("has_add", False))


def _missing_workdir(ctx: Dict[str, Any]) -> bool:
    return not ctx.get("has_workdir", False)


def _apt_get_split(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("apt_get_split", False))


def _missing_labels(ctx: Dict[str, Any]) -> bool:
    labels = ctx.get("labels", {})
    return not labels


def _sensitive_env_vars(ctx: Dict[str, Any]) -> bool:
    sensitive_keywords = {"password", "passwd", "secret", "api_key", "token", "private_key"}
    for env in ctx.get("env_vars", []):
        key = env.split("=")[0].lower()
        if any(kw in key for kw in sensitive_keywords):
            return True
    return False


def _excessive_layers(ctx: Dict[str, Any]) -> bool:
    return ctx.get("num_layers", 0) > 20


def _image_running_as_root(ctx: Dict[str, Any]) -> bool:
    return _running_as_root(ctx)


def _image_base_unversioned(ctx: Dict[str, Any]) -> bool:
    return _base_image_unversioned(ctx)


def _compose_image_unversioned(ctx: Dict[str, Any]) -> bool:
    return _base_image_unversioned(ctx)


def _compose_root_user(ctx: Dict[str, Any]) -> bool:
    return _running_as_root(ctx)


def _compose_sensitive_env(ctx: Dict[str, Any]) -> bool:
    return _sensitive_env_vars(ctx)


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


def _compose_duplicate_images(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("has_duplicate_images", False))


# ---------------------------------------------------------------------------
# Registry: check name → evaluator function
# ---------------------------------------------------------------------------

_CHECK_REGISTRY: Dict[str, CheckFn] = {
    "base_image_unversioned":   _base_image_unversioned,
    "running_as_root":          _running_as_root,
    "multiple_run_instructions": _multiple_run_instructions,
    "add_instead_of_copy":      _add_instead_of_copy,
    "missing_workdir":          _missing_workdir,
    "apt_get_split":            _apt_get_split,
    "missing_labels":           _missing_labels,
    "sensitive_env_vars":       _sensitive_env_vars,
    "excessive_layers":         _excessive_layers,
    "image_running_as_root":    _image_running_as_root,
    "image_base_unversioned":   _image_base_unversioned,
    "compose_image_unversioned": _compose_image_unversioned,
    "compose_root_user":        _compose_root_user,
    "compose_sensitive_env":    _compose_sensitive_env,
    "compose_exposed_ports":    _compose_exposed_ports,
    "compose_duplicate_images": _compose_duplicate_images,
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
            FileNotFoundError: if the rules file does not exist.
            json.JSONDecodeError: if the file is not valid JSON.
        """
        with open(self._rules_path, encoding="utf-8") as fh:
            data = json.load(fh)

        self._rules = data.get("rules", [])
        self._rules_by_id = {r["id"]: r for r in self._rules}
        return self._rules

    # ------------------------------------------------------------------

    def evaluate(self, rule_id: str, context: Dict[str, Any]) -> List[Issue]:
        """
        Evaluate a single rule against *context*.

        Returns a list containing one Issue if the rule fires, or an empty list.
        """
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
                    component=context.get("component", rule.get("component", "unknown")),
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
