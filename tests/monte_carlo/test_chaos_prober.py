"""
Deep Chaos Monte Carlo Prober
=============================
Injects truly chaotic data (None, int, list, bytes, nested garbage) into
every rule evaluator and core function. NO safety guards — if the code
can't handle it, the test fails and we harden the source.
"""

from unittest.mock import MagicMock

import pytest

from core.analyzer import Analyzer
from core.config import Config
from core.rules_engine import _CHECK_REGISTRY, RulesEngine
from models.issue import Issue
from tests.utils.fuzz_data import get_hybrid_param, random_garbage, random_string

# ======================================================================
# 1. Individual Rule Evaluator Probing — NO TYPE GUARDS
# ======================================================================


@pytest.mark.parametrize("rule_name,evaluator_fn", list(_CHECK_REGISTRY.items()))
def test_deep_chaos_evaluator(rule_name, evaluator_fn):
    """
    Pass raw garbage directly into each rule evaluator.
    No isinstance() checks. If the code crashes on None/int/list, GOOD —
    we found a bug to fix.
    """
    for _ in range(10000):
        # 50% valid context, 50% pure garbage (could be None, int, list, etc.)
        ctx = get_hybrid_param(
            {
                "base_image": "ubuntu:latest",
                "user": "root",
                "has_healthcheck": False,
                "env_vars": ["PATH=/usr/bin"],
                "ports": ["8080:8080"],
                "has_add": True,
                "has_workdir": False,
                "multiple_run": True,
                "apt_get_split": True,
                "labels": {},
                "num_layers": 25,
                "has_replicas": False,
                "has_resource_limits": False,
                "has_resource_reservations": False,
                "restart_policy": None,
                "restart_max_attempts": None,
                "has_placement_constraints": False,
                "has_update_config": False,
                "uses_docker_secrets": False,
                "uses_explicit_network": False,
                "has_logging": False,
                "is_privileged": True,
                "volumes": [],
                "services": {},
                "apt_get_missing_no_recommends": True,
                "pip_missing_no_cache_dir": True,
                "secrets_file_path": None,
            },
            lambda: random_garbage(depth=3),
        )
        # DO NOT sanitize ctx — let it crash
        try:
            evaluator_fn(ctx)
        except (TypeError, AttributeError, KeyError, ValueError) as e:
            pytest.fail(
                f"CRASH in '{rule_name}': {type(e).__name__}: {e}\n"
                f"  Input type: {type(ctx).__name__}\n"
                f"  Input preview: {repr(ctx)[:300]}"
            )


# ======================================================================
# 2. RulesEngine.evaluate() — garbage rule_ids and contexts
# ======================================================================


def test_deep_chaos_rules_engine_evaluate():
    """Test deep chaos rules engine evaluate."""
    engine = RulesEngine("rules/default_rules.json")
    engine.load_rules()
    for _ in range(10000):
        rule_id = get_hybrid_param("DF-001", lambda: random_garbage(depth=1))
        ctx = get_hybrid_param(
            {"base_image": "x", "user": "root"},
            lambda: random_garbage(depth=3),
        )
        try:
            engine.evaluate(rule_id, ctx)
        except (TypeError, AttributeError, KeyError, ValueError) as e:
            pytest.fail(
                f"RulesEngine.evaluate CRASH: {type(e).__name__}: {e}\n"
                f"  rule_id={repr(rule_id)}, ctx_type={type(ctx).__name__}"
            )


# ======================================================================
# 3. Config — garbage options
# ======================================================================


def test_deep_chaos_config():
    """Test deep chaos config."""
    for _ in range(10000):
        opts = get_hybrid_param(
            {"command": "all", "severity": "critical"},
            lambda: random_garbage(depth=2),
        )
        try:
            config = Config(opts)
            config.get_option(random_garbage(depth=0), random_garbage(depth=0))
            config.severity_passes(random_garbage(depth=0))
        except (TypeError, AttributeError, KeyError, ValueError) as e:
            pytest.fail(
                f"Config CRASH: {type(e).__name__}: {e}\n"
                f"  Input: {repr(opts)[:300]}"
            )


# ======================================================================
# 4. Analyzer._validate_path — garbage paths
# ======================================================================


def test_deep_chaos_analyzer_validate_path():
    """Test deep chaos analyzer validate path."""
    args = MagicMock()
    for _ in range(10000):
        args.command = get_hybrid_param("dockerfile", lambda: random_garbage(depth=0))
        args.dockerfile_path = get_hybrid_param(
            "Dockerfile", lambda: random_garbage(depth=1)
        )
        try:
            config = Config.from_cli(args)
            analyzer = Analyzer(config)
            analyzer._validate_path(
                get_hybrid_param("Dockerfile", lambda: random_garbage(depth=1)),
                get_hybrid_param("test", lambda: random_garbage(depth=0)),
            )
        except (TypeError, AttributeError, KeyError, ValueError) as e:
            pytest.fail(
                f"Analyzer._validate_path CRASH: {type(e).__name__}: {e}\n"
                f"  path={repr(args.dockerfile_path)[:200]}"
            )


# ======================================================================
# 5. Issue model — garbage constructor args
# ======================================================================


def test_deep_chaos_issue_model():
    """Test deep chaos issue model."""
    for _ in range(10000):
        p = {
            "id": random_garbage(depth=0),
            "description": random_garbage(depth=0),
            "severity": random_garbage(depth=0),
            "component": random_garbage(depth=0),
            "recommendation": random_garbage(depth=0),
        }
        try:
            Issue(**p)
        except (ValueError, TypeError):
            pass  # Expected — Issue may validate types
        except Exception as e:
            pytest.fail(
                f"Issue UNEXPECTED CRASH: {type(e).__name__}: {e}\n"
                f"  Input: {repr(p)[:300]}"
            )
