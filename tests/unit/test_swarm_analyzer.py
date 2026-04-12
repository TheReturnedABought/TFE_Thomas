"""
tests/unit/test_swarm_analyzer.py

Unit tests for analyzers/swarm_analyzer.py — SwarmAnalyzer.

Covers all 10 Swarm rules (SW-001 … SW-010):
    - SW-001: Missing replica count
    - SW-002: No resource limits
    - SW-003: No resource reservations
    - SW-004: No restart policy (or unbounded max_attempts)
    - SW-005: No placement constraints
    - SW-006: No update_config
    - SW-007: Sensitive data in env vars instead of secrets
    - SW-008: Unversioned / :latest image
    - SW-009: Default network instead of explicit overlay
    - SW-010: No healthcheck
    - Clean stack producing zero issues
"""

import pytest
from unittest.mock import patch

from tests.conftest import smart_mock_open


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def make_swarm_analyzer(content: str):
    """Instantiate SwarmAnalyzer by patching file I/O."""
    from analyzers.swarm_analyzer import SwarmAnalyzer
    with patch("builtins.open", side_effect=smart_mock_open("docker-stack.yml", content)):
        analyzer = SwarmAnalyzer("docker-stack.yml")
    return analyzer


# ---------------------------------------------------------------------------
# SW-001: Missing replicas
# ---------------------------------------------------------------------------

class TestMissingReplicas:

    def test_no_replicas_raises_issue(self, swarm_bad):
        analyzer = make_swarm_analyzer(swarm_bad)
        issues = analyzer.detect_bad_practices()
        assert any(i.id == "SW-001" for i in issues), \
            "Expected SW-001 for missing replicas"

    def test_replicas_defined_no_issue(self, swarm_good):
        analyzer = make_swarm_analyzer(swarm_good)
        issues = analyzer.detect_bad_practices()
        assert not any(i.id == "SW-001" for i in issues)


# ---------------------------------------------------------------------------
# SW-002: No resource limits
# ---------------------------------------------------------------------------

class TestNoResourceLimits:

    def test_no_resource_limits_raises_issue(self, swarm_bad):
        analyzer = make_swarm_analyzer(swarm_bad)
        issues = analyzer.detect_bad_practices()
        assert any(i.id == "SW-002" for i in issues), \
            "Expected SW-002 for missing resource limits"

    def test_resource_limits_defined_no_issue(self, swarm_good):
        analyzer = make_swarm_analyzer(swarm_good)
        issues = analyzer.detect_bad_practices()
        assert not any(i.id == "SW-002" for i in issues)


# ---------------------------------------------------------------------------
# SW-003: No resource reservations
# ---------------------------------------------------------------------------

class TestNoResourceReservations:

    def test_no_reservations_raises_issue(self, swarm_bad):
        analyzer = make_swarm_analyzer(swarm_bad)
        issues = analyzer.detect_bad_practices()
        assert any(i.id == "SW-003" for i in issues)

    def test_reservations_defined_no_issue(self, swarm_good):
        analyzer = make_swarm_analyzer(swarm_good)
        issues = analyzer.detect_bad_practices()
        assert not any(i.id == "SW-003" for i in issues)


# ---------------------------------------------------------------------------
# SW-004: No restart policy
# ---------------------------------------------------------------------------

class TestNoRestartPolicy:

    def test_no_restart_policy_raises_issue(self, swarm_bad):
        analyzer = make_swarm_analyzer(swarm_bad)
        issues = analyzer.detect_bad_practices()
        assert any(i.id == "SW-004" for i in issues), \
            "Expected SW-004 for missing restart policy"

    def test_restart_policy_with_max_attempts_no_issue(self, swarm_good):
        analyzer = make_swarm_analyzer(swarm_good)
        issues = analyzer.detect_bad_practices()
        assert not any(i.id == "SW-004" for i in issues)

    def test_restart_policy_without_max_attempts_raises_issue(self):
        content = (
            "version: '3.8'\n"
            "services:\n"
            "  web:\n"
            "    image: nginx:1.25\n"
            "    deploy:\n"
            "      replicas: 1\n"
            "      restart_policy:\n"
            "        condition: on-failure\n"
        )
        analyzer = make_swarm_analyzer(content)
        issues = analyzer.detect_bad_practices()
        assert any(i.id == "SW-004" for i in issues), \
            "Expected SW-004 when restart_policy has no max_attempts"


# ---------------------------------------------------------------------------
# SW-005: No placement constraints
# ---------------------------------------------------------------------------

class TestNoPlacementConstraints:

    def test_no_placement_raises_issue(self, swarm_bad):
        analyzer = make_swarm_analyzer(swarm_bad)
        issues = analyzer.detect_bad_practices()
        assert any(i.id == "SW-005" for i in issues)

    def test_placement_defined_no_issue(self, swarm_good):
        analyzer = make_swarm_analyzer(swarm_good)
        issues = analyzer.detect_bad_practices()
        assert not any(i.id == "SW-005" for i in issues)


# ---------------------------------------------------------------------------
# SW-006: No update_config
# ---------------------------------------------------------------------------

class TestNoUpdateConfig:

    def test_no_update_config_raises_issue(self, swarm_bad):
        analyzer = make_swarm_analyzer(swarm_bad)
        issues = analyzer.detect_bad_practices()
        assert any(i.id == "SW-006" for i in issues)

    def test_update_config_defined_no_issue(self, swarm_good):
        analyzer = make_swarm_analyzer(swarm_good)
        issues = analyzer.detect_bad_practices()
        assert not any(i.id == "SW-006" for i in issues)


# ---------------------------------------------------------------------------
# SW-007: Sensitive data in env vars
# ---------------------------------------------------------------------------

class TestSecretsInEnv:

    def test_password_in_env_raises_issue(self, swarm_bad):
        analyzer = make_swarm_analyzer(swarm_bad)
        issues = analyzer.detect_bad_practices()
        assert any(i.id == "SW-007" for i in issues), \
            "Expected SW-007 for secrets in environment variables"

    def test_no_sensitive_env_no_issue(self, swarm_good):
        analyzer = make_swarm_analyzer(swarm_good)
        issues = analyzer.detect_bad_practices()
        assert not any(i.id == "SW-007" for i in issues)


# ---------------------------------------------------------------------------
# SW-008: Unversioned image
# ---------------------------------------------------------------------------

class TestSwarmImageVersioning:

    def test_latest_image_raises_issue(self, swarm_bad):
        analyzer = make_swarm_analyzer(swarm_bad)
        issues = analyzer.detect_bad_practices()
        assert any(i.id == "SW-008" for i in issues), \
            "Expected SW-008 for :latest image"

    def test_pinned_image_no_issue(self, swarm_good):
        analyzer = make_swarm_analyzer(swarm_good)
        issues = analyzer.detect_bad_practices()
        assert not any(i.id == "SW-008" for i in issues)


# ---------------------------------------------------------------------------
# SW-009: Default network
# ---------------------------------------------------------------------------

class TestSwarmDefaultNetwork:

    def test_no_explicit_network_raises_issue(self, swarm_bad):
        analyzer = make_swarm_analyzer(swarm_bad)
        issues = analyzer.detect_bad_practices()
        assert any(i.id == "SW-009" for i in issues), \
            "Expected SW-009 for default network usage"

    def test_explicit_overlay_network_no_issue(self, swarm_good):
        analyzer = make_swarm_analyzer(swarm_good)
        issues = analyzer.detect_bad_practices()
        assert not any(i.id == "SW-009" for i in issues)


# ---------------------------------------------------------------------------
# SW-010: No healthcheck
# ---------------------------------------------------------------------------

class TestSwarmNoHealthcheck:

    def test_no_healthcheck_raises_issue(self, swarm_bad):
        analyzer = make_swarm_analyzer(swarm_bad)
        issues = analyzer.detect_bad_practices()
        assert any(i.id == "SW-010" for i in issues), \
            "Expected SW-010 for missing healthcheck"

    def test_healthcheck_defined_no_issue(self, swarm_good):
        analyzer = make_swarm_analyzer(swarm_good)
        issues = analyzer.detect_bad_practices()
        assert not any(i.id == "SW-010" for i in issues)


# ---------------------------------------------------------------------------
# Clean stack — zero issues
# ---------------------------------------------------------------------------

class TestCleanSwarmStack:

    def test_clean_stack_returns_no_issues(self, swarm_good):
        analyzer = make_swarm_analyzer(swarm_good)
        issues = analyzer.detect_bad_practices()
        assert len(issues) == 0, \
            f"Expected zero issues for clean stack, got {len(issues)}: {[i.id for i in issues]}"

    def test_bad_stack_returns_multiple_issues(self, swarm_bad):
        analyzer = make_swarm_analyzer(swarm_bad)
        issues = analyzer.detect_bad_practices()
        # swarm_bad should trigger at least 8 of the 10 rules
        assert len(issues) >= 8, \
            f"Expected at least 8 issues for bad stack, got {len(issues)}: {[i.id for i in issues]}"

    def test_issues_have_valid_severity(self, swarm_bad):
        analyzer = make_swarm_analyzer(swarm_bad)
        issues = analyzer.detect_bad_practices()
        valid = {"low", "medium", "critical"}
        for issue in issues:
            assert issue.severity in valid, f"Invalid severity: {issue.severity}"

    def test_issues_have_swarm_component(self, swarm_bad):
        analyzer = make_swarm_analyzer(swarm_bad)
        issues = analyzer.detect_bad_practices()
        for issue in issues:
            assert "swarm" in issue.component, \
                f"Issue {issue.id} component should contain 'swarm', got '{issue.component}'"

    def test_partial_stack_has_some_issues(self, swarm_partial):
        analyzer = make_swarm_analyzer(swarm_partial)
        issues = analyzer.detect_bad_practices()
        # swarm_partial has update_config missing, placement missing, healthcheck missing, no max_attempts
        assert len(issues) > 0, "Expected some issues for partial stack"
        # But not all 10
        assert len(issues) < 10, "Partial stack should not trigger all 10 rules"
