"""
tests/unit/test_compose_analyzer.py

Unit tests for analyzers/compose_analyzer.py — ComposeAnalyzer.

Covers:
    - analyze_services() — returns a list of service names
    - check_security_rules() — unversioned image tags (latest / no tag)
    - check_security_rules() — root user or missing USER per service
    - check_security_rules() — sensitive environment variables
    - check_security_rules() — unnecessary exposed ports
    - detect_redundancies() — duplicate or unused service detection
    - Clean compose file producing zero issues
    - Issue structure validation
"""

import pytest
from unittest.mock import patch, mock_open, MagicMock
import yaml
import io

from tests.conftest import smart_mock_open


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def make_compose_analyzer(content: str):
    """Instantiate ComposeAnalyzer by patching file I/O."""
    from analyzers.compose_analyzer import ComposeAnalyzer
    with patch("builtins.open", side_effect=smart_mock_open("docker-compose.yml", content)):
        analyzer = ComposeAnalyzer("docker-compose.yml")
    return analyzer


# ---------------------------------------------------------------------------
# analyze_services
# ---------------------------------------------------------------------------

class TestAnalyzeServices:

    def test_returns_correct_service_names(self, compose_good):
        analyzer = make_compose_analyzer(compose_good)
        services = analyzer.analyze_services()
        assert set(services) == {"web", "db"}

    def test_returns_list(self, compose_good):
        analyzer = make_compose_analyzer(compose_good)
        assert isinstance(analyzer.analyze_services(), list)

    def test_empty_services_returns_empty_list(self):
        content = "version: '3.8'\nservices: {}\n"
        analyzer = make_compose_analyzer(content)
        assert analyzer.analyze_services() == []

    def test_single_service_detected(self, compose_bad_root):
        analyzer = make_compose_analyzer(compose_bad_root)
        services = analyzer.analyze_services()
        assert len(services) == 1
        assert "app" in services


# ---------------------------------------------------------------------------
# check_security_rules — image versioning
# ---------------------------------------------------------------------------

class TestImageVersioning:

    def test_latest_tag_raises_issue(self, compose_bad_latest):
        analyzer = make_compose_analyzer(compose_bad_latest)
        issues = analyzer.check_security_rules()
        assert any("latest" in i.description.lower() or "tag" in i.description.lower()
                   for i in issues), "Expected versioning issue for :latest image tag"

    def test_image_without_tag_raises_issue(self, compose_bad_latest):
        # "postgres" with no tag in compose_bad_latest
        analyzer = make_compose_analyzer(compose_bad_latest)
        issues = analyzer.check_security_rules()
        descriptions = [i.description.lower() for i in issues]
        assert any("tag" in d or "version" in d for d in descriptions)

    def test_pinned_version_no_tag_issue(self, compose_good):
        analyzer = make_compose_analyzer(compose_good)
        issues = analyzer.check_security_rules()
        tag_issues = [i for i in issues
                      if "latest" in i.description.lower() or "unversioned" in i.description.lower()]
        assert len(tag_issues) == 0


# ---------------------------------------------------------------------------
# check_security_rules — user / root
# ---------------------------------------------------------------------------

class TestUserRootCompose:

    def test_root_user_raises_critical_issue(self, compose_bad_root):
        analyzer = make_compose_analyzer(compose_bad_root)
        issues = analyzer.check_security_rules()
        assert any(i.severity == "critical" and "root" in i.description.lower()
                   for i in issues), "Expected a critical issue for root user"

    def test_missing_user_raises_issue(self, compose_missing_user):
        analyzer = make_compose_analyzer(compose_missing_user)
        issues = analyzer.check_security_rules()
        assert any("user" in i.description.lower() for i in issues), \
            "Expected an issue when 'user' key is absent from a service"

    def test_valid_non_root_user_no_issue(self, compose_good):
        analyzer = make_compose_analyzer(compose_good)
        issues = analyzer.check_security_rules()
        root_issues = [i for i in issues if "root" in i.description.lower()]
        assert len(root_issues) == 0


# ---------------------------------------------------------------------------
# check_security_rules — sensitive environment variables
# ---------------------------------------------------------------------------

class TestSensitiveEnvVars:

    def test_plaintext_password_raises_issue(self, compose_bad_latest):
        # compose_bad_latest has POSTGRES_PASSWORD: supersecret
        analyzer = make_compose_analyzer(compose_bad_latest)
        issues = analyzer.check_security_rules()
        assert any(
            "password" in i.description.lower()
            or "secret" in i.description.lower()
            or "env" in i.description.lower()
            for i in issues
        ), "Expected an issue for plaintext password in environment variables"

    def test_secret_file_reference_no_issue(self, compose_good):
        # compose_good uses POSTGRES_PASSWORD_FILE (safe pattern)
        analyzer = make_compose_analyzer(compose_good)
        issues = analyzer.check_security_rules()
        secret_issues = [
            i for i in issues
            if "password" in i.description.lower() and i.severity == "critical"
        ]
        assert len(secret_issues) == 0

    def test_sensitive_key_names_detected(self):
        content = (
            "version: '3.8'\n"
            "services:\n"
            "  app:\n"
            "    image: myapp:1.0\n"
            "    user: '1000'\n"
            "    environment:\n"
            "      API_SECRET: abc123\n"
            "      JWT_SECRET_KEY: supersecret\n"
        )
        analyzer = make_compose_analyzer(content)
        issues = analyzer.check_security_rules()
        assert any("secret" in i.description.lower() or "env" in i.description.lower()
                   for i in issues)


# ---------------------------------------------------------------------------
# check_security_rules — exposed ports
# ---------------------------------------------------------------------------

class TestExposedPorts:

    def test_all_interfaces_port_raises_issue(self, compose_bad_root):
        # compose_bad_root exposes 0.0.0.0:22:22
        analyzer = make_compose_analyzer(compose_bad_root)
        issues = analyzer.check_security_rules()
        assert any(
            "port" in i.description.lower() or "0.0.0.0" in i.description
            for i in issues
        ), "Expected an issue for port exposed on all interfaces"

    def test_restricted_port_no_issue(self, compose_good):
        analyzer = make_compose_analyzer(compose_good)
        issues = analyzer.check_security_rules()
        port_issues = [i for i in issues if "0.0.0.0" in i.description]
        assert len(port_issues) == 0

    def test_sensitive_port_22_raises_issue(self):
        content = (
            "version: '3.8'\n"
            "services:\n"
            "  sshd:\n"
            "    image: myapp:1.0\n"
            "    user: '1000'\n"
            "    ports:\n"
            "      - '22:22'\n"
        )
        analyzer = make_compose_analyzer(content)
        issues = analyzer.check_security_rules()
        assert any("22" in i.description or "port" in i.description.lower()
                   for i in issues)


# ---------------------------------------------------------------------------
# detect_redundancies
# ---------------------------------------------------------------------------

class TestDetectRedundancies:

    def test_no_redundancy_in_clean_compose(self, compose_good):
        analyzer = make_compose_analyzer(compose_good)
        issues = analyzer.detect_redundancies()
        assert isinstance(issues, list)

    def test_duplicate_image_detected(self):
        content = (
            "version: '3.8'\n"
            "services:\n"
            "  web1:\n"
            "    image: nginx:1.25\n"
            "    user: '1000'\n"
            "  web2:\n"
            "    image: nginx:1.25\n"
            "    user: '1000'\n"
        )
        analyzer = make_compose_analyzer(content)
        issues = analyzer.detect_redundancies()
        assert any("duplicate" in i.description.lower() or "redund" in i.description.lower()
                   for i in issues), "Expected a redundancy issue for duplicate images"


# ---------------------------------------------------------------------------
# Clean compose — zero issues
# ---------------------------------------------------------------------------

class TestCleanCompose:

    def test_clean_compose_returns_no_issues(self, compose_good):
        analyzer = make_compose_analyzer(compose_good)
        security_issues = analyzer.check_security_rules()
        redundancy_issues = analyzer.detect_redundancies()
        all_issues = security_issues + redundancy_issues
        assert len(all_issues) == 0

    def test_issue_objects_have_required_attributes(self, compose_bad_latest):
        analyzer = make_compose_analyzer(compose_bad_latest)
        issues = analyzer.check_security_rules()
        assert len(issues) > 0
        for issue in issues:
            assert hasattr(issue, "id")
            assert hasattr(issue, "severity")
            assert hasattr(issue, "description")
            assert hasattr(issue, "recommendation")
            assert hasattr(issue, "component")

    def test_severity_values_are_valid(self, compose_bad_latest):
        analyzer = make_compose_analyzer(compose_bad_latest)
        issues = analyzer.check_security_rules()
        valid = {"low", "medium", "critical"}
        for issue in issues:
            assert issue.severity in valid, f"Invalid severity: {issue.severity}"

    def test_component_references_service_name(self, compose_bad_latest):
        analyzer = make_compose_analyzer(compose_bad_latest)
        issues = analyzer.check_security_rules()
        service_names = analyzer.analyze_services()
        for issue in issues:
            assert any(svc in issue.component for svc in service_names), \
                f"Issue component '{issue.component}' does not reference a known service"
