import pytest

from analyzers.compose_analyzer import ComposeAnalyzer


class Test_ComposeAnalyzer___init__:
    def test_init_success(self, tmp_path):
        """Test init success."""
        f = tmp_path / "docker-compose.yml"
        f.write_text("version: '3.8'\nservices: {}")
        analyzer = ComposeAnalyzer(str(f))
        assert analyzer._path == str(f)

    def test_init_file_not_found(self):
        """Test init file not found."""
        with pytest.raises(IOError):
            ComposeAnalyzer("/non/existent/compose.yml")


class Test_ComposeAnalyzer_analyze_services:
    def test_happy_path(self, tmp_path):
        """Test happy path."""
        f = tmp_path / "compose.yml"
        f.write_text("services:\n  web:\n    image: nginx")
        analyzer = ComposeAnalyzer(str(f))
        issues = analyzer.check_security_rules()
        # Should catch nginx:latest tag
        assert any(
            "DC-001" in i.id or "compose_image_unversioned" in i.id for i in issues
        )

    def test_analyze_services_empty(self, tmp_path):
        f = tmp_path / "compose.yml"
        f.write_text("services: null")
        analyzer = ComposeAnalyzer(str(f))
        assert analyzer.analyze_services() == []


class Test_ComposeAnalyzer_detect_redundancies:
    def test_duplicate_images(self, tmp_path):
        """Test duplicate images."""
        content = """
services:
  web1:
    image: nginx:1.21
  web2:
    image: nginx:1.21
"""
        f = tmp_path / "compose.yml"
        f.write_text(content)
        analyzer = ComposeAnalyzer(str(f))
        issues = analyzer.detect_redundancies()
        assert any("DC-005" in i.id for i in issues)

    def test_redundancies_invalid_dict(self, tmp_path):
        f = tmp_path / "compose.yml"
        f.write_text("services:\n  web: []")
        analyzer = ComposeAnalyzer(str(f))
        assert analyzer.detect_redundancies() == []


class Test_ComposeAnalyzer__build_service_context:
    def test_build(self, tmp_path):
        """Test build."""
        f = tmp_path / "compose.yml"
        f.write_text("services: {}")
        analyzer = ComposeAnalyzer(str(f))
        svc_config = {
            "image": "ubuntu:22.04",
            "user": "root",
            "privileged": True,
            "environment": ["SECRET=123"],
        }
        ctx = analyzer._build_service_context("web", svc_config)
        assert ctx["base_image"] == "ubuntu:22.04"
        assert ctx["user"] == "root"
        assert ctx["privileged"] is True
        assert "SECRET=123" in ctx["env_vars"]

    def test_build_context_edge_cases(self, tmp_path):
        f = tmp_path / "compose.yml"
        f.write_text("services: {}")
        analyzer = ComposeAnalyzer(str(f))
        assert analyzer._build_service_context("web", None)["component"] == "compose"
        
        vols = ["/host:/container", "../relative:/container"]
        ctx = analyzer._build_service_context("web", {"volumes": vols})
        assert ctx["has_writable_volumes"] is True
        
        ctx2 = analyzer._build_service_context("web", {"environment": ["A=B"]})
        assert "A=B" in ctx2["env_vars"]
        
        ctx3 = analyzer._build_service_context("web", {"environment": {"C": "D"}})
        assert "C=D" in ctx3["env_vars"]


class Test_ComposeAnalyzer__load:
    def test_load_valid_yaml(self, tmp_path):
        """Test load valid yaml."""
        f = tmp_path / "compose.yml"
        f.write_text("services:\n  web:\n    image: nginx")
        analyzer = ComposeAnalyzer(str(f))
        assert analyzer._data is not None
        assert "services" in analyzer._data

    def test_load_empty_services(self, tmp_path):
        """Test load empty services."""
        f = tmp_path / "compose.yml"
        f.write_text("services: {}")
        analyzer = ComposeAnalyzer(str(f))
        assert analyzer._data["services"] == {}


class Test_ComposeAnalyzer_check_security_rules:
    def test_catches_root_user(self, tmp_path):
        """Test catches root user."""
        f = tmp_path / "compose.yml"
        f.write_text("services:\n  web:\n    image: nginx:1.25\n    user: root")
        analyzer = ComposeAnalyzer(str(f))
        issues = analyzer.check_security_rules()
        assert any("DC-002" in i.id or "compose_root_user" in i.id for i in issues)

    def test_catches_privileged_mode(self, tmp_path):
        """Test catches privileged mode."""
        f = tmp_path / "compose.yml"
        f.write_text("services:\n  web:\n    image: nginx:1.25\n    privileged: true")
        analyzer = ComposeAnalyzer(str(f))
        issues = analyzer.check_security_rules()
        assert any("DC-006" in i.id or "compose_privileged" in i.id for i in issues)

    def test_compose_analyzer_edge(self):
        """Test compose analyzer edge."""
        "Test edge cases with empty dictionaries running without tracebacks."
        from analyzers.compose_analyzer import ComposeAnalyzer

        analyzer = ComposeAnalyzer("tests/fixtures/docker-compose.edge.yml")
        issues = analyzer.check_security_rules()
        assert isinstance(issues, list)
        rule_ids = {i.id for i in issues}
        assert "DC-001" in rule_ids
        assert "DC-003" in rule_ids
