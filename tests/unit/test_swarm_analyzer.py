from analyzers.swarm_analyzer import SwarmAnalyzer


class Test_SwarmAnalyzer___init__:
    def test_init_success(self, tmp_path):
        """Test init success."""
        f = tmp_path / "stack.yml"
        f.write_text("version: '3.8'\nservices: {}")
        analyzer = SwarmAnalyzer(str(f))
        assert analyzer._path == str(f)


class Test_SwarmAnalyzer_analyze_services:
    def test_happy_path(self, tmp_path):
        """Test happy path."""
        content = """
services:
  web:
    image: nginx:latest
    deploy:
      replicas: 3
"""
        f = tmp_path / "stack.yml"
        f.write_text(content)
        analyzer = SwarmAnalyzer(str(f))
        issues = analyzer.detect_bad_practices()
        # Should catch latest tag
        assert any(
            "SW-008" in i.id or "swarm_image_unversioned" in i.id for i in issues
        )

    def test_analyze_services_empty(self, tmp_path):
        f = tmp_path / "stack.yml"
        f.write_text("services: null")
        analyzer = SwarmAnalyzer(str(f))
        assert analyzer.analyze_services() == []
        assert analyzer.detect_bad_practices() == []


class Test_SwarmAnalyzer_detect_bad_practices:
    def test_missing_deploy_configs(self, tmp_path):
        """Test missing deploy configs."""
        content = """
services:
  db:
    image: postgres:14
"""
        f = tmp_path / "stack.yml"
        f.write_text(content)
        analyzer = SwarmAnalyzer(str(f))
        issues = analyzer.detect_bad_practices()
        # Should catch missing replicas, resource limits, etc.
        assert any("SW-001" in i.id for i in issues)  # replicas
        assert any("SW-002" in i.id for i in issues)  # limits

    def test_detect_bad_practices_invalid_dict(self, tmp_path):
        f = tmp_path / "stack.yml"
        f.write_text("services:\n  web: []")
        analyzer = SwarmAnalyzer(str(f))
        assert analyzer.detect_bad_practices() == []


class Test_SwarmAnalyzer__build_service_context:
    def test_build(self, tmp_path):
        """Test build."""
        f = tmp_path / "stack.yml"
        f.write_text("services: {}")
        analyzer = SwarmAnalyzer(str(f))

        svc_config = {
            "image": "redis:alpine",
            "deploy": {"replicas": 5, "resources": {"limits": {"cpus": "0.5"}}},
        }
        svc_config = {
            "image": "redis:alpine",
            "deploy": {"replicas": 5, "resources": {"limits": {"cpus": "0.5"}}},
            "environment": ["DEBUG=true"],
            "networks": ["frontend"],
        }
        networks = {"frontend": {}}
        ctx = analyzer._build_service_context("cache", svc_config, networks)
        assert ctx["base_image"] == "redis:alpine"
        assert ctx["has_replicas"] is True
        assert "DEBUG=true" in ctx["env_vars"]
        assert ctx["uses_explicit_network"] is True

        # Test dict networks
        svc_config["networks"] = {"backend": {}}
        ctx = analyzer._build_service_context("c2", svc_config, {"backend": {}})
        assert ctx["uses_explicit_network"] is True

    def test_build_context_edge_cases(self, tmp_path):
        f = tmp_path / "stack.yml"
        f.write_text("services: {}")
        analyzer = SwarmAnalyzer(str(f))
        assert analyzer._build_service_context("web", None, {})["component"] == "swarm"
        
        ctx = analyzer._build_service_context("web", {"environment": ["A=B"], "volumes": ["/host:/container"]}, {})
        assert "A=B" in ctx["env_vars"]
        assert ctx["volume_missing_type"] is True
        
        ctx2 = analyzer._build_service_context("web", {"environment": {"C": "D"}}, {})
        assert "C=D" in ctx2["env_vars"]


class Test_SwarmAnalyzer__load:
    def test_load_valid_yaml(self, tmp_path):
        """Test load valid yaml."""
        f = tmp_path / "stack.yml"
        f.write_text("services:\n  web:\n    image: nginx:1.25")
        analyzer = SwarmAnalyzer(str(f))
        assert analyzer._data is not None
        assert "services" in analyzer._data

    def test_load_empty_services(self, tmp_path):
        """Test load empty services."""
        f = tmp_path / "stack.yml"
        f.write_text("services: {}")
        analyzer = SwarmAnalyzer(str(f))
        assert analyzer._data["services"] == {}

    def test_swarm_analyzer_edge(self):
        """Test swarm analyzer edge."""
        "Test edge cases with explicit nulls and bizarre missing structures."
        from analyzers.swarm_analyzer import SwarmAnalyzer

        swarm_analyzer = SwarmAnalyzer("tests/fixtures/docker-stack.edge.yml")
        issues = swarm_analyzer.detect_bad_practices()
        assert isinstance(issues, list)
        rule_ids = {i.id for i in issues}
        assert "SW-001" in rule_ids
        assert "SW-002" in rule_ids
        assert "SW-004" in rule_ids
