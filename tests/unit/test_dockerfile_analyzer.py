import pytest

from analyzers.dockerfile_analyzer import DockerfileAnalyzer


class Test_DockerfileAnalyzer___init__:
    def test_init_success(self, tmp_path):
        """Test init success."""
        f = tmp_path / "Dockerfile"
        f.write_text("FROM alpine")
        analyzer = DockerfileAnalyzer(str(f))
        assert analyzer._path == str(f)

    def test_init_file_not_found(self):
        """Test init file not found."""
        with pytest.raises(IOError):
            DockerfileAnalyzer("/non/existent/Dockerfile")


class Test_DockerfileAnalyzer_parse_dockerfile:
    def test_parse_simple(self, tmp_path):
        """Test parse simple."""
        content = "FROM alpine\nRUN echo hello"
        f = tmp_path / "Dockerfile"
        f.write_text(content)
        analyzer = DockerfileAnalyzer(str(f))
        instructions = analyzer.parse_dockerfile()
        assert any(i.instruction == "FROM" for i in instructions)
        assert any(i.instruction == "RUN" for i in instructions)


class Test_DockerfileAnalyzer__build_context:
    def test_build_context(self, tmp_path):
        """Test build context."""
        content = "FROM alpine:latest\nUSER root\nRUN apt-get update"
        f = tmp_path / "Dockerfile"
        f.write_text(content)
        analyzer = DockerfileAnalyzer(str(f))
        instructions = analyzer.parse_dockerfile()
        ctx = analyzer._build_context(instructions)
        assert ctx["base_image"] == "alpine:latest"
        assert ctx["user"] == "root"
        assert ctx["multiple_run"] is False

    def test_multiple_run_detection(self, tmp_path):
        """Test multiple run detection."""
        # Threshold is > 2 (so 3 runs)
        content = "RUN x\nRUN y\nRUN z"
        f = tmp_path / "DF"
        f.write_text(content)
        analyzer = DockerfileAnalyzer(str(f))
        ctx = analyzer._build_context(analyzer.parse_dockerfile())
        assert ctx["multiple_run"] is True

    def test_env_and_flags(self, tmp_path):
        """Test env and flags."""
        content = """
ENV MY_VAR world
ENV FOO=BAR
ADD file /
RUN apt-get install -y git
RUN pip install flask
"""
        f = tmp_path / "DF"
        f.write_text(content)
        analyzer = DockerfileAnalyzer(str(f))
        ctx = analyzer._build_context(analyzer.parse_dockerfile())
        assert ctx["has_add"] is True
        assert "MY_VAR=world" in ctx["env_vars"]
        assert "FOO=BAR" in ctx["env_vars"]
        assert ctx["apt_get_missing_no_recommends"] is True
        assert ctx["pip_missing_no_cache_dir"] is True


class Test_DockerfileAnalyzer_detect_bad_practices:
    def test_detection(self, tmp_path):
        """Test detection."""
        f = tmp_path / "DF"
        f.write_text("FROM alpine:latest\nUSER root")
        analyzer = DockerfileAnalyzer(str(f))
        issues = analyzer.detect_bad_practices()
        # Should catch latest tag and root user
        assert len(issues) >= 2
        assert any("DF-001" in i.id or "base_image_unversioned" in i.id for i in issues)


class Test_DockerfileAnalyzer__load:
    def test_load_reads_content(self, tmp_path):
        """Test load reads content."""
        f = tmp_path / "Dockerfile"
        f.write_text("FROM alpine\nRUN echo hi")
        analyzer = DockerfileAnalyzer(str(f))
        assert analyzer._content is not None
        assert "FROM alpine" in analyzer._content

    def test_load_empty_file(self, tmp_path):
        """Test load empty file."""
        f = tmp_path / "Dockerfile"
        f.write_text("")
        analyzer = DockerfileAnalyzer(str(f))
        assert analyzer._content == ""
