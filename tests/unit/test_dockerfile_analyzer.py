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

    def test_parse_caching_and_empty(self, tmp_path):
        f = tmp_path / "DF"
        f.write_text("")
        analyzer = DockerfileAnalyzer(str(f))
        assert analyzer.parse_dockerfile() == []
        assert set(analyzer._build_context(None).keys()) == {"component"}

        f.write_text("FROM alpine\n")
        analyzer = DockerfileAnalyzer(str(f))
        analyzer.parse_dockerfile()
        assert len(analyzer.parse_dockerfile()) > 0


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

    def test_build_context_nodes(self, tmp_path):
        from core.ast import WorkdirNode, HealthcheckNode, RunNode, GenericNode
        f = tmp_path / "DF"
        f.write_text("")
        analyzer = DockerfileAnalyzer(str(f))
        
        nodes = [
            WorkdirNode(instruction="WORKDIR", raw_value="WORKDIR /app", line_number=1, path="/app"),
            HealthcheckNode(instruction="HEALTHCHECK", raw_value="HEALTHCHECK CMD ...", line_number=2, command="CMD curl -f http://..."),
            GenericNode(instruction="EXPOSE", raw_value="EXPOSE 8080", line_number=3),
            GenericNode(instruction="MAINTAINER", raw_value="MAINTAINER doc", line_number=4),
            RunNode(instruction="RUN", raw_value="RUN apk add", line_number=5, commands=["apk add foo", "sudo bash", "npm install foo", "cd /tmp"]),
            RunNode(instruction="RUN", raw_value="RUN yum", line_number=6, commands=["yum install foo", "curl http://foo", "wget http://foo"]),
            "not_a_node",
        ]
        ctx = analyzer._build_context(nodes)
        assert ctx["has_workdir"] is True
        assert ctx["has_healthcheck"] is True
        assert ctx["has_expose"] is True
        assert ctx["maintainer_used"] is True
        assert ctx["apk_missing_no_cache"] is True
        assert ctx["sudo_in_run"] is True
        assert ctx["npm_missing_cleanup"] is True
        assert ctx["cd_used_in_run"] is True
        assert ctx["yum_missing_cleanup"] is True
        assert ctx["curl_missing_fsl"] is True
        assert ctx["wget_missing_qO"] is True


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
