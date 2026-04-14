"""
Unit tests for the DockerfileLexer State Machine parser verifying that
advanced multi-line and mixed instructions map precisely to AST nodes.
"""

from core.ast import (
    AddNode,
    CopyNode,
    EnvNode,
    FromNode,
    GenericNode,
    HealthcheckNode,
    LabelNode,
    RunNode,
    UserNode,
    WorkdirNode,
)
from core.parser.dockerfile_parser import DockerfileParser


class TestDockerfileParser:

    def test_parse_empty(self):
        """Test parse empty."""
        p = DockerfileParser()
        assert p.parse("") == []
        assert p.parse("   \n   # comment  ") == []

    def test_parse_basics(self):
        """Test parse basics."""
        p = DockerfileParser()
        content = """FROM ubuntu:latest
RUN echo 'hi'
USER app
WORKDIR /app"""
        nodes = p.parse(content)
        assert len(nodes) == 4
        assert isinstance(nodes[0], FromNode)
        assert nodes[0].image == "ubuntu"
        assert nodes[0].tag == "latest"

        assert isinstance(nodes[1], RunNode)
        assert nodes[1].commands == ["echo 'hi'"]

        assert isinstance(nodes[2], UserNode)
        assert nodes[2].user == "app"

        assert isinstance(nodes[3], WorkdirNode)
        assert nodes[3].path == "/app"

    def test_parse_multi_line_continuation(self):
        """Test parse multi line continuation."""
        p = DockerfileParser()
        content = """RUN apt-get update && \\
    apt-get install -y git && \\
    rm -rf /var/lib/apt/lists/*"""
        nodes = p.parse(content)
        assert len(nodes) == 1
        run_node = nodes[0]
        assert isinstance(run_node, RunNode)
        assert len(run_node.commands) == 3
        assert run_node.commands[0] == "apt-get update"
        assert run_node.commands[1] == "apt-get install -y git"

    def test_parse_env_formats(self):
        """Test parse env formats."""
        p = DockerfileParser()
        content = """ENV KEY=VALUE
ENV OLD_KEY OLD_VALUE"""
        nodes = p.parse(content)
        assert isinstance(nodes[0], EnvNode)
        assert nodes[0].key == "KEY"
        assert nodes[0].value == "VALUE"

        assert isinstance(nodes[1], EnvNode)
        assert nodes[1].key == "OLD_KEY"
        assert nodes[1].value == "OLD_VALUE"

    def test_parse_copy_add(self):
        """Test parse copy add."""
        p = DockerfileParser()
        nodes = p.parse("""COPY src dest
ADD f1 f2 target""")
        assert getattr(nodes[0], "src") == ["src"]
        assert getattr(nodes[0], "dst") == "dest"
        assert getattr(nodes[1], "src") == ["f1", "f2"]
        assert getattr(nodes[1], "dst") == "target"

    def test_parse_healthcheck(self):
        """Test parse healthcheck."""
        p = DockerfileParser()
        nodes = p.parse("HEALTHCHECK CMD curl -f http://localhost/")
        assert isinstance(nodes[0], HealthcheckNode)
        assert nodes[0].command == "CMD curl -f http://localhost/"

    def test_generic_fallback(self):
        """Test generic fallback."""
        p = DockerfileParser()
        nodes = p.parse("""CMD ["python"]
EXPOSE 8080""")
        assert isinstance(nodes[0], GenericNode)
        assert nodes[0].instruction == "CMD"
        assert isinstance(nodes[1], GenericNode)
        assert nodes[1].instruction == "EXPOSE"
