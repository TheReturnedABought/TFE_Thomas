"""
tests/unit/test_dockerfile_analyzer.py

Unit tests for analyzers/dockerfile_analyzer.py — DockerfileAnalyzer.

Covers:
    - Detection of missing USER instruction (running as root)
    - Detection of unversioned base image (FROM x:latest or FROM x)
    - Detection of multiple consecutive RUN instructions (non-optimized layers)
    - Detection of ADD instead of COPY
    - Detection of missing WORKDIR
    - Clean Dockerfile producing zero issues
    - parse_dockerfile() returning correct instruction list
"""

import pytest
from unittest.mock import patch, MagicMock, mock_open


# ---------------------------------------------------------------------------
# Helpers — we test the analyzer in isolation by patching file I/O
# ---------------------------------------------------------------------------

def make_analyzer(content: str):
    """
    Instantiate DockerfileAnalyzer with patched file reading.
    The analyzer is expected to accept a file path and read it internally.
    """
    from analyzers.dockerfile_analyzer import DockerfileAnalyzer
    with patch("builtins.open", mock_open(read_data=content)):
        analyzer = DockerfileAnalyzer("Dockerfile")
    return analyzer


# ---------------------------------------------------------------------------
# parse_dockerfile
# ---------------------------------------------------------------------------

class TestParseDockerfile:

    def test_returns_list_of_instructions(self, dockerfile_good):
        from analyzers.dockerfile_analyzer import DockerfileAnalyzer
        with patch("builtins.open", mock_open(read_data=dockerfile_good)):
            analyzer = DockerfileAnalyzer("Dockerfile")
        instructions = analyzer.parse_dockerfile()
        assert isinstance(instructions, list)
        assert len(instructions) > 0

    def test_each_instruction_has_command_and_value(self, dockerfile_good):
        from analyzers.dockerfile_analyzer import DockerfileAnalyzer
        with patch("builtins.open", mock_open(read_data=dockerfile_good)):
            analyzer = DockerfileAnalyzer("Dockerfile")
        instructions = analyzer.parse_dockerfile()
        for instr in instructions:
            assert "command" in instr
            assert "value" in instr

    def test_from_instruction_detected(self, dockerfile_good):
        from analyzers.dockerfile_analyzer import DockerfileAnalyzer
        with patch("builtins.open", mock_open(read_data=dockerfile_good)):
            analyzer = DockerfileAnalyzer("Dockerfile")
        instructions = analyzer.parse_dockerfile()
        commands = [i["command"].upper() for i in instructions]
        assert "FROM" in commands

    def test_comments_are_ignored(self):
        content = "# This is a comment\nFROM python:3.11\nUSER appuser\n"
        from analyzers.dockerfile_analyzer import DockerfileAnalyzer
        with patch("builtins.open", mock_open(read_data=content)):
            analyzer = DockerfileAnalyzer("Dockerfile")
        instructions = analyzer.parse_dockerfile()
        commands = [i["command"].upper() for i in instructions]
        assert "#" not in commands

    def test_empty_dockerfile_returns_empty_list(self):
        from analyzers.dockerfile_analyzer import DockerfileAnalyzer
        with patch("builtins.open", mock_open(read_data="")):
            analyzer = DockerfileAnalyzer("Dockerfile")
        assert analyzer.parse_dockerfile() == []


# ---------------------------------------------------------------------------
# detect_bad_practices — USER / root
# ---------------------------------------------------------------------------

class TestUserRootDetection:

    def test_missing_user_instruction_raises_issue(self, dockerfile_bad_root):
        from analyzers.dockerfile_analyzer import DockerfileAnalyzer
        with patch("builtins.open", mock_open(read_data=dockerfile_bad_root)):
            analyzer = DockerfileAnalyzer("Dockerfile")
        issues = analyzer.detect_bad_practices()
        ids = [i.id for i in issues]
        assert any("USER" in i or "ROOT" in i or "root" in i.lower() for i in ids), \
            "Expected a root/USER issue to be raised"

    def test_explicit_root_user_raises_issue(self, dockerfile_bad_latest):
        from analyzers.dockerfile_analyzer import DockerfileAnalyzer
        with patch("builtins.open", mock_open(read_data=dockerfile_bad_latest)):
            analyzer = DockerfileAnalyzer("Dockerfile")
        issues = analyzer.detect_bad_practices()
        severities = [i.severity for i in issues]
        assert "critical" in severities or "medium" in severities

    def test_correct_user_instruction_no_issue(self, dockerfile_good):
        from analyzers.dockerfile_analyzer import DockerfileAnalyzer
        with patch("builtins.open", mock_open(read_data=dockerfile_good)):
            analyzer = DockerfileAnalyzer("Dockerfile")
        issues = analyzer.detect_bad_practices()
        root_issues = [i for i in issues if "root" in i.description.lower() or "user" in i.id.lower()]
        assert len(root_issues) == 0


# ---------------------------------------------------------------------------
# detect_bad_practices — base image versioning
# ---------------------------------------------------------------------------

class TestBaseImageVersioning:

    def test_latest_tag_raises_issue(self, dockerfile_bad_root):
        from analyzers.dockerfile_analyzer import DockerfileAnalyzer
        with patch("builtins.open", mock_open(read_data=dockerfile_bad_root)):
            analyzer = DockerfileAnalyzer("Dockerfile")
        issues = analyzer.detect_bad_practices()
        assert any("latest" in i.description.lower() or "version" in i.description.lower()
                   for i in issues), "Expected a versioning issue for :latest tag"

    def test_no_tag_raises_issue(self):
        content = "FROM ubuntu\nUSER appuser\nCMD [\"bash\"]\n"
        from analyzers.dockerfile_analyzer import DockerfileAnalyzer
        with patch("builtins.open", mock_open(read_data=content)):
            analyzer = DockerfileAnalyzer("Dockerfile")
        issues = analyzer.detect_bad_practices()
        assert any("version" in i.description.lower() or "tag" in i.description.lower()
                   for i in issues)

    def test_pinned_tag_no_version_issue(self, dockerfile_good):
        from analyzers.dockerfile_analyzer import DockerfileAnalyzer
        with patch("builtins.open", mock_open(read_data=dockerfile_good)):
            analyzer = DockerfileAnalyzer("Dockerfile")
        issues = analyzer.detect_bad_practices()
        version_issues = [i for i in issues
                          if "latest" in i.description.lower() or "tag" in i.description.lower()]
        assert len(version_issues) == 0


# ---------------------------------------------------------------------------
# detect_bad_practices — multiple RUN instructions
# ---------------------------------------------------------------------------

class TestMultipleRunInstructions:

    def test_multiple_run_instructions_raises_issue(self, dockerfile_multi_run):
        from analyzers.dockerfile_analyzer import DockerfileAnalyzer
        with patch("builtins.open", mock_open(read_data=dockerfile_multi_run)):
            analyzer = DockerfileAnalyzer("Dockerfile")
        issues = analyzer.detect_bad_practices()
        assert any("RUN" in i.description or "layer" in i.description.lower()
                   for i in issues), "Expected an issue for multiple consecutive RUN instructions"

    def test_chained_run_no_issue(self):
        content = (
            "FROM node:18\n"
            "RUN apt-get update && apt-get install -y curl git\n"
            "USER node\n"
            "CMD [\"node\", \"server.js\"]\n"
        )
        from analyzers.dockerfile_analyzer import DockerfileAnalyzer
        with patch("builtins.open", mock_open(read_data=content)):
            analyzer = DockerfileAnalyzer("Dockerfile")
        issues = analyzer.detect_bad_practices()
        run_issues = [i for i in issues if "RUN" in i.description or "layer" in i.description.lower()]
        assert len(run_issues) == 0


# ---------------------------------------------------------------------------
# detect_bad_practices — ADD vs COPY
# ---------------------------------------------------------------------------

class TestAddVsCopy:

    def test_add_instruction_raises_issue(self):
        content = "FROM python:3.11\nADD . /app\nUSER appuser\nCMD [\"python\", \"main.py\"]\n"
        from analyzers.dockerfile_analyzer import DockerfileAnalyzer
        with patch("builtins.open", mock_open(read_data=content)):
            analyzer = DockerfileAnalyzer("Dockerfile")
        issues = analyzer.detect_bad_practices()
        assert any("ADD" in i.description or "COPY" in i.description for i in issues), \
            "Expected an issue recommending COPY over ADD"

    def test_copy_instruction_no_add_issue(self, dockerfile_good):
        from analyzers.dockerfile_analyzer import DockerfileAnalyzer
        with patch("builtins.open", mock_open(read_data=dockerfile_good)):
            analyzer = DockerfileAnalyzer("Dockerfile")
        issues = analyzer.detect_bad_practices()
        add_issues = [i for i in issues if "ADD" in i.description]
        assert len(add_issues) == 0


# ---------------------------------------------------------------------------
# detect_bad_practices — WORKDIR
# ---------------------------------------------------------------------------

class TestWorkdirPresence:

    def test_missing_workdir_raises_issue(self):
        content = "FROM python:3.11\nCOPY . .\nUSER appuser\nCMD [\"python\", \"main.py\"]\n"
        from analyzers.dockerfile_analyzer import DockerfileAnalyzer
        with patch("builtins.open", mock_open(read_data=content)):
            analyzer = DockerfileAnalyzer("Dockerfile")
        issues = analyzer.detect_bad_practices()
        assert any("WORKDIR" in i.description or "workdir" in i.description.lower()
                   for i in issues)

    def test_workdir_present_no_issue(self, dockerfile_good):
        from analyzers.dockerfile_analyzer import DockerfileAnalyzer
        with patch("builtins.open", mock_open(read_data=dockerfile_good)):
            analyzer = DockerfileAnalyzer("Dockerfile")
        issues = analyzer.detect_bad_practices()
        workdir_issues = [i for i in issues if "WORKDIR" in i.description]
        assert len(workdir_issues) == 0


# ---------------------------------------------------------------------------
# Clean Dockerfile — zero issues
# ---------------------------------------------------------------------------

class TestCleanDockerfile:

    def test_clean_dockerfile_returns_no_issues(self, dockerfile_good):
        from analyzers.dockerfile_analyzer import DockerfileAnalyzer
        with patch("builtins.open", mock_open(read_data=dockerfile_good)):
            analyzer = DockerfileAnalyzer("Dockerfile")
        issues = analyzer.detect_bad_practices()
        assert issues == [] or len(issues) == 0

    def test_issues_are_issue_objects(self, dockerfile_bad_root):
        from analyzers.dockerfile_analyzer import DockerfileAnalyzer
        with patch("builtins.open", mock_open(read_data=dockerfile_bad_root)):
            analyzer = DockerfileAnalyzer("Dockerfile")
        issues = analyzer.detect_bad_practices()
        for issue in issues:
            assert hasattr(issue, "id")
            assert hasattr(issue, "severity")
            assert hasattr(issue, "description")
            assert hasattr(issue, "recommendation")

    def test_severity_values_are_valid(self, dockerfile_bad_root):
        from analyzers.dockerfile_analyzer import DockerfileAnalyzer
        with patch("builtins.open", mock_open(read_data=dockerfile_bad_root)):
            analyzer = DockerfileAnalyzer("Dockerfile")
        issues = analyzer.detect_bad_practices()
        valid = {"low", "medium", "critical"}
        for issue in issues:
            assert issue.severity in valid, f"Invalid severity: {issue.severity}"
