"""
tests/unit/test_autofix.py - Validates automated remediation logic safely utilizing AST boundaries and ruamel YAML mapping without modifying external configs.
"""

import os

import pytest

from core.autofix import DockerfileFixer, YamlFixer
from models.issue import Issue


def test_dockerfile_fixer_applies_fixes(tmp_path):
    """Test dockerfile fixer applies fixes."""
    df_path = tmp_path / "Dockerfile"
    df_path.write_text(
        "FROM ubuntu\nADD source dest\nRUN apt-get install python\nRUN pip install requests"
    )

    issues = [
        Issue(
            id="DF-001",
            description="foo",
            severity="low",
            component="dockerfile",
            recommendation="bar",
        ),
        Issue(
            id="DF-002",
            description="foo",
            severity="critical",
            component="dockerfile",
            recommendation="bar",
        ),
        Issue(
            id="DF-004",
            description="foo",
            severity="low",
            component="dockerfile",
            recommendation="bar",
        ),
        Issue(
            id="DF-008",
            description="foo",
            severity="medium",
            component="dockerfile",
            recommendation="bar",
        ),
        Issue(
            id="DF-009",
            description="foo",
            severity="low",
            component="dockerfile",
            recommendation="bar",
        ),
    ]

    # Run Autofix
    fixes = DockerfileFixer.apply_fixes(str(df_path), issues)

    # Needs to apply 5 fixes:
    # 1. :latest tag
    # 2. RUN useradd / USER dockcheckuser
    # 3. ADD -> COPY
    # 4. apt-get --no-install-recommends
    # 5. pip --no-cache-dir
    assert fixes == 5

    content = df_path.read_text()
    assert "ubuntu:latest" in content
    assert "COPY source dest" in content
    assert "--no-install-recommends" in content
    assert "--no-cache-dir" in content
    assert "USER dockcheckuser" in content


def test_yaml_fixer_applies_fixes_compose(tmp_path):
    """Test yaml fixer applies fixes compose."""
    yml_path = tmp_path / "docker-compose.yml"
    yaml_content = """
version: '3'
services:
  web:
    image: nginx
    privileged: true
    volumes:
      - /host:/container
"""
    yml_path.write_text(yaml_content)

    issues = [
        Issue(
            id="DC-001",
            description="foo",
            severity="low",
            component="compose",
            recommendation="bar",
        ),
        Issue(
            id="DC-002",
            description="foo",
            severity="critical",
            component="compose",
            recommendation="bar",
        ),
        Issue(
            id="DC-006",
            description="foo",
            severity="critical",
            component="compose",
            recommendation="bar",
        ),
        Issue(
            id="DC-007",
            description="foo",
            severity="low",
            component="compose",
            recommendation="bar",
        ),
    ]

    fixes = YamlFixer.apply_fixes(str(yml_path), issues)

    # 1. image tag -> nginx:latest
    # 2. Add user: "1000"
    # 3. Strip privileged
    # 4. Read only volume
    assert fixes == 4

    content = yml_path.read_text()
    assert "nginx:latest" in content
    assert "user: '1000'" in content
    assert "privileged:" not in content
    assert "/host:/container:ro" in content
