"""
Property-based Testing using Hypothesis to ensure strict structural stability
of the State-Machine Lexer against high-entropic payloads with an extreme scaling bound.
"""

import os
import tempfile

import hypothesis.strategies as st
from hypothesis import HealthCheck, given, settings

from analyzers.dockerfile_analyzer import DockerfileAnalyzer
from core.parser.dockerfile_parser import DockerfileParser


@settings(
    max_examples=20000, deadline=None, suppress_health_check=[HealthCheck.too_slow]
)
@given(st.text())
def test_dockerfile_parser_never_crashes(s):
    """
    Hypothesis property test feeding 10,000 bounds of absolute garbage into
    the raw lexer. Expectation: The system must never throw a traceback.
    Null, unicode strings, control characters will natively just fall back
    to GenericNode or cleanly abort logic, but MUST NOT CRASH AST generation!
    """
    parser = DockerfileParser()
    try:
        nodes = parser.parse(s)
        assert isinstance(nodes, list)
    except Exception as e:
        assert False, f"AST Parser Traceback crashed: {e}"


@settings(
    max_examples=20000, deadline=None, suppress_health_check=[HealthCheck.too_slow]
)
@given(st.text())
def test_dockerfile_analyzer_e2e_property_never_crashes(s):
    """
    Ensures that bad data pushed all the way through the Analyzer doesn't
    break internal mapping assumptions.
    """
    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as f:
        f.write(s)
        temp_path = f.name

    try:
        analyzer = DockerfileAnalyzer(temp_path)
        issues = analyzer.detect_bad_practices()
        assert isinstance(issues, list)
    except Exception as e:
        assert False, f"Analyzer Traceback crashed: {e}"
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)
