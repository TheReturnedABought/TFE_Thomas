import random

import pytest

from models.issue import VALID_SEVERITIES, Issue
from tests.utils.fuzz_data import get_hybrid_param, random_string


class Test_Issue:
    """Tests for the Issue dataclass and its validation logic."""

    def test_init_validation(self):
        """Test init validation."""
        # 50% chance to use predefined valid data, 50% chance to use random strings
        issue_id = get_hybrid_param("DF-001", lambda: random_string(10))
        desc = get_hybrid_param("Violation", lambda: random_string(50))
        severity = get_hybrid_param(
            "critical", lambda: random.choice(list(VALID_SEVERITIES))
        )
        comp = get_hybrid_param("dockerfile", lambda: random_string(15))
        rec = get_hybrid_param("Fix it", lambda: random_string(100))

        # This should always pass with valid-ish data
        issue = Issue(
            id=issue_id,
            description=desc,
            severity=severity,
            component=comp,
            recommendation=rec,
        )
        assert issue.id == issue_id
        assert issue.description == desc

    def test_init_failures(self):
        """Test validation failures with chaotic data."""
        # 50% chance to use 'None' or empty, 50% chance to use a predictable failure
        bad_id = get_hybrid_param("", lambda: random.choice([None, "  ", ""]))

        with pytest.raises(ValueError):
            Issue(
                id=bad_id,
                description="d",
                severity="low",
                component="c",
                recommendation="r",
            )

    def test_repr(self):
        """Test repr."""
        issue = Issue(
            id="1", description="d", severity="low", component="c", recommendation="r"
        )
        assert "Issue" in repr(issue)
        assert "1" in repr(issue)

    def test_equality(self):
        """Test equality."""
        i1 = Issue(
            id="1", description="d", severity="low", component="c", recommendation="r"
        )
        i2 = Issue(
            id="1", description="d", severity="low", component="c", recommendation="r"
        )
        assert i1 == i2
        assert i1 != "not an issue"


class Test_Issue___post_init__:
    def test_coerces_int_id_to_str(self):
        """Test coerces int id to str."""
        issue = Issue(
            id=42, description="d", severity="low", component="c", recommendation="r"
        )
        assert issue.id == "42"

    def test_coerces_none_description_to_empty_raises(self):
        """Test coerces none description to empty raises."""
        with pytest.raises(ValueError):
            Issue(
                id="1",
                description=None,
                severity="low",
                component="c",
                recommendation="r",
            )

    def test_invalid_severity_raises(self):
        """Test invalid severity raises."""
        with pytest.raises(ValueError, match="Invalid severity"):
            Issue(
                id="1",
                description="d",
                severity="banana",
                component="c",
                recommendation="r",
            )

    def test_whitespace_only_id_raises(self):
        """Test whitespace only id raises."""
        with pytest.raises(ValueError):
            Issue(
                id="   ",
                description="d",
                severity="low",
                component="c",
                recommendation="r",
            )
