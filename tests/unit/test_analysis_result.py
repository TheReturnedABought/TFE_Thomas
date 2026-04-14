from models.analysis_result import AnalysisResult
from models.issue import Issue


class Test_AnalysisResult_add_issue:
    def test_add(self):
        """Test add."""
        res = AnalysisResult()
        issue = Issue(
            id="1", description="d", severity="low", component="c", recommendation="r"
        )
        res.add_issue(issue)
        assert len(res.issues) == 1


class Test_AnalysisResult_merge:
    def test_merge(self):
        """Test merge."""
        r1 = AnalysisResult(metadata={"a": 1})
        r1.add_issue(
            Issue(
                id="I1",
                description="d",
                severity="low",
                component="c",
                recommendation="r",
            )
        )

        r2 = AnalysisResult(metadata={"b": 2})
        r2.add_issue(
            Issue(
                id="I2",
                description="d",
                severity="low",
                component="c",
                recommendation="r",
            )
        )

        r1.merge(r2)
        assert len(r1.issues) == 2
        assert r1.metadata["b"] == 2


class Test_AnalysisResult_total_issues:
    def test_total_issues(self):
        """Test total issues."""
        res = AnalysisResult()
        res.add_issue(
            Issue(
                id="1",
                description="d",
                severity="low",
                component="c",
                recommendation="r",
            )
        )
        res.add_issue(
            Issue(
                id="2",
                description="d",
                severity="low",
                component="c",
                recommendation="r",
            )
        )
        assert res.total_issues() == 2

    def test_empty(self):
        """Test empty."""
        res = AnalysisResult()
        assert res.total_issues() == 0


class Test_AnalysisResult_has_critical:
    def test_has_critical(self):
        """Test has critical."""
        res = AnalysisResult()
        res.add_issue(
            Issue(
                id="1",
                description="d",
                severity="low",
                component="c",
                recommendation="r",
            )
        )
        assert res.has_critical() is False
        res.add_issue(
            Issue(
                id="2",
                description="d",
                severity="critical",
                component="c",
                recommendation="r",
            )
        )
        assert res.has_critical() is True


class Test_AnalysisResult_severity_levels:
    def test_counts_correct(self):
        """Test counts correct."""
        res = AnalysisResult()
        res.add_issue(
            Issue(
                id="1",
                description="d",
                severity="low",
                component="c",
                recommendation="r",
            )
        )
        res.add_issue(
            Issue(
                id="2",
                description="d",
                severity="critical",
                component="c",
                recommendation="r",
            )
        )
        res.add_issue(
            Issue(
                id="3",
                description="d",
                severity="critical",
                component="c",
                recommendation="r",
            )
        )
        levels = res.severity_levels
        assert levels["low"] == 1
        assert levels["critical"] == 2
        assert levels["medium"] == 0

    def test_empty_result(self):
        """Test empty result."""
        res = AnalysisResult()
        levels = res.severity_levels
        assert levels == {"critical": 0, "medium": 0, "low": 0}
