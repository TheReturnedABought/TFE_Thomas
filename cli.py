"""
cli/cli.py — Command-line interface for DockCheck.

Maps CLI arguments to the appropriate analyzer(s) and triggers report generation.
"""

import argparse
import sys
from typing import Optional

from core.config import Config
from core.analyzer import Analyzer
from report.report_generator import ReportGenerator


class CLI:
    """Parses CLI arguments, builds Config, runs analysis, and outputs results."""

    SEVERITY_LEVELS = ["low", "medium", "critical"]

    def __init__(self):
        self.parser = self._build_parser()

    def _build_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            prog="dockcheck",
            description="DockCheck — Static analysis for Docker images, Dockerfiles and Compose files.",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  dockcheck image nginx:latest
  dockcheck dockerfile ./Dockerfile --output report.html
  dockcheck compose ./docker-compose.yml --severity critical
  dockcheck all --image myapp:1.0 --dockerfile ./Dockerfile --compose ./docker-compose.yml
            """,
        )

        parser.add_argument(
            "--version", action="version", version="DockCheck 1.0.0"
        )
        parser.add_argument(
            "--output", "-o",
            metavar="PATH",
            default="dockcheck_report.html",
            help="Path for the generated HTML report (default: dockcheck_report.html)",
        )
        parser.add_argument(
            "--severity", "-s",
            choices=self.SEVERITY_LEVELS,
            default="low",
            help="Minimum severity level to report (default: low)",
        )
        parser.add_argument(
            "--no-report",
            action="store_true",
            help="Skip HTML report generation (print summary only)",
        )
        parser.add_argument(
            "--rules",
            metavar="PATH",
            default=None,
            help="Path to a custom rules JSON file",
        )

        subparsers = parser.add_subparsers(dest="command", required=True)

        # --- image subcommand ---
        image_parser = subparsers.add_parser(
            "image", help="Analyse a local Docker image"
        )
        image_parser.add_argument("image_name", help="Name or ID of the local Docker image")

        # --- dockerfile subcommand ---
        df_parser = subparsers.add_parser(
            "dockerfile", help="Analyse a Dockerfile"
        )
        df_parser.add_argument("dockerfile_path", help="Path to the Dockerfile")

        # --- compose subcommand ---
        compose_parser = subparsers.add_parser(
            "compose", help="Analyse a docker-compose.yml file"
        )
        compose_parser.add_argument("compose_path", help="Path to the docker-compose.yml file")

        # --- all subcommand ---
        all_parser = subparsers.add_parser(
            "all", help="Run all analyses together"
        )
        all_parser.add_argument("--image", metavar="IMAGE", default=None, help="Local Docker image name")
        all_parser.add_argument("--dockerfile", metavar="PATH", default=None, help="Path to Dockerfile")
        all_parser.add_argument("--compose", metavar="PATH", default=None, help="Path to docker-compose.yml")

        return parser

    def run(self) -> int:
        """Parse args, run analysis, generate report. Returns exit code."""
        args = self.parser.parse_args()

        config = Config.from_cli(args)
        analyzer = Analyzer(config)

        print(f"[DockCheck] Starting analysis...")

        result = analyzer.aggregate_results()

        self.print_summary(result)

        if not args.no_report:
            generator = ReportGenerator(config)
            report_path = generator.generate_html_report(result)
            print(f"[DockCheck] Report saved to: {report_path}")

        # Exit code 1 if any issues found (useful for CI/CD pipelines)
        return 1 if result.issues else 0

    def print_summary(self, result) -> None:
        """Print a concise analysis summary to stdout."""
        print("\n" + "=" * 50)
        print("  DockCheck — Analysis Summary")
        print("=" * 50)

        if result.metadata:
            for key, value in result.metadata.items():
                print(f"  {key:<20}: {value}")

        print(f"\n  Issues found: {len(result.issues)}")

        counts = {}
        for issue in result.issues:
            counts[issue.severity] = counts.get(issue.severity, 0) + 1

        for severity in ["critical", "medium", "low"]:
            count = counts.get(severity, 0)
            if count:
                print(f"    [{severity.upper():^8}] {count} issue(s)")

        if not result.issues:
            print("    No issues detected. ✓")

        print("=" * 50 + "\n")
