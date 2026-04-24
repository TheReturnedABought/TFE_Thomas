"""
cli/cli.py — Command-line interface for DockCheck.

Maps CLI arguments to the appropriate analyzer(s) and triggers report generation.
"""

import argparse

from core.analyzer import Analyzer
from core.autofix import DockerfileFixer, YamlFixer
from core.config import Config
from core.i18n import get_text, set_locale
from report.report_generator import ReportGenerator
from report.sarif_generator import SarifGenerator


class CLI:
    """Parses CLI arguments, builds Config, runs analysis, and outputs results."""

    SEVERITY_LEVELS = ["low", "medium", "critical"]

    def __init__(self):
        self.parser = self._build_parser()

    def _build_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            prog="dockcheck",
            description=(
                "DockCheck — Static analysis for Docker images, "
                "Dockerfiles and Compose files."
            ),
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  dockcheck image nginx:latest
  dockcheck dockerfile ./Dockerfile --output report.html
  dockcheck compose ./docker-compose.yml --severity critical
  dockcheck all --image myapp:1.0 --dockerfile ./Dockerfile --compose ./docker-compose.yml
            """,
        )

        parser.add_argument("--version", action="version", version="DockCheck 1.0.0")
        parser.add_argument(
            "--output",
            "-o",
            metavar="PATH",
            default="dockcheck_report.html",
            help="Path for the generated HTML report (default: dockcheck_report.html)",
        )
        parser.add_argument(
            "--severity",
            "-s",
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
            "--sarif-output",
            metavar="PATH",
            nargs="?",
            const="dockcheck_report.sarif",
            default=None,
            help="Output SARIF format alongside/instead of HTML. Optional path.",
        )
        parser.add_argument(
            "--rules",
            metavar="PATH",
            default=None,
            help="Path to a custom rules JSON file",
        )
        parser.add_argument(
            "--fix",
            action="store_true",
            help="Automatically remediate and fix static issues found natively in-place.",
        )
        parser.add_argument(
            "--lang",
            choices=["en", "fr", "es"],
            default="en",
            help="Select translation dictionary for output (en/fr/es).",
        )

        subparsers = parser.add_subparsers(dest="command", required=True)

        # --- image subcommand ---
        image_parser = subparsers.add_parser(
            "image", help="Analyse a local Docker image"
        )
        image_parser.add_argument(
            "image_name", help="Name or ID of the local Docker image"
        )

        # --- dockerfile subcommand ---
        df_parser = subparsers.add_parser("dockerfile", help="Analyse a Dockerfile")
        df_parser.add_argument("dockerfile_path", help="Path to the Dockerfile")

        # --- compose subcommand ---
        compose_parser = subparsers.add_parser(
            "compose", help="Analyse a docker-compose.yml file"
        )
        compose_parser.add_argument(
            "compose_path", help="Path to the docker-compose.yml file"
        )

        # --- all subcommand ---
        all_parser = subparsers.add_parser("all", help="Run all analyses together")
        all_parser.add_argument(
            "--image", metavar="IMAGE", default=None, help="Local Docker image name"
        )
        all_parser.add_argument(
            "--dockerfile", metavar="PATH", default=None, help="Path to Dockerfile"
        )
        all_parser.add_argument(
            "--compose", metavar="PATH", default=None, help="Path to docker-compose.yml"
        )
        all_parser.add_argument(
            "--swarm", metavar="PATH", default=None, help="Path to Swarm stack file"
        )

        # --- swarm subcommand ---
        swarm_parser = subparsers.add_parser(
            "swarm", help="Analyse a Docker Swarm stack file"
        )
        swarm_parser.add_argument("swarm_path", help="Path to the Swarm stack file")

        return parser

    def run(self) -> int:
        """Parse args, run analysis, generate report. Returns exit code."""
        args = self.parser.parse_args()

        # Override Locale translation dictionaries
        set_locale(args.lang)

        config = Config.from_cli(args)
        analyzer = Analyzer(config)

        print(f"[DockCheck] {get_text('cli.starting', 'Starting analysis...')}")

        result = analyzer.aggregate_results()

        self.print_summary(result)

        if not args.no_report:
            generator = ReportGenerator(config)
            report_path = generator.generate_html_report(result)
            print(
                f"[DockCheck] {get_text('cli.report_saved', 'Report saved to')}: {report_path}"
            )

        if args.sarif_output is not None:
            config._options["sarif_output"] = args.sarif_output
            sarif = SarifGenerator(config)
            sarif_path = sarif.generate(result)
            print(
                f"[DockCheck] SARIF {get_text('cli.report_saved', 'Report saved to')}: {sarif_path}"
            )

        # Autofix Engine logic
        if getattr(args, "fix", False) and result.issues:
            print(
                f"\n[DockCheck] {get_text('cli.fixing', 'Applying AutoFix engine...')}"
            )

            fixes = 0
            # Target Dockerfiles
            if getattr(args, "dockerfile_path", None):
                fixes += DockerfileFixer.apply_fixes(
                    args.dockerfile_path, result.issues
                )
            elif getattr(args, "dockerfile", None):
                fixes += DockerfileFixer.apply_fixes(args.dockerfile, result.issues)

            # Target Compose Files
            if getattr(args, "compose_path", None):
                fixes += YamlFixer.apply_fixes(args.compose_path, result.issues)
            elif getattr(args, "compose", None):
                fixes += YamlFixer.apply_fixes(args.compose, result.issues)

            # Target Swarm
            if getattr(args, "swarm_path", None):
                fixes += YamlFixer.apply_fixes(args.swarm_path, result.issues)
            elif getattr(args, "swarm", None):
                fixes += YamlFixer.apply_fixes(args.swarm, result.issues)

            if fixes > 0:
                print(
                    f"[DockCheck] {fixes} {get_text('cli.fix_applied', 'Automatic fixes applied successfully!')}"
                )

            has_high_severity = any(
                i.severity in ["medium", "critical"] for i in result.issues
            )
            if has_high_severity:
                print(
                    f"\n[!] {get_text('cli.manual_review_warning', 'Warning: Higher severity rules (Critical/Medium) often require manual engineering review.')}"
                )

        # Exit code 1 if any issues found (useful for CI/CD pipelines)
        return 1 if result.issues else 0

    def print_summary(self, result) -> None:
        """Print a concise analysis summary to stdout."""
        print("\n" + "=" * 50)
        print("  DockCheck - Analysis Summary")
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
            print("    No issues detected. [OK]")

        print("=" * 50 + "\n")
