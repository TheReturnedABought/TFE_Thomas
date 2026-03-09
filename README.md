# DockCheck

> Static analysis tool for Docker images, Dockerfiles and Docker Compose files.  
> TFE — EPHEC Haute École | Thomas Girboux | Rapporteur : Jonathan Noël | 2026

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Rules Engine](#rules-engine)
- [HTML Report](#html-report)
- [Running Tests](#running-tests)
- [Limitations](#limitations)

---

## Overview

DockCheck is a command-line tool that performs **static analysis** of Docker environments without requiring a running daemon (except for image metadata extraction). It targets DevOps engineers and system integrators who need to automate quality and security checks on their Docker assets.

It fills a gap left by existing tools:

| Tool | Dockerfile analysis | Compose analysis | HTML report |
|------|-------------------|-----------------|-------------|
| Hadolint | ✅ | ❌ | ❌ |
| Dockle | ❌ | ❌ | ❌ |
| Trivy | Partial | ❌ | ❌ |
| **DockCheck** | **✅** | **✅** | **✅** |

---

## Features

- **Dockerfile analysis** — detects bad practices: unversioned base images, running as root, multiple consecutive `RUN` instructions, `ADD` instead of `COPY`, missing `WORKDIR`, split `apt-get` calls.
- **Docker image analysis** — extracts metadata (size, layers, base image, labels, env vars) and flags security issues via the Docker SDK (read-only).
- **Docker Compose analysis** — validates service configurations: unversioned images, root users, hardcoded secrets in environment variables, sensitive exposed ports, duplicate services.
- **HTML report generation** — structured report with summary, issues ranked by severity, and concrete recommendations.
- **Severity filtering** — `--severity low|medium|critical` threshold for CI/CD gate usage.
- **Exit codes** — returns `0` (no issues) or `1` (issues found) for pipeline integration.
- **Custom rules** — supports a custom `rules.json` file via `--rules`.

---

## Architecture

DockCheck follows a clean layered architecture:

```
CLI (argparse)
    └── Config
         └── Analyzer (orchestrator)
              ├── DockerfileAnalyzer  ──► RulesEngine ──► Issue[]
              ├── ComposeAnalyzer     ──► RulesEngine ──► Issue[]
              └── DockerImageAnalyzer ──► RulesEngine ──► Issue[]
                        └── AnalysisResult
                                └── ReportGenerator ──► report.html
```

All analysis is **read-only** and **isolated** from the host system. No container is executed during analysis.

---

## Installation

**Requirements:** Python 3.10+, Docker (only needed for image analysis)

```bash
# Clone the repository
git clone https://github.com/your-username/dockcheck.git
cd dockcheck

# Install dependencies
pip install -r requirements.txt
```

---

## Usage

### Analyse a Dockerfile

```bash
python main.py dockerfile ./Dockerfile
python main.py dockerfile ./Dockerfile --output report.html --severity medium
```

### Analyse a Docker Compose file

```bash
python main.py compose ./docker-compose.yml
python main.py compose ./docker-compose.yml --severity critical
```

### Analyse a local Docker image

```bash
python main.py image nginx:latest
python main.py image myapp:1.0 --output myapp_report.html
```

### Run all analyses at once

```bash
python main.py all \
  --image myapp:1.0 \
  --dockerfile ./Dockerfile \
  --compose ./docker-compose.yml \
  --output full_report.html
```

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `--output`, `-o` | `dockcheck_report.html` | Path for the HTML report |
| `--severity`, `-s` | `low` | Minimum severity to report (`low`, `medium`, `critical`) |
| `--no-report` | false | Skip HTML generation, print summary only |
| `--rules` | built-in | Path to a custom rules JSON file |

---

## Project Structure

```
dockcheck/
├── main.py                        # Entry point
├── cli/
│   └── cli.py                     # Argument parsing & routing
├── core/
│   ├── analyzer.py                # Orchestrates sub-analyzers
│   ├── config.py                  # Runtime configuration
│   └── rules_engine.py            # Rule loading & evaluation
├── analyzers/
│   ├── dockerfile_analyzer.py     # Dockerfile static analysis
│   ├── image_analyzer.py          # Docker image metadata & checks
│   └── compose_analyzer.py        # Docker Compose static analysis
├── models/
│   ├── issue.py                   # Issue dataclass
│   └── analysis_result.py         # AnalysisResult dataclass
├── report/
│   ├── report_generator.py        # HTML report generation
│   └── templates/
│       └── report.html.j2         # Jinja2 template
├── rules/
│   └── default_rules.json         # Built-in rules (DF-*, IMG-*, DC-*)
├── utils/
│   ├── docker_client.py           # Docker SDK wrapper (read-only)
│   └── performance_monitor.py     # Wall-clock timer
└── tests/
    ├── unit/
    │   ├── test_dockerfile_analyzer.py
    │   ├── test_image_analyzer.py
    │   └── test_compose_analyzer.py
    └── integration/
        └── test_full_analysis.py
```

---

## Rules Engine

Rules are defined in `rules/default_rules.json`. Each rule has an `id`, `severity`, `description`, `recommendation`, and a `check` key that maps to an evaluator function.

**Built-in rules:**

| ID | Component | Severity | Description |
|----|-----------|----------|-------------|
| DF-001 | dockerfile | medium | Unversioned base image (`:latest` or no tag) |
| DF-002 | dockerfile | critical | Running as root (no `USER` or `USER root`) |
| DF-003 | dockerfile | low | Multiple consecutive `RUN` instructions |
| DF-004 | dockerfile | low | `ADD` used instead of `COPY` |
| DF-005 | dockerfile | low | Missing `WORKDIR` |
| DF-006 | dockerfile | medium | Split `apt-get update` / `apt-get install` |
| IMG-001 | image | low | Missing image labels |
| IMG-002 | image | critical | Sensitive data in environment variables |
| IMG-003 | image | medium | Excessive layer count (> 20) |
| IMG-004 | image | critical | Image runs as root |
| IMG-005 | image | medium | Unversioned base image |
| DC-001 | compose | medium | Service uses `:latest` or untagged image |
| DC-002 | compose | critical | Service runs as root or has no `user` |
| DC-003 | compose | critical | Hardcoded secret in environment variables |
| DC-004 | compose | medium | Port exposed on all interfaces or sensitive port |
| DC-005 | compose | low | Duplicate service images |

You can add custom rules by pointing `--rules` to your own JSON file following the same schema.

---

## HTML Report

The generated report contains:

- **Summary** — target analysed, total issues, breakdown by severity.
- **Issues** — each issue with its ID, severity badge, description, and recommendation.
- **Recommendations** — grouped actionable guidance.

Reports are self-contained HTML files suitable for archiving, sharing, or attaching to CI/CD pipeline artifacts.

---

## Running Tests

```bash
# All tests
pytest

# Unit tests only
pytest tests/unit/

# Integration tests only
pytest tests/integration/

# With coverage
pytest --cov=. --cov-report=html
```

Tests use mocked file I/O and a mocked Docker SDK — no live Docker daemon is required to run the test suite.

---

## Limitations

- **No runtime analysis** — issues that only appear during container execution (network conflicts, runtime errors) cannot be detected.
- **No CVE scanning** — DockCheck focuses on best-practice and configuration checks, not vulnerability databases. Use Trivy or Grype alongside DockCheck for CVE coverage.
- **`.env` files** — dynamic values from external `.env` files are not resolved unless DockCheck has access to them.
- **Large images** — parsing metadata for very large, multi-layer images may be CPU and memory intensive.
- **Docker Desktop (Windows)** — minor behavioural differences compared to Linux may affect image metadata extraction in some edge cases.

---

## License

MIT — see [LICENSE](LICENSE).
