# DockCheck

> Static analysis tool for Docker images, Dockerfiles, Docker Compose files, and Docker Swarm stacks.  
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

| Tool | Dockerfile | Compose | Swarm | HTML report |
|------|-----------|---------|-------|-------------|
| Hadolint | ✅ | ❌ | ❌ | ❌ |
| Dockle | ❌ | ❌ | ❌ | ❌ |
| Trivy | Partial | ❌ | ❌ | ❌ |
| **DockCheck** | **✅** | **✅** | **✅** | **✅** |

---

## Features

- **Dockerfile analysis** — detects bad practices: unversioned base images, running as root, multiple consecutive `RUN` instructions, `ADD` instead of `COPY`, missing `WORKDIR`, split `apt-get` calls.
- **Docker image analysis** — extracts metadata (size, layers, base image, labels, env vars) and flags security issues via the Docker SDK (read-only).
- **Docker Compose analysis** — validates service configurations: unversioned images, root users, hardcoded secrets in environment variables, sensitive exposed ports, duplicate services.
- **Docker Swarm analysis** — validates Swarm stack deployment configurations: missing replicas, resource limits/reservations, restart policies, placement constraints, rolling update configs, secrets management, image versioning, network isolation, and healthchecks.
- **HTML report generation** — structured report with summary dashboard, issues ranked by severity, and concrete recommendations.
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
              ├── SwarmAnalyzer       ──► RulesEngine ──► Issue[]
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
python main.py --output report.html --severity medium dockerfile ./Dockerfile
```

### Analyse a Docker Compose file

```bash
python main.py compose ./docker-compose.yml
python main.py --severity critical compose ./docker-compose.yml
```

### Analyse a Docker Swarm stack file

```bash
python main.py swarm ./docker-stack.yml
python main.py --output swarm_report.html swarm ./docker-stack.yml
```

### Analyse a local Docker image

```bash
python main.py image nginx:latest
python main.py --output myapp_report.html image myapp:1.0
```

### Run all analyses at once

```bash
python main.py all \
  --image myapp:1.0 \
  --dockerfile ./Dockerfile \
  --compose ./docker-compose.yml \
  --swarm ./docker-stack.yml \
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
├── requirements.txt               # Project dependencies
├── cli/
│   └── cli.py                     # Argument parsing & routing
├── core/
│   ├── analyzer.py                # Orchestrates sub-analyzers
│   ├── config.py                  # Runtime configuration
│   └── rules_engine.py            # Rule loading & evaluation
├── analyzers/
│   ├── dockerfile_analyzer.py     # Dockerfile static analysis
│   ├── image_analyzer.py          # Docker image metadata & checks
│   ├── compose_analyzer.py        # Docker Compose static analysis
│   └── swarm_analyzer.py          # Docker Swarm stack analysis
├── models/
│   ├── issue.py                   # Issue dataclass
│   └── analysis_result.py         # AnalysisResult dataclass
├── report/
│   ├── report_generator.py        # HTML report generation (Jinja2)
│   └── templates/
│       └── report.html.j2         # Self-contained HTML template
├── rules/
│   └── default_rules.json         # Built-in rules (DF-*, IMG-*, DC-*, SW-*)
├── utils/
│   ├── docker_client.py           # Docker SDK wrapper (read-only)
│   └── performance_monitor.py     # Wall-clock timer
└── tests/
    ├── conftest.py                # Shared pytest fixtures
    ├── fixtures/                  # E2E test files (good/bad/edge)
    │   ├── Dockerfile.good
    │   ├── Dockerfile.bad
    │   ├── Dockerfile.edge
    │   ├── docker-compose.good.yml
    │   ├── docker-compose.bad.yml
    │   ├── docker-stack.good.yml
    │   └── docker-stack.bad.yml
    ├── unit/
    │   ├── test_dockerfile_analyzer.py
    │   ├── test_compose_analyzer.py
    │   ├── test_swarm_analyzer.py
    │   └── test_full_analysis.py
    └── integration/
        └── test_image_analyzer.py
```

---

## Rules Engine

Rules are defined in `rules/default_rules.json`. Each rule has an `id`, `severity`, `description`, `recommendation`, and a `check` key that maps to an evaluator function.

**Built-in rules:**

### Dockerfile rules (DF-*)

| ID | Severity | Description |
|----|----------|-------------|
| DF-001 | medium | Unversioned base image (`:latest` or no tag) |
| DF-002 | critical | Running as root (no `USER` or `USER root`) |
| DF-003 | low | Multiple consecutive `RUN` instructions |
| DF-004 | low | `ADD` used instead of `COPY` |
| DF-005 | low | Missing `WORKDIR` |
| DF-006 | medium | Split `apt-get update` / `apt-get install` |

### Image rules (IMG-*)

| ID | Severity | Description |
|----|----------|-------------|
| IMG-001 | low | Missing image labels |
| IMG-002 | critical | Sensitive data in environment variables |
| IMG-003 | medium | Excessive layer count (> 20) |
| IMG-004 | critical | Image runs as root |
| IMG-005 | medium | Unversioned base image |

### Compose rules (DC-*)

| ID | Severity | Description |
|----|----------|-------------|
| DC-001 | medium | Service uses `:latest` or untagged image |
| DC-002 | critical | Service runs as root or has no `user` |
| DC-003 | critical | Hardcoded secret in environment variables |
| DC-004 | medium | Port exposed on all interfaces or sensitive port |
| DC-005 | low | Duplicate service images |

### Swarm rules (SW-*)

| ID | Severity | Description |
|----|----------|-------------|
| SW-001 | medium | No explicit replica count defined |
| SW-002 | critical | No CPU or memory resource limits |
| SW-003 | low | No CPU or memory resource reservations |
| SW-004 | critical | No restart policy or unbounded max_attempts |
| SW-005 | low | No placement constraints |
| SW-006 | medium | No rolling update configuration |
| SW-007 | critical | Secrets passed via env vars instead of Docker secrets |
| SW-008 | medium | Unversioned image (`:latest` or no tag) |
| SW-009 | medium | Default network instead of explicit overlay |
| SW-010 | medium | No healthcheck defined |

You can add custom rules by pointing `--rules` to your own JSON file following the same schema.

---

## HTML Report

The generated report contains:

- **Summary dashboard** — total issues count with severity breakdown cards.
- **Metadata** — target analysed, analysis timestamp.
- **Issues** — each issue with its ID, severity badge, description, and component reference.
- **Recommendations** — grouped actionable guidance.
- **Performance** — analysis duration.

Reports are self-contained HTML files (inline CSS, dark theme) suitable for archiving, sharing, or attaching to CI/CD pipeline artifacts.

---

## Running Tests

```bash
# All tests (107 tests)
pytest -v

# Unit tests only
pytest tests/unit/

# Integration tests only
pytest tests/integration/

# With coverage (94%+ coverage)
pytest --cov=. --cov-report=term-missing
```

Tests use mocked file I/O and a mocked Docker SDK — no live Docker daemon is required to run the test suite.

---

## Limitations

- **No runtime analysis** — issues that only appear during container execution (network conflicts, runtime errors) cannot be detected.
- **No CVE scanning** — DockCheck focuses on best-practice and configuration checks, not vulnerability databases. Use Trivy or Grype alongside DockCheck for CVE coverage.
- **`.env` files** — dynamic values from external `.env` files are not resolved unless DockCheck has access to them.
- **Large images** — parsing metadata for very large, multi-layer images may be CPU and memory intensive.
- **Docker Desktop (Windows)** — minor behavioural differences compared to Linux may affect image metadata extraction in some edge cases.
- **Swarm live state** — DockCheck analyses the static stack file, not the live cluster state. Drift between the file and deployed services is not detected.

---

## License

MIT — see [LICENSE](LICENSE).
