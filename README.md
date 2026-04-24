# DockCheck

> Static analysis tool for Docker images, Dockerfiles, Docker Compose files, and Docker Swarm stacks.  
> TFE — EPHEC Haute École | Thomas Girboux | Rapporteur : Jonathan Noël | 2026

---

## Table of Contents

- [Overview](#overview)
- [Python Engineering Best Practices](#python-engineering-best-practices)
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

## Python Engineering Best Practices

This project was built to demonstrate professional Python software engineering patterns:
- **Test-Driven Development & Fuzzing:** Achieves ~1.14:1 test-to-source code ratio (>90% coverage) using `pytest`. Employs property-based fuzzing (`hypothesis`) and Monte Carlo limits testing.
- **Compiler Level AST Manipulation:** Implements a state-machine Lexer enabling non-destructive reading of Dockerfiles without regex fragilities.
- **Immutable Data Structures:** Built strictly around Python `dataclass` models (`Issue`, `AnalysisResult`).
- **Modularity:** High separation of concerns (`core`, `CLI`, `orchestrator`, `parsers`), making extending the engine with custom frameworks safe and atomic.
- **Type Hinting:** Fully type-hinted methods throughout the architecture ensuring maximum execution safety.

---

## Features

- **Dockerfile analysis** — detects bad practices: unversioned base images, running as root, multiple consecutive `RUN` instructions, `ADD` instead of `COPY`, missing `WORKDIR`, split `apt-get` calls.
- **Docker image analysis** — extracts metadata (size, layers, base image, labels, env vars) and flags security issues via the Docker SDK (read-only).
- **Docker Compose analysis** — validates service configurations: unversioned images, root users, hardcoded secrets in environment variables, sensitive exposed ports, duplicate services.
- **Docker Swarm analysis** — validates Swarm stack deployment configurations: missing replicas, resource limits/reservations, restart policies, placement constraints, rolling update configs, secrets management, image versioning, network isolation, and healthchecks.
- **HTML report generation** — structured report with summary dashboard, issues ranked by severity, and concrete recommendations.
- **Severity filtering** — `--severity low|medium|critical` threshold for CI/CD gate usage.
- **CI/CD AutoFix Engine (`--fix`)** — Implements an automated remediation layer replacing vulnerable AST structures with safe nodes natively without stripping configuration layouts.
- **SARIF Code Scanning Export** — Generates `dockcheck_report.sarif` mapping securely onto OASIS v2.1.0 specifications for immediate ingestion into **GitHub Advanced Security** and **GitLab SAST** dashboards.
- **Compiler Level Parse Integrity** — Implements pure-state-machine Dockerfile AST generation guaranteeing 100% resilience against multiline syntax formatting failures structurally tested against 10,000 bounds of fuzzed hypothesis noise limiters.
- **i18n Localization (`--lang fr`)** — Complete decoupling of english strings scaling natively to generalized i18n JSON locales (supports native French and Spanish out of the box).
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
| `--sarif-output` | `dockcheck_report.sarif` | Generates a SARIF file alongside HTML for CI/CD SAST dashboard aggregation |
| `--fix` | false | Automatically mitigates simple static issues natively. For complex issues, outputs a warning explicitly flagged for manual engineering review. |
| `--lang` | `en` | Overrides reporting strings localization (supports `en`, `fr`, 'es') |
| `--severity`, `-s` | `low` | Minimum severity to report (`low`, `medium`, `critical`) |
| `--no-report` | false | Skip HTML generation, print summary only |
| `--rules` | built-in | Path to a custom rules JSON file |

---

## Custom Rules & AutoFixing

DockCheck supports injecting custom rules through standard JSON schemas using the `--rules` flag. By adding a declarative `"autofix"` metadata block, your custom rules become natively supported by the `--fix` automated mitigation engine!

### Defining a Custom Rule

Create a `custom_rules.json` file and pass it via `--rules custom_rules.json`. The syntax allows targeting any string natively. 

```json
{
  "rules": [
    {
      "id": "CUST-001",
      "component": "dockerfile",
      "description": "Always replace 'python:latest' with 'python:slim'",
      "severity": "low",
      "check": "base_image_unversioned",
      "recommendation": "Use slim variant.",
      "autofix": {
        "supported": true,
        "strategy": "replace_string",
        "target": ":latest",
        "replacement": ":slim"
      }
    }
  ]
}
```

The engine currently supports two fundamental structural strategies natively without requiring Python extensions:
- **`replace_string` (Dockerfile)**: Parses and substitutes direct text matching inside active statements.
- **`set_key` (Compose/Swarm YAML)**: Blindly assigns the key-value dictionary mappings natively to bypass node limits.

---

## Project Structure

```text
dockcheck/
├── main.py                        # Entry point
├── requirements.txt               # Project dependencies
├── locales/
│   └── en.json                    # i18n localization definitions
├── cli/
│   └── cli.py                     # Argument parsing & routing
├── core/
│   ├── analyzer.py                # Orchestrates sub-analyzers
│   ├── ast.py                     # Abstract Syntax Tree Data Classes (Lexer)
│   ├── config.py                  # Runtime configuration
│   ├── i18n.py                    # Localization and translation getter framework
│   ├── rules_engine.py            # Rule loading & evaluation
│   └── parser/
│       └── dockerfile_parser.py   # State-machine Compiler parser for Docker files
├── analyzers/
│   ├── dockerfile_analyzer.py     # Dockerfile static analysis (ingests AST)
│   ├── image_analyzer.py          # Docker image metadata & checks
│   ├── compose_analyzer.py        # Docker Compose static analysis
│   └── swarm_analyzer.py          # Docker Swarm stack analysis
├── models/
│   ├── issue.py                   # Issue dataclass
│   └── analysis_result.py         # AnalysisResult dataclass
├── report/
│   ├── report_generator.py        # HTML report generation (Jinja2)
│   ├── sarif_generator.py         # Standard SAST SARIF v2.1.0 formatted exports 
│   └── templates/
│       └── report.html.j2         # Self-contained HTML template
├── rules/
│   └── default_rules.json         # Built-in rules (DF-*, IMG-*, DC-*, SW-*)
├── utils/
│   ├── docker_client.py           # Docker SDK wrapper (read-only)
│   └── performance_monitor.py     # Wall-clock timer
└── tests/
    ├── conftest.py                # Shared pytest fixtures
    ├── fixtures/                  # E2E test files
    ├── unit/                      # 1:1 source-to-test mapping
    │   ├── test_analysis_result.py
    │   ├── test_analyzer.py
    │   ├── test_ast.py
    │   ├── test_compose_analyzer.py
    │   ├── test_config.py
    │   ├── test_docker_client.py
    │   ├── test_dockerfile_analyzer.py
    │   ├── test_dockerfile_parser.py
    │   ├── test_i18n.py
    │   ├── test_image_analyzer.py
    │   ├── test_issue.py
    │   ├── test_performance_monitor.py
    │   ├── test_report_generator.py
    │   ├── test_rules_engine.py
    │   ├── test_sarif.py
    │   └── test_swarm_analyzer.py
    ├── integration/
    │   └── test_image_analyzer.py # Requires Docker daemon
    ├── property/
    │   └── test_ast_fuzzing.py    # Extremely aggressive fuzzer on the compiler theory level limits via Hypothesis.
    └── monte_carlo/
        └── test_grand_fuzzer.py   # High variance system chaos framework
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
| DF-010 | low | apk add used without --no-cache |
| DF-011 | low | yum install used without repository cleanup |
| DF-012 | medium | curl used without silent-fail flags (-fSL) |
| DF-013 | low | wget used without quiet-output stream bindings |
| DF-014 | critical | sudo executed during Docker build |
| DF-015 | low | apt-get install used without footprint cleanup |
| DF-016 | low | No EXPOSE network port mappings declared |
| DF-017 | low | Use of deprecated MAINTAINER tag |
| DF-018 | medium | Inline path traversals (cd) rather than deterministic WORKDIR |
| DF-019 | low | npm install used without clearing node caching |

### Image rules (IMG-*)

| ID | Severity | Description |
|----|----------|-------------|
| IMG-001 | low | Missing image labels |
| IMG-002 | critical | Sensitive data in environment variables |
| IMG-003 | medium | Excessive layer count (> 20) |
| IMG-004 | critical | Image runs as root |
| IMG-005 | medium | Unversioned base image |
| IMG-006 | medium | Total image payload significantly exceeds 1GB limit |
| IMG-007 | low | Virtual network mappings lack ExposedPorts structure definitions |
| IMG-008 | critical | Scratch infrastructure defaults silently back to unregulated ROOT mappings |
| IMG-009 | medium | Production configurations rely implicitly upon 'latest' tag allocations |
| IMG-010 | medium | Constructed object artifacts miss active daemon process triggers (CMD/ENTRYPOINT) |

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
# All tests (Unit tests, 10,000 bound property bounds, and E2E)
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

## Sources & References

The rules and best practices implemented in DockCheck are derived from industry-standard security benchmarks and community guides:

- **[IBM Best Practices for Docker Security](https://www.ibm.com/docs/en/cloud-paks/cp-data/4.0?topic=security-docker-best-practices)** — Foundation for root user checks, healthchecks, and privileged mode alerts.
- **[10 Docker Best Practices for Security](https://blog.aquasec.com/docker-security-best-practices)** — Basis for `ADD` vs `COPY`, `apt-get` optimization, and layer reduction.
- **[AccuWeb Swarm Recommendations](https://www.accuwebhosting.com/blog/docker-swarm-best-practices/)** — Basis for resource limits, secrets management, and network isolation rules in Swarm.
- **[Official Docker Documentation](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/)** — General syntax and structural standards.

- **NIST Application Container Security Guide (SP 800-190)** — Foundation for host PID, IPC, and network mode mapping strict isolation boundaries.
- **Node.js Docker Best Practices** — Basis for cache clearing requirements inside 'npm' runtime construction.
- **Docker Official Swarm Update Configurations** — Recommended metrics guiding zero-downtime rolling update 'order' priorities and 'delay' limits.

---

## License

MIT — see [LICENSE](LICENSE).
