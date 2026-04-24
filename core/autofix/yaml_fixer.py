"""
core/autofix/yaml_fixer.py - Automated Remediation Engine for Compose and Swarm using ruamel.yaml.
"""

from typing import List

from ruamel.yaml import YAML

from models.issue import Issue


class YamlFixer:
    """Remediates issues directly on Docker Compose / Swarm YAML source."""

    @staticmethod
    def apply_fixes(file_path: str, issues: List[Issue]) -> int:
        yaml = YAML()
        yaml.preserve_quotes = True
        yaml.indent(mapping=2, sequence=4, offset=2)

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = yaml.load(f)
        except Exception:
            return 0

        fixes_applied = 0

        # Gather all rules affecting compose/swarm
        rule_ids = {issue.id for issue in issues}

        services = data.get("services", {})
        if not services:
            return 0

        for svc_name, svc_config in services.items():
            if not isinstance(svc_config, dict):
                continue

            # DC-002: Root user execution (inject non-root)
            if "DC-002" in rule_ids and "user" not in svc_config:
                svc_config["user"] = "1000"
                fixes_applied += 1

            # DC-006 / SW-012: Privileged mode
            if ("DC-006" in rule_ids or "SW-012" in rule_ids) and svc_config.get(
                "privileged"
            ):
                del svc_config["privileged"]
                fixes_applied += 1

            # DC-001 / SW-008: Unversioned image
            if ("DC-001" in rule_ids or "SW-008" in rule_ids) and "image" in svc_config:
                img = svc_config["image"]
                if img is not None and ":" not in str(img):
                    svc_config["image"] = f"{img}:latest"
                    fixes_applied += 1

            # DC-007: Volume not readonly
            if "DC-007" in rule_ids and "volumes" in svc_config:
                vols = svc_config["volumes"]
                if isinstance(vols, list):
                    for i, vol in enumerate(vols):
                        if isinstance(vol, str) and not vol.endswith(":ro"):
                            vols[i] = f"{vol}:ro"
                            fixes_applied += 1

            # New native rule support (e.g. DC-010 healthcheck, etc.) if requested natively...
            if "DC-010" in rule_ids and "healthcheck" not in svc_config:
                # Add default basic healthcheck
                svc_config["healthcheck"] = {"test": ["CMD-SHELL", "curl -f http://localhost/ || exit 1"]}
                fixes_applied += 1

            # Dynamic Custom Autofix parsing
            for issue in issues:
                if issue.autofix and issue.autofix.get("supported"):
                    if issue.autofix.get("strategy") == "set_key":
                        target_key = issue.autofix.get("target")
                        target_value = issue.autofix.get("replacement")
                        if target_key and target_key not in svc_config:
                            svc_config[target_key] = target_value
                            fixes_applied += 1

        if fixes_applied > 0:
            with open(file_path, "w", encoding="utf-8") as f:
                yaml.dump(data, f)

        return fixes_applied
