"""
core/rules_engine.py — Loads analysis rules and evaluates them against a context.

Rules are stored in a JSON file (default: rules/default_rules.json).
Each rule has a 'check' identifier that maps to an evaluator function defined
in this module.  The engine is intentionally kept simple: no plugin system,
no external DSL — just plain Python functions keyed by check name.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional

from models.issue import Issue

# ---------------------------------------------------------------------------
# Type alias
# ---------------------------------------------------------------------------
CheckFn = Callable[[Dict[str, Any]], bool]

# ---------------------------------------------------------------------------
# Check implementations
# Signature: (context: dict) -> bool   (True = rule fires = issue created)
# ---------------------------------------------------------------------------


def _safe_check(fn: CheckFn) -> CheckFn:
    """Decorator: silently returns False if ctx is not a dict."""

    def wrapper(ctx: Dict[str, Any]) -> bool:
        if not isinstance(ctx, dict):
            return False
        return fn(ctx)

    wrapper.__name__ = fn.__name__
    wrapper.__doc__ = fn.__doc__
    return wrapper


@_safe_check
def _base_image_unversioned(ctx: Dict[str, Any]) -> bool:
    base = ctx.get("base_image", "")
    if not base:
        return True
    if ":" not in base:
        return True
    tag = base.split(":")[-1]
    return tag.lower() == "latest"


@_safe_check
def _running_as_root(ctx: Dict[str, Any]) -> bool:
    user = ctx.get("user", "").strip().lower()
    # Explicitly check for root/0 OR check if no USER was defined (implicitly root)
    if user in ("root", "0"):
        return True
    if not ctx.get("user_is_explicit", True) and user == "root":
        # This handles the case where the context builder defaulted to 'root'
        return True
    return False


@_safe_check
def _multiple_run_instructions(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("multiple_run", False))


@_safe_check
def _add_instead_of_copy(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("has_add", False))


@_safe_check
def _missing_workdir(ctx: Dict[str, Any]) -> bool:
    return not ctx.get("has_workdir", False)


@_safe_check
def _apt_get_split(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("apt_get_split", False))


@_safe_check
def _missing_healthcheck_dockerfile(ctx: Dict[str, Any]) -> bool:
    """DF-007: No HEALTHCHECK instruction in Dockerfile. Source: IBM."""
    return not ctx.get("has_healthcheck", False)


@_safe_check
def _apt_get_no_recommends(ctx: Dict[str, Any]) -> bool:
    """DF-008: apt-get install without --no-install-recommends. Source: Medium/0xfujin."""
    return bool(ctx.get("apt_get_missing_no_recommends", False))


@_safe_check
def _pip_no_cache_dir(ctx: Dict[str, Any]) -> bool:
    """DF-009: pip install without --no-cache-dir. Source: Medium/0xfujin."""
    return bool(ctx.get("pip_missing_no_cache_dir", False))


@_safe_check
def _missing_labels(ctx: Dict[str, Any]) -> bool:
    labels = ctx.get("labels", {})
    return not labels


@_safe_check
def _sensitive_env_vars(ctx: Dict[str, Any]) -> bool:
    sensitive_keywords = {
        "password", "secret", "key", "token", "auth", "cred"
    }
    for env in ctx.get("env_vars", []):
        key = env.split("=")[0].lower()
        # Skip Docker secrets file references (e.g. POSTGRES_PASSWORD_FILE)
        if key.endswith("_file"):
            continue
        if any(kw in key for kw in sensitive_keywords):
            return True
    return False


@_safe_check
def _excessive_layers(ctx: Dict[str, Any]) -> bool:
    return ctx.get("num_layers", 0) > 20


@_safe_check
def _image_running_as_root(ctx: Dict[str, Any]) -> bool:
    return _running_as_root(ctx)


@_safe_check
def _image_base_unversioned(ctx: Dict[str, Any]) -> bool:
    return _base_image_unversioned(ctx)


@_safe_check
def _compose_image_unversioned(ctx: Dict[str, Any]) -> bool:
    return _base_image_unversioned(ctx)


@_safe_check
def _compose_root_user(ctx: Dict[str, Any]) -> bool:
    return _running_as_root(ctx)


@_safe_check
def _compose_sensitive_env(ctx: Dict[str, Any]) -> bool:
    return _sensitive_env_vars(ctx)


@_safe_check
def _compose_exposed_ports(ctx: Dict[str, Any]) -> bool:
    sensitive_ports = {"22", "23", "3389", "5900"}
    for port in ctx.get("ports", []):
        port_str = str(port)
        if "0.0.0.0" in port_str:
            return True
        # Extract host port
        parts = port_str.split(":")
        host_port = parts[-2] if len(parts) >= 2 else parts[0]
        if host_port.strip() in sensitive_ports:
            return True
    return False


@_safe_check
def _compose_duplicate_images(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("has_duplicate_images", False))


@_safe_check
def _compose_privileged_mode(ctx: Dict[str, Any]) -> bool:
    """DC-006: Container runs in privileged mode. Source: IBM."""
    return bool(ctx.get("privileged", False))


@_safe_check
def _compose_volume_not_readonly(ctx: Dict[str, Any]) -> bool:
    """DC-007: Volume not mounted as read-only. Source: IBM."""
    return bool(ctx.get("has_writable_volumes", False))


# --- Swarm checks -----------------------------------------------------------


@_safe_check
def _swarm_missing_replicas(ctx: Dict[str, Any]) -> bool:
    return not ctx.get("has_replicas", False)


@_safe_check
def _swarm_no_resource_limits(ctx: Dict[str, Any]) -> bool:
    return not ctx.get("has_resource_limits", False)


@_safe_check
def _swarm_no_resource_reservations(ctx: Dict[str, Any]) -> bool:
    return not ctx.get("has_resource_reservations", False)


@_safe_check
def _swarm_no_restart_policy(ctx: Dict[str, Any]) -> bool:
    if not ctx.get("has_restart_policy", False):
        return True
    # Also flag if max_attempts is not set (unbounded retries)
    return ctx.get("restart_max_attempts") is None


@_safe_check
def _swarm_no_placement_constraints(ctx: Dict[str, Any]) -> bool:
    return not ctx.get("has_placement_constraints", False)


@_safe_check
def _swarm_no_update_config(ctx: Dict[str, Any]) -> bool:
    return not ctx.get("has_update_config", False)


@_safe_check
def _swarm_secrets_in_env(ctx: Dict[str, Any]) -> bool:
    """Flag if sensitive data is in env vars instead of Docker secrets."""
    return _sensitive_env_vars(ctx)


@_safe_check
def _swarm_image_unversioned(ctx: Dict[str, Any]) -> bool:
    return _base_image_unversioned(ctx)


@_safe_check
def _swarm_default_network(ctx: Dict[str, Any]) -> bool:
    return not ctx.get("uses_explicit_network", False)


@_safe_check
def _swarm_no_healthcheck(ctx: Dict[str, Any]) -> bool:
    return not ctx.get("has_healthcheck", False)


@_safe_check
def _swarm_no_logging(ctx: Dict[str, Any]) -> bool:
    """SW-011: No logging configuration. Source: AccuWeb, IBM."""
    return not ctx.get("has_logging", False)


@_safe_check
def _swarm_privileged_mode(ctx: Dict[str, Any]) -> bool:
    """SW-012: Service runs in privileged mode. Source: IBM."""
    return bool(ctx.get("privileged", False))


# --- Additional Dockerfile checks (DF-010 to DF-019) -----------------------

@_safe_check
def _apt_get_no_cleanup(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("apt_get_missing_cleanup", False))

@_safe_check
def _apk_no_cache(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("apk_missing_no_cache", False))

@_safe_check
def _yum_no_clean(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("yum_missing_cleanup", False))

@_safe_check
def _curl_no_fsl(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("curl_missing_fsl", False))

@_safe_check
def _wget_no_qO(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("wget_missing_qO", False))

@_safe_check
def _sudo_in_run(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("sudo_in_run", False))

@_safe_check
def _missing_expose(ctx: Dict[str, Any]) -> bool:
    return not ctx.get("has_expose", False)

@_safe_check
def _maintainer_used(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("maintainer_used", False))

@_safe_check
def _cd_instead_of_workdir(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("cd_used_in_run", False))

@_safe_check
def _npm_no_cache_clean(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("npm_missing_cleanup", False))

# --- Additional Compose checks (DC-008 to DC-017) -------------------------

@_safe_check
def _compose_missing_restart(ctx: Dict[str, Any]) -> bool:
    return not ctx.get("has_restart", False)

@_safe_check
def _compose_missing_healthcheck(ctx: Dict[str, Any]) -> bool:
    return not ctx.get("has_healthcheck", False)

@_safe_check
def _compose_network_mode_host(ctx: Dict[str, Any]) -> bool:
    return ctx.get("network_mode", "") == "host"

@_safe_check
def _compose_pid_host(ctx: Dict[str, Any]) -> bool:
    return ctx.get("pid_mode", "") == "host"

@_safe_check
def _compose_missing_limits(ctx: Dict[str, Any]) -> bool:
    return not ctx.get("has_resource_limits", False)

@_safe_check
def _compose_hardcoded_container_name(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("has_container_name", False))

@_safe_check
def _compose_dangerous_caps(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("has_dangerous_caps", False))

@_safe_check
def _compose_ipc_host(ctx: Dict[str, Any]) -> bool:
    return ctx.get("ipc_mode", "") == "host"

@_safe_check
def _compose_hardcoded_mac(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("has_mac_address", False))

@_safe_check
def _compose_hardcoded_dns(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("has_dns", False))

# --- Additional Swarm checks (SW-013 to SW-017) ---------------------------

@_safe_check
def _swarm_missing_stop_grace_period(ctx: Dict[str, Any]) -> bool:
    return not ctx.get("has_stop_grace_period", False)

@_safe_check
def _swarm_endpoint_mode_dnsrr(ctx: Dict[str, Any]) -> bool:
    return ctx.get("endpoint_mode", "") == "dnsrr"

@_safe_check
def _swarm_update_order_stop_first(ctx: Dict[str, Any]) -> bool:
    return ctx.get("update_order", "stop-first") == "stop-first"

@_safe_check
def _swarm_restart_delay_short(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("restart_delay_missing_or_short", False))

@_safe_check
def _swarm_volume_missing_type(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("volume_missing_type", False))

# --- Additional Image checks (IMG-006 to IMG-010) -------------------------

@_safe_check
def _image_excessive_size(ctx: Dict[str, Any]) -> bool:
    # Checked against size in MB -> > 1024 MB is excessive
    return ctx.get("size_mb", 0.0) > 1024.0

@_safe_check
def _image_missing_exposed_ports(ctx: Dict[str, Any]) -> bool:
    return not ctx.get("has_exposed_ports", False)

@_safe_check
def _image_scratch_root(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("is_scratch_root", False))

@_safe_check
def _image_unversioned_tags(ctx: Dict[str, Any]) -> bool:
    tags = ctx.get("tags", [])
    for tag in tags:
        if ":latest" in str(tag).lower():
            return True
    return False

@_safe_check
def _image_missing_cmd_entrypoint(ctx: Dict[str, Any]) -> bool:
    return not ctx.get("has_cmd_or_entrypoint", False)


# ---------------------------------------------------------------------------


# --- Additional DF-020 to DF-034 checks ------------------------------------

@_safe_check
def _df_system_upgrade(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("df_system_upgrade", False))

@_safe_check
def _df_missing_setuid_cleanup(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("df_missing_setuid_cleanup", False))

@_safe_check
def _df_arg_secrets(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("df_arg_secrets", False))

@_safe_check
def _df_entrypoint_shell_form(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("df_entrypoint_shell_form", False))

@_safe_check
def _df_cmd_shell_form(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("df_cmd_shell_form", False))

@_safe_check
def _df_expose_port_22(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("df_expose_port_22", False))

@_safe_check
def _df_missing_checksum(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("df_missing_checksum", False))

@_safe_check
def _df_apk_unpinned(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("df_apk_unpinned", False))

@_safe_check
def _df_apt_unpinned(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("df_apt_unpinned", False))

@_safe_check
def _df_healthcheck_no_interval(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("df_healthcheck_no_interval", False))

@_safe_check
def _df_copy_run_chown(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("df_copy_run_chown", False))

@_safe_check
def _df_untrusted_registry(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("df_untrusted_registry", False))

@_safe_check
def _df_no_multi_stage(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("df_no_multi_stage", False))

@_safe_check
def _df_user_switched_to_root(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("df_user_switched_to_root", False))

@_safe_check
def _df_http_package_repo(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("df_http_package_repo", False))

# ---------------------------------------------------------------------------


# --- Additional IMG-011 to IMG-026 checks ----------------------------------

@_safe_check
def _img_no_healthcheck(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("img_no_healthcheck", False))

@_safe_check
def _img_no_trust(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("img_no_trust", False))

@_safe_check
def _img_history_has_add(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("img_history_has_add", False))

@_safe_check
def _img_history_system_upgrade(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("img_history_system_upgrade", False))

@_safe_check
def _img_generic_architecture(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("img_generic_architecture", False))

@_safe_check
def _img_history_secrets(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("img_history_secrets", False))

@_safe_check
def _img_explicit_root_user(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("img_explicit_root_user", False))

@_safe_check
def _img_huge_layers(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("img_huge_layers", False))

@_safe_check
def _img_missing_oci_labels(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("img_missing_oci_labels", False))

@_safe_check
def _img_expose_all_interfaces(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("img_expose_all_interfaces", False))

@_safe_check
def _img_missing_os(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("img_missing_os", False))

@_safe_check
def _img_debug_env_vars(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("img_debug_env_vars", False))

@_safe_check
def _img_missing_entrypoint_or_cmd(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("img_missing_entrypoint_or_cmd", False))

@_safe_check
def _img_empty_layers(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("img_empty_layers", False))

@_safe_check
def _img_permissive_volumes(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("img_permissive_volumes", False))

@_safe_check
def _img_history_missing_checksum(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get("img_history_missing_checksum", False))

# ---------------------------------------------------------------------------

@_safe_check
def _dc_missing_cap_drop_all(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get('dc_missing_cap_drop_all', False))

@_safe_check
def _dc_missing_no_new_privileges(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get('dc_missing_no_new_privileges', False))

@_safe_check
def _dc_mounts_sensitive_files(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get('dc_mounts_sensitive_files', False))

@_safe_check
def _dc_no_custom_network(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get('dc_no_custom_network', False))

@_safe_check
def _dc_exposes_docker_sock(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get('dc_exposes_docker_sock', False))

@_safe_check
def _dc_missing_read_only(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get('dc_missing_read_only', False))

@_safe_check
def _dc_explicit_bridge(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get('dc_explicit_bridge', False))

@_safe_check
def _dc_mounts_root(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get('dc_mounts_root', False))

@_safe_check
def _dc_mounts_etc(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get('dc_mounts_etc', False))

@_safe_check
def _dc_uses_env_file(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get('dc_uses_env_file', False))

@_safe_check
def _dc_missing_logging_config(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get('dc_missing_logging_config', False))

@_safe_check
def _dc_tmpfs_no_size(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get('dc_tmpfs_no_size', False))

@_safe_check
def _dc_privileged_ports(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get('dc_privileged_ports', False))

@_safe_check
def _dc_missing_depends_on(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get('dc_missing_depends_on', False))

@_safe_check
def _dc_uses_cgroup_parent(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get('dc_uses_cgroup_parent', False))

@_safe_check
def _dc_userns_host(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get('dc_userns_host', False))

@_safe_check
def _sw_missing_autolock(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get('sw_missing_autolock', False))

@_safe_check
def _sw_unencrypted_overlay(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get('sw_unencrypted_overlay', False))

@_safe_check
def _sw_host_volume(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get('sw_host_volume', False))

@_safe_check
def _sw_missing_placement(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get('sw_missing_placement', False))

@_safe_check
def _sw_wildcard_binding(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get('sw_wildcard_binding', False))

@_safe_check
def _sw_missing_update_config(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get('sw_missing_update_config', False))

@_safe_check
def _sw_improper_secrets(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get('sw_improper_secrets', False))

@_safe_check
def _sw_exposes_mgmt_ports(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get('sw_exposes_mgmt_ports', False))

@_safe_check
def _sw_missing_cpu_limit(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get('sw_missing_cpu_limit', False))

@_safe_check
def _sw_missing_mem_limit(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get('sw_missing_mem_limit', False))

@_safe_check
def _sw_global_mode(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get('sw_global_mode', False))

@_safe_check
def _sw_env_instead_of_configs(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get('sw_env_instead_of_configs', False))

@_safe_check
def _sw_missing_dnsrr(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get('sw_missing_dnsrr', False))

@_safe_check
def _sw_cap_add_all(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get('sw_cap_add_all', False))

@_safe_check
def _sw_host_ports(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get('sw_host_ports', False))

@_safe_check
def _sw_missing_healthcheck(ctx: Dict[str, Any]) -> bool:
    return bool(ctx.get('sw_missing_healthcheck', False))

# Registry: check name → evaluator function
# ---------------------------------------------------------------------------

@_safe_check
def _df_workdir_relative(context: dict) -> bool:
    return context.get('df_workdir_relative', False)

@_safe_check
def _df_gem_unpinned(context: dict) -> bool:
    return context.get('df_gem_unpinned', False)

@_safe_check
def _df_npm_unpinned(context: dict) -> bool:
    return context.get('df_npm_unpinned', False)

@_safe_check
def _df_yum_no_y(context: dict) -> bool:
    return context.get('df_yum_no_y', False)

@_safe_check
def _df_yum_unpinned(context: dict) -> bool:
    return context.get('df_yum_unpinned', False)

@_safe_check
def _df_zypper_no_y(context: dict) -> bool:
    return context.get('df_zypper_no_y', False)

@_safe_check
def _df_zypper_no_clean(context: dict) -> bool:
    return context.get('df_zypper_no_clean', False)

@_safe_check
def _df_zypper_unpinned(context: dict) -> bool:
    return context.get('df_zypper_unpinned', False)

@_safe_check
def _df_dnf_no_y(context: dict) -> bool:
    return context.get('df_dnf_no_y', False)

@_safe_check
def _df_dnf_no_clean(context: dict) -> bool:
    return context.get('df_dnf_no_clean', False)

@_safe_check
def _df_dnf_unpinned(context: dict) -> bool:
    return context.get('df_dnf_unpinned', False)

@_safe_check
def _df_multiple_healthcheck(context: dict) -> bool:
    return context.get('df_multiple_healthcheck', False)

@_safe_check
def _df_invalid_expose(context: dict) -> bool:
    return context.get('df_invalid_expose', False)

@_safe_check
def _df_copy_bad_dest(context: dict) -> bool:
    return context.get('df_copy_bad_dest', False)

@_safe_check
def _df_copy_bad_from(context: dict) -> bool:
    return context.get('df_copy_bad_from', False)

@_safe_check
def _df_from_not_unique(context: dict) -> bool:
    return context.get('df_from_not_unique', False)

@_safe_check
def _df_apt_used(context: dict) -> bool:
    return context.get('df_apt_used', False)

@_safe_check
def _img_missing_sbom(context: dict) -> bool:
    return context.get('img_missing_sbom', False)

@_safe_check
def _img_missing_slsa(context: dict) -> bool:
    return context.get('img_missing_slsa', False)

@_safe_check
def _img_full_os_base(context: dict) -> bool:
    return context.get('img_full_os_base', False)

@_safe_check
def _img_debug_tools(context: dict) -> bool:
    return context.get('img_debug_tools', False)

@_safe_check
def _img_shell_in_prod(context: dict) -> bool:
    return context.get('img_shell_in_prod', False)

@_safe_check
def _img_pkg_manager(context: dict) -> bool:
    return context.get('img_pkg_manager', False)

_CHECK_REGISTRY: Dict[str, CheckFn] = {
    "base_image_unversioned": _base_image_unversioned,
    "running_as_root": _running_as_root,
    "multiple_run_instructions": _multiple_run_instructions,
    "add_instead_of_copy": _add_instead_of_copy,
    "missing_workdir": _missing_workdir,
    "apt_get_split": _apt_get_split,
    "missing_healthcheck": _missing_healthcheck_dockerfile,
    "apt_get_no_recommends": _apt_get_no_recommends,
    "pip_no_cache_dir": _pip_no_cache_dir,
    "missing_labels": _missing_labels,
    "sensitive_env_vars": _sensitive_env_vars,
    "excessive_layers": _excessive_layers,
    "image_running_as_root": _image_running_as_root,
    "image_base_unversioned": _image_base_unversioned,
    "compose_image_unversioned": _compose_image_unversioned,
    "compose_root_user": _compose_root_user,
    "compose_sensitive_env": _compose_sensitive_env,
    "compose_exposed_ports": _compose_exposed_ports,
    "compose_duplicate_images": _compose_duplicate_images,
    "compose_privileged_mode": _compose_privileged_mode,
    "compose_volume_not_readonly": _compose_volume_not_readonly,
    # Swarm checks
    "swarm_missing_replicas": _swarm_missing_replicas,
    "swarm_no_resource_limits": _swarm_no_resource_limits,
    "swarm_no_resource_reservations": _swarm_no_resource_reservations,
    "swarm_no_restart_policy": _swarm_no_restart_policy,
    "swarm_no_placement_constraints": _swarm_no_placement_constraints,
    "swarm_no_update_config": _swarm_no_update_config,
    "swarm_secrets_in_env": _swarm_secrets_in_env,
    "swarm_image_unversioned": _swarm_image_unversioned,
    "swarm_default_network": _swarm_default_network,
    "swarm_no_healthcheck": _swarm_no_healthcheck,
    "swarm_no_logging": _swarm_no_logging,
    "swarm_privileged_mode": _swarm_privileged_mode,
    # Additional rules assignments
    "apt_get_no_cleanup": _apt_get_no_cleanup,
    "apk_no_cache": _apk_no_cache,
    "yum_no_clean": _yum_no_clean,
    "curl_no_fsl": _curl_no_fsl,
    "wget_no_qO": _wget_no_qO,
    "sudo_in_run": _sudo_in_run,
    "missing_expose": _missing_expose,
    "maintainer_used": _maintainer_used,
    "cd_instead_of_workdir": _cd_instead_of_workdir,
    "npm_no_cache_clean": _npm_no_cache_clean,
    "compose_missing_restart": _compose_missing_restart,
    "compose_missing_healthcheck": _compose_missing_healthcheck,
    "compose_network_mode_host": _compose_network_mode_host,
    "compose_pid_host": _compose_pid_host,
    "compose_missing_limits": _compose_missing_limits,
    "compose_hardcoded_container_name": _compose_hardcoded_container_name,
    "compose_dangerous_caps": _compose_dangerous_caps,
    "compose_ipc_host": _compose_ipc_host,
    "compose_hardcoded_mac": _compose_hardcoded_mac,
    "compose_hardcoded_dns": _compose_hardcoded_dns,
    "swarm_missing_stop_grace_period": _swarm_missing_stop_grace_period,
    "swarm_endpoint_mode_dnsrr": _swarm_endpoint_mode_dnsrr,
    "swarm_update_order_stop_first": _swarm_update_order_stop_first,
    "swarm_restart_delay_short": _swarm_restart_delay_short,
    "swarm_volume_missing_type": _swarm_volume_missing_type,
    "image_excessive_size": _image_excessive_size,
    "image_missing_exposed_ports": _image_missing_exposed_ports,
    "image_scratch_root": _image_scratch_root,
    "image_unversioned_tags": _image_unversioned_tags,
    "image_missing_cmd_entrypoint": _image_missing_cmd_entrypoint,
    "df_system_upgrade": _df_system_upgrade,
    "df_missing_setuid_cleanup": _df_missing_setuid_cleanup,
    "df_arg_secrets": _df_arg_secrets,
    "df_entrypoint_shell_form": _df_entrypoint_shell_form,
    "df_cmd_shell_form": _df_cmd_shell_form,
    "df_expose_port_22": _df_expose_port_22,
    "df_missing_checksum": _df_missing_checksum,
    "df_apk_unpinned": _df_apk_unpinned,
    "df_apt_unpinned": _df_apt_unpinned,
    "df_healthcheck_no_interval": _df_healthcheck_no_interval,
    "df_copy_run_chown": _df_copy_run_chown,
    "df_untrusted_registry": _df_untrusted_registry,
    "df_no_multi_stage": _df_no_multi_stage,
    "df_user_switched_to_root": _df_user_switched_to_root,
    "df_http_package_repo": _df_http_package_repo,
    "img_no_healthcheck": _img_no_healthcheck,
    "img_no_trust": _img_no_trust,
    "img_history_has_add": _img_history_has_add,
    "img_history_system_upgrade": _img_history_system_upgrade,
    "img_generic_architecture": _img_generic_architecture,
    "img_history_secrets": _img_history_secrets,
    "img_explicit_root_user": _img_explicit_root_user,
    "img_huge_layers": _img_huge_layers,
    "img_missing_oci_labels": _img_missing_oci_labels,
    "img_expose_all_interfaces": _img_expose_all_interfaces,
    "img_missing_os": _img_missing_os,
    "img_debug_env_vars": _img_debug_env_vars,
    "img_missing_entrypoint_or_cmd": _img_missing_entrypoint_or_cmd,
    "img_empty_layers": _img_empty_layers,
    "img_permissive_volumes": _img_permissive_volumes,
    "img_history_missing_checksum": _img_history_missing_checksum,
    "dc_missing_cap_drop_all": _dc_missing_cap_drop_all,
    "dc_missing_no_new_privileges": _dc_missing_no_new_privileges,
    "dc_mounts_sensitive_files": _dc_mounts_sensitive_files,
    "dc_no_custom_network": _dc_no_custom_network,
    "dc_exposes_docker_sock": _dc_exposes_docker_sock,
    "dc_missing_read_only": _dc_missing_read_only,
    "dc_explicit_bridge": _dc_explicit_bridge,
    "dc_mounts_root": _dc_mounts_root,
    "dc_mounts_etc": _dc_mounts_etc,
    "dc_uses_env_file": _dc_uses_env_file,
    "dc_missing_logging_config": _dc_missing_logging_config,
    "dc_tmpfs_no_size": _dc_tmpfs_no_size,
    "dc_privileged_ports": _dc_privileged_ports,
    "dc_missing_depends_on": _dc_missing_depends_on,
    "dc_uses_cgroup_parent": _dc_uses_cgroup_parent,
    "dc_userns_host": _dc_userns_host,
    "sw_missing_autolock": _sw_missing_autolock,
    "sw_unencrypted_overlay": _sw_unencrypted_overlay,
    "sw_host_volume": _sw_host_volume,
    "sw_missing_placement": _sw_missing_placement,
    "sw_wildcard_binding": _sw_wildcard_binding,
    "sw_missing_update_config": _sw_missing_update_config,
    "sw_improper_secrets": _sw_improper_secrets,
    "sw_exposes_mgmt_ports": _sw_exposes_mgmt_ports,
    "sw_missing_cpu_limit": _sw_missing_cpu_limit,
    "sw_missing_mem_limit": _sw_missing_mem_limit,
    "sw_global_mode": _sw_global_mode,
    "sw_env_instead_of_configs": _sw_env_instead_of_configs,
    "sw_missing_dnsrr": _sw_missing_dnsrr,
    "sw_cap_add_all": _sw_cap_add_all,
    "sw_host_ports": _sw_host_ports,
    "sw_missing_healthcheck": _sw_missing_healthcheck,
    "df_workdir_relative": _df_workdir_relative,
    "df_gem_unpinned": _df_gem_unpinned,
    "df_npm_unpinned": _df_npm_unpinned,
    "df_yum_no_y": _df_yum_no_y,
    "df_yum_unpinned": _df_yum_unpinned,
    "df_zypper_no_y": _df_zypper_no_y,
    "df_zypper_no_clean": _df_zypper_no_clean,
    "df_zypper_unpinned": _df_zypper_unpinned,
    "df_dnf_no_y": _df_dnf_no_y,
    "df_dnf_no_clean": _df_dnf_no_clean,
    "df_dnf_unpinned": _df_dnf_unpinned,
    "df_multiple_healthcheck": _df_multiple_healthcheck,
    "df_invalid_expose": _df_invalid_expose,
    "df_copy_bad_dest": _df_copy_bad_dest,
    "df_copy_bad_from": _df_copy_bad_from,
    "df_from_not_unique": _df_from_not_unique,
    "df_apt_used": _df_apt_used,
    "img_missing_sbom": _img_missing_sbom,
    "img_missing_slsa": _img_missing_slsa,
    "img_full_os_base": _img_full_os_base,
    "img_debug_tools": _img_debug_tools,
    "img_shell_in_prod": _img_shell_in_prod,
    "img_pkg_manager": _img_pkg_manager,
}

# ---------------------------------------------------------------------------
# RulesEngine
# ---------------------------------------------------------------------------




class RulesEngine:

    """
    Loads a rules JSON file and evaluates individual rules against a context dict.

    Usage::

        engine = RulesEngine("rules/default_rules.json")
        engine.load_rules()
        issues = engine.evaluate("DF-001", {"base_image": "ubuntu:latest"})
    """

    def __init__(self, rules_path: str) -> None:
        self._rules_path = rules_path
        self._rules: List[Dict[str, Any]] = []
        self._rules_by_id: Dict[str, Dict[str, Any]] = {}

    # ------------------------------------------------------------------

    def load_rules(self) -> List[Dict[str, Any]]:
        """
        Load and parse the rules JSON file.

        Returns:
            list of rule dicts.

        Raises:
            IOError: if the rules file cannot be read.
            json.JSONDecodeError: if the file is not valid JSON.
        """
        try:
            with open(self._rules_path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError) as e:
            # Re-raise with a more descriptive message that Analyzers can catch
            raise IOError(f"Failed to load rules from {self._rules_path}") from e

        self._rules = data.get("rules", [])
        self._rules_by_id = {r["id"]: r for r in self._rules}
        return self._rules

    # ------------------------------------------------------------------

    def evaluate(self, rule_id: str, context: Dict[str, Any]) -> List[Issue]:
        """
        Evaluate a single rule against *context*.

        Returns a list containing one Issue if the rule fires, or an empty list.
        """
        # Defensive type guards (discovered via Deep Chaos Monte Carlo)
        if not isinstance(rule_id, str):
            return []
        if not isinstance(context, dict):
            return []

        rule = self._rules_by_id.get(rule_id)
        if rule is None:
            return []

        check_fn = _CHECK_REGISTRY.get(rule["check"])
        if check_fn is None:
            return []

        if check_fn(context):
            return [
                Issue(
                    id=rule["id"],
                    description=rule["description"],
                    severity=rule["severity"],
                    component=context.get(
                        "component", rule.get("component", "unknown")
                    ),
                    recommendation=rule["recommendation"],
                    autofix=rule.get("autofix")
                )
            ]
        return []

    def evaluate_all(
        self,
        context: Dict[str, Any],
        component_filter: Optional[str] = None,
    ) -> List[Issue]:
        """
        Evaluate all loaded rules against *context*.

        Args:
            context:          dict passed to each check function.
            component_filter: if given, only rules matching this component are run.

        Returns:
            list of Issue objects for every rule that fired.
        """
        issues: List[Issue] = []
        for rule in self._rules:
            if component_filter and rule.get("component") != component_filter:
                continue
            issues.extend(self.evaluate(rule["id"], context))
        return issues

    @property
    def rules(self) -> List[Dict[str, Any]]:
        return list(self._rules)
