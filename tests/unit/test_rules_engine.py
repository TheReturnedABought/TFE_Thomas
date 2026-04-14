import json

import pytest

from core.rules_engine import (
    RulesEngine,
    _add_instead_of_copy,
    _apt_get_no_recommends,
    _apt_get_split,
    _base_image_unversioned,
    _compose_duplicate_images,
    _compose_exposed_ports,
    _compose_image_unversioned,
    _compose_privileged_mode,
    _compose_root_user,
    _compose_sensitive_env,
    _compose_volume_not_readonly,
    _excessive_layers,
    _image_base_unversioned,
    _image_running_as_root,
    _missing_healthcheck_dockerfile,
    _missing_labels,
    _missing_workdir,
    _multiple_run_instructions,
    _pip_no_cache_dir,
    _running_as_root,
    _sensitive_env_vars,
    _swarm_default_network,
    _swarm_image_unversioned,
    _swarm_missing_replicas,
    _swarm_no_healthcheck,
    _swarm_no_logging,
    _swarm_no_placement_constraints,
    _swarm_no_resource_limits,
    _swarm_no_resource_reservations,
    _swarm_no_restart_policy,
    _swarm_no_update_config,
    _swarm_privileged_mode,
    _swarm_secrets_in_env,
)


class Test__base_image_unversioned:
    def test_unversioned_returns_true(self):
        """Test unversioned returns true."""
        assert _base_image_unversioned({"base_image": "ubuntu"}) is True

    def test_latest_returns_true(self):
        """Test latest returns true."""
        assert _base_image_unversioned({"base_image": "ubuntu:latest"}) is True

    def test_pinned_returns_false(self):
        """Test pinned returns false."""
        assert _base_image_unversioned({"base_image": "ubuntu:22.04"}) is False

    def test_empty_returns_true(self):
        """Test empty returns true."""
        assert _base_image_unversioned({}) is True

    def test_non_dict_returns_false(self):
        """Test non dict returns false."""
        assert _base_image_unversioned(None) is False


class Test__running_as_root:
    def test_root_user_returns_true(self):
        """Test root user returns true."""
        assert _running_as_root({"user": "root"}) is True
        assert _running_as_root({"user": "0"}) is True

    def test_implicit_root_returns_true(self):
        """Test implicit root returns true."""
        assert _running_as_root({"user": "root", "user_is_explicit": False}) is True

    def test_non_root_returns_false(self):
        """Test non root returns false."""
        assert _running_as_root({"user": "appuser"}) is False

    def test_non_dict_returns_false(self):
        """Test non dict returns false."""
        assert _running_as_root(42) is False


class Test__multiple_run_instructions:
    def test_multiple_returns_true(self):
        """Test multiple returns true."""
        assert _multiple_run_instructions({"multiple_run": True}) is True

    def test_single_returns_false(self):
        """Test single returns false."""
        assert _multiple_run_instructions({"multiple_run": False}) is False


class Test__add_instead_of_copy:
    def test_has_add_returns_true(self):
        """Test has add returns true."""
        assert _add_instead_of_copy({"has_add": True}) is True

    def test_no_add_returns_false(self):
        """Test no add returns false."""
        assert _add_instead_of_copy({"has_add": False}) is False


class Test__missing_workdir:
    def test_missing_returns_true(self):
        """Test missing returns true."""
        assert _missing_workdir({"has_workdir": False}) is True

    def test_present_returns_false(self):
        """Test present returns false."""
        assert _missing_workdir({"has_workdir": True}) is False


class Test__apt_get_split:
    def test_split_returns_true(self):
        """Test split returns true."""
        assert _apt_get_split({"apt_get_split": True}) is True

    def test_combined_returns_false(self):
        """Test combined returns false."""
        assert _apt_get_split({"apt_get_split": False}) is False


class Test__missing_healthcheck_dockerfile:
    def test_missing_returns_true(self):
        """Test missing returns true."""
        assert _missing_healthcheck_dockerfile({"has_healthcheck": False}) is True

    def test_present_returns_false(self):
        """Test present returns false."""
        assert _missing_healthcheck_dockerfile({"has_healthcheck": True}) is False


class Test__apt_get_no_recommends:
    def test_missing_flag_returns_true(self):
        """Test missing flag returns true."""
        assert _apt_get_no_recommends({"apt_get_missing_no_recommends": True}) is True

    def test_flag_present_returns_false(self):
        """Test flag present returns false."""
        assert _apt_get_no_recommends({"apt_get_missing_no_recommends": False}) is False


class Test__pip_no_cache_dir:
    def test_missing_flag_returns_true(self):
        """Test missing flag returns true."""
        assert _pip_no_cache_dir({"pip_missing_no_cache_dir": True}) is True

    def test_flag_present_returns_false(self):
        """Test flag present returns false."""
        assert _pip_no_cache_dir({"pip_missing_no_cache_dir": False}) is False


class Test__missing_labels:
    def test_no_labels_returns_true(self):
        """Test no labels returns true."""
        assert _missing_labels({"labels": {}}) is True

    def test_has_labels_returns_false(self):
        """Test has labels returns false."""
        assert _missing_labels({"labels": {"maintainer": "me"}}) is False


class Test__sensitive_env_vars:
    def test_sensitive_detected(self):
        """Test sensitive detected."""
        assert _sensitive_env_vars({"env_vars": ["DB_PASSWORD=secret"]}) is True

    def test_secrets_file_ignored(self):
        """Test secrets file ignored."""
        assert (
            _sensitive_env_vars({"env_vars": ["DB_PASSWORD_FILE=/run/secrets/px"]})
            is False
        )

    def test_safe_vars_pass(self):
        """Test safe vars pass."""
        assert _sensitive_env_vars({"env_vars": ["NODE_ENV=production"]}) is False


class Test__excessive_layers:
    def test_excessive_returns_true(self):
        """Test excessive returns true."""
        assert _excessive_layers({"num_layers": 25}) is True

    def test_normal_returns_false(self):
        """Test normal returns false."""
        assert _excessive_layers({"num_layers": 10}) is False

    def test_boundary_returns_false(self):
        """Test boundary returns false."""
        assert _excessive_layers({"num_layers": 20}) is False


class Test__image_running_as_root:
    def test_root_returns_true(self):
        """Test root returns true."""
        assert _image_running_as_root({"user": "root"}) is True

    def test_non_root_returns_false(self):
        """Test non root returns false."""
        assert _image_running_as_root({"user": "appuser"}) is False


class Test__image_base_unversioned:
    def test_unversioned_returns_true(self):
        """Test unversioned returns true."""
        assert _image_base_unversioned({"base_image": "nginx"}) is True

    def test_pinned_returns_false(self):
        """Test pinned returns false."""
        assert _image_base_unversioned({"base_image": "nginx:1.25"}) is False


class Test__compose_image_unversioned:
    def test_unversioned_returns_true(self):
        """Test unversioned returns true."""
        assert _compose_image_unversioned({"base_image": "redis"}) is True

    def test_pinned_returns_false(self):
        """Test pinned returns false."""
        assert _compose_image_unversioned({"base_image": "redis:7.2"}) is False


class Test__compose_root_user:
    def test_root_returns_true(self):
        """Test root returns true."""
        assert _compose_root_user({"user": "root"}) is True

    def test_non_root_returns_false(self):
        """Test non root returns false."""
        assert _compose_root_user({"user": "www-data"}) is False


class Test__compose_sensitive_env:
    def test_sensitive_returns_true(self):
        """Test sensitive returns true."""
        assert _compose_sensitive_env({"env_vars": ["API_KEY=abc"]}) is True

    def test_safe_returns_false(self):
        """Test safe returns false."""
        assert _compose_sensitive_env({"env_vars": ["LOG_LEVEL=debug"]}) is False


class Test__compose_exposed_ports:
    def test_sensitive_port_detected(self):
        """Test sensitive port detected."""
        assert _compose_exposed_ports({"ports": ["22:22"]}) is True

    def test_all_interfaces_detected(self):
        """Test all interfaces detected."""
        assert _compose_exposed_ports({"ports": ["0.0.0.0:80:80"]}) is True

    def test_safe_port_passes(self):
        """Test safe port passes."""
        assert _compose_exposed_ports({"ports": ["8080:8080"]}) is False


class Test__compose_duplicate_images:
    def test_duplicate_returns_true(self):
        """Test duplicate returns true."""
        assert _compose_duplicate_images({"has_duplicate_images": True}) is True

    def test_no_duplicate_returns_false(self):
        """Test no duplicate returns false."""
        assert _compose_duplicate_images({"has_duplicate_images": False}) is False


class Test__compose_privileged_mode:
    def test_privileged_returns_true(self):
        """Test privileged returns true."""
        assert _compose_privileged_mode({"privileged": True}) is True

    def test_unprivileged_returns_false(self):
        """Test unprivileged returns false."""
        assert _compose_privileged_mode({"privileged": False}) is False


class Test__compose_volume_not_readonly:
    def test_writable_returns_true(self):
        """Test writable returns true."""
        assert _compose_volume_not_readonly({"has_writable_volumes": True}) is True

    def test_readonly_returns_false(self):
        """Test readonly returns false."""
        assert _compose_volume_not_readonly({"has_writable_volumes": False}) is False


class Test__swarm_missing_replicas:
    def test_missing_returns_true(self):
        """Test missing returns true."""
        assert _swarm_missing_replicas({"has_replicas": False}) is True

    def test_present_returns_false(self):
        """Test present returns false."""
        assert _swarm_missing_replicas({"has_replicas": True}) is False


class Test__swarm_no_resource_limits:
    def test_missing_returns_true(self):
        """Test missing returns true."""
        assert _swarm_no_resource_limits({"has_resource_limits": False}) is True

    def test_present_returns_false(self):
        """Test present returns false."""
        assert _swarm_no_resource_limits({"has_resource_limits": True}) is False


class Test__swarm_no_resource_reservations:
    def test_missing_returns_true(self):
        """Test missing returns true."""
        assert (
            _swarm_no_resource_reservations({"has_resource_reservations": False})
            is True
        )

    def test_present_returns_false(self):
        """Test present returns false."""
        assert (
            _swarm_no_resource_reservations({"has_resource_reservations": True})
            is False
        )


class Test__swarm_no_restart_policy:
    def test_missing_returns_true(self):
        """Test missing returns true."""
        assert _swarm_no_restart_policy({"has_restart_policy": False}) is True

    def test_unbounded_returns_true(self):
        """Test unbounded returns true."""
        assert (
            _swarm_no_restart_policy(
                {"has_restart_policy": True, "restart_max_attempts": None}
            )
            is True
        )

    def test_bounded_returns_false(self):
        """Test bounded returns false."""
        assert (
            _swarm_no_restart_policy(
                {"has_restart_policy": True, "restart_max_attempts": 3}
            )
            is False
        )


class Test__swarm_no_placement_constraints:
    def test_missing_returns_true(self):
        """Test missing returns true."""
        assert (
            _swarm_no_placement_constraints({"has_placement_constraints": False})
            is True
        )

    def test_present_returns_false(self):
        """Test present returns false."""
        assert (
            _swarm_no_placement_constraints({"has_placement_constraints": True})
            is False
        )


class Test__swarm_no_update_config:
    def test_missing_returns_true(self):
        """Test missing returns true."""
        assert _swarm_no_update_config({"has_update_config": False}) is True

    def test_present_returns_false(self):
        """Test present returns false."""
        assert _swarm_no_update_config({"has_update_config": True}) is False


class Test__swarm_secrets_in_env:
    def test_secret_in_env_returns_true(self):
        """Test secret in env returns true."""
        assert _swarm_secrets_in_env({"env_vars": ["SECRET=abc"]}) is True

    def test_safe_env_returns_false(self):
        """Test safe env returns false."""
        assert _swarm_secrets_in_env({"env_vars": ["NODE_ENV=prod"]}) is False


class Test__swarm_image_unversioned:
    def test_unversioned_returns_true(self):
        """Test unversioned returns true."""
        assert _swarm_image_unversioned({"base_image": "nginx"}) is True

    def test_pinned_returns_false(self):
        """Test pinned returns false."""
        assert _swarm_image_unversioned({"base_image": "nginx:1.25"}) is False


class Test__swarm_default_network:
    def test_default_returns_true(self):
        """Test default returns true."""
        assert _swarm_default_network({"uses_explicit_network": False}) is True

    def test_explicit_returns_false(self):
        """Test explicit returns false."""
        assert _swarm_default_network({"uses_explicit_network": True}) is False


class Test__swarm_no_healthcheck:
    def test_missing_returns_true(self):
        """Test missing returns true."""
        assert _swarm_no_healthcheck({"has_healthcheck": False}) is True

    def test_present_returns_false(self):
        """Test present returns false."""
        assert _swarm_no_healthcheck({"has_healthcheck": True}) is False


class Test__swarm_no_logging:
    def test_missing_returns_true(self):
        """Test missing returns true."""
        assert _swarm_no_logging({"has_logging": False}) is True

    def test_present_returns_false(self):
        """Test present returns false."""
        assert _swarm_no_logging({"has_logging": True}) is False


class Test__swarm_privileged_mode:
    def test_privileged_returns_true(self):
        """Test privileged returns true."""
        assert _swarm_privileged_mode({"privileged": True}) is True

    def test_unprivileged_returns_false(self):
        """Test unprivileged returns false."""
        assert _swarm_privileged_mode({"privileged": False}) is False


class Test_RulesEngine_load_rules:
    def test_success(self, tmp_path):
        """Test success."""
        f = tmp_path / "rules.json"
        f.write_text(
            json.dumps(
                {
                    "rules": [
                        {
                            "id": "R1",
                            "check": "base_image_unversioned",
                            "description": "d",
                            "severity": "low",
                            "recommendation": "r",
                        }
                    ]
                }
            )
        )
        engine = RulesEngine(str(f))
        rules = engine.load_rules()
        assert len(rules) == 1

    def test_io_error(self):
        """Test io error."""
        engine = RulesEngine("/non/existent/path.json")
        with pytest.raises(IOError):
            engine.load_rules()


class Test_RulesEngine_evaluate:
    def test_rule_firing(self, tmp_path):
        """Test rule firing."""
        f = tmp_path / "rules.json"
        f.write_text(
            json.dumps(
                {
                    "rules": [
                        {
                            "id": "R1",
                            "check": "base_image_unversioned",
                            "description": "d",
                            "severity": "low",
                            "recommendation": "r",
                        }
                    ]
                }
            )
        )
        engine = RulesEngine(str(f))
        engine.load_rules()
        issues = engine.evaluate("R1", {"base_image": "latest"})
        assert len(issues) == 1
        assert issues[0].id == "R1"

    def test_non_dict_context_returns_empty(self, tmp_path):
        """Test non dict context returns empty."""
        f = tmp_path / "rules.json"
        f.write_text(
            json.dumps(
                {
                    "rules": [
                        {
                            "id": "R1",
                            "check": "base_image_unversioned",
                            "description": "d",
                            "severity": "low",
                            "recommendation": "r",
                        }
                    ]
                }
            )
        )
        engine = RulesEngine(str(f))
        engine.load_rules()
        assert engine.evaluate("R1", None) == []

    def test_non_str_rule_id_returns_empty(self, tmp_path):
        """Test non str rule id returns empty."""
        f = tmp_path / "rules.json"
        f.write_text(
            json.dumps(
                {
                    "rules": [
                        {
                            "id": "R1",
                            "check": "base_image_unversioned",
                            "description": "d",
                            "severity": "low",
                            "recommendation": "r",
                        }
                    ]
                }
            )
        )
        engine = RulesEngine(str(f))
        engine.load_rules()
        assert engine.evaluate(999, {"base_image": "x"}) == []


class Test_RulesEngine_evaluate_all:
    def test_evaluate_all_fires(self, tmp_path):
        """Test evaluate all fires."""
        f = tmp_path / "rules.json"
        f.write_text(
            json.dumps(
                {
                    "rules": [
                        {
                            "id": "R1",
                            "check": "base_image_unversioned",
                            "component": "dockerfile",
                            "description": "d",
                            "severity": "low",
                            "recommendation": "r",
                        }
                    ]
                }
            )
        )
        engine = RulesEngine(str(f))
        engine.load_rules()
        issues = engine.evaluate_all({"base_image": "ubuntu"})
        assert len(issues) == 1

    def test_evaluate_all_component_filter(self, tmp_path):
        """Test evaluate all component filter."""
        f = tmp_path / "rules.json"
        f.write_text(
            json.dumps(
                {
                    "rules": [
                        {
                            "id": "R1",
                            "check": "base_image_unversioned",
                            "component": "dockerfile",
                            "description": "d",
                            "severity": "low",
                            "recommendation": "r",
                        }
                    ]
                }
            )
        )
        engine = RulesEngine(str(f))
        engine.load_rules()
        issues = engine.evaluate_all({"base_image": "ubuntu"}, component_filter="swarm")
        assert len(issues) == 0
