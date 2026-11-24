"""Configuration precedence: defaults, YAML file, environment, overrides."""

from __future__ import annotations

from pathlib import Path

import pytest

from reconpulse.core.config import AppConfig
from reconpulse.core.errors import ConfigError


class TestDefaults:
    def test_safe_defaults(self) -> None:
        config = AppConfig()
        assert config.rate_per_second <= 1.0
        assert config.allow_private is False
        assert config.verify_tls is True
        assert "{version}" in config.user_agent
        assert config.extra == {}

    @pytest.mark.parametrize("field", ["timeout", "rate_per_second", "concurrency", "max_response_bytes"])
    def test_non_positive_values_are_rejected(self, field: str) -> None:
        with pytest.raises(ConfigError):
            AppConfig(**{field: 0})


class TestFromMapping:
    def test_type_coercion(self) -> None:
        config = AppConfig.from_mapping(
            {
                "timeout": "20",
                "rate_per_second": "0.5",
                "allow_private": "yes",
                "per_host_rate": "2.5",
                "budget_total": "100",
            }
        )
        assert config.timeout == 20
        assert config.rate_per_second == 0.5
        assert config.allow_private is True
        assert config.per_host_rate == 2.5
        assert config.budget_total == 100

    def test_none_per_host_rate(self) -> None:
        assert AppConfig.from_mapping({"per_host_rate": None}).per_host_rate is None

    def test_unknown_keys_go_to_extra(self) -> None:
        config = AppConfig.from_mapping({"custom": 1})
        assert config.extra == {"custom": 1}
        assert "extra" not in config.to_dict()

    @pytest.mark.parametrize(
        ("mapping", "message"),
        [
            ({"timeout": "abc"}, "timeout"),
            ({"rate_per_second": "fast"}, "rate_per_second"),
            ({"allow_private": "maybe"}, "boolean"),
        ],
    )
    def test_bad_values(self, mapping: dict[str, object], message: str) -> None:
        with pytest.raises(ConfigError, match=message):
            AppConfig.from_mapping(mapping)


class TestFileLoading:
    def test_yaml_file(self, tmp_path: Path) -> None:
        path = tmp_path / "config.yaml"
        path.write_text("timeout: 30\nrate_per_second: 0.4\n", encoding="utf-8")
        config = AppConfig.load(path)
        assert config.timeout == 30
        assert config.rate_per_second == 0.4

    def test_nested_root_key(self, tmp_path: Path) -> None:
        path = tmp_path / "config.yaml"
        path.write_text("reconpulse:\n  timeout: 25\n", encoding="utf-8")
        assert AppConfig.load(path).timeout == 25

    def test_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="not found"):
            AppConfig.load(tmp_path / "absent.yaml")

    def test_invalid_yaml(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.yaml"
        path.write_text("timeout: [", encoding="utf-8")
        with pytest.raises(ConfigError, match="invalid YAML"):
            AppConfig.load(path)

    def test_non_mapping_yaml(self, tmp_path: Path) -> None:
        path = tmp_path / "list.yaml"
        path.write_text("- 1\n", encoding="utf-8")
        with pytest.raises(ConfigError, match="mapping"):
            AppConfig.load(path)

    def test_empty_file_uses_defaults(self, tmp_path: Path) -> None:
        path = tmp_path / "empty.yaml"
        path.write_text("", encoding="utf-8")
        assert AppConfig.load(path).timeout == AppConfig().timeout

    def test_environment_overrides_file(self, tmp_path: Path) -> None:
        path = tmp_path / "config.yaml"
        path.write_text("timeout: 30\n", encoding="utf-8")
        config = AppConfig.load(path, environ={"RECONPULSE_TIMEOUT": "40", "PATH": "/usr/bin"})
        assert config.timeout == 40

    def test_overrides_beat_environment(self, tmp_path: Path) -> None:
        config = AppConfig.load(
            None,
            environ={"RECONPULSE_TIMEOUT": "40"},
            overrides={"timeout": 50, "concurrency": None},
        )
        assert config.timeout == 50
        assert config.concurrency == AppConfig().concurrency
