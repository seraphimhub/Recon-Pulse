"""Configuration loading: defaults, YAML file, environment variables, CLI flags.

Precedence (lowest to highest): built-in defaults, config file, environment
variables, explicit CLI overrides. Every default is safe: passive mode, low rate,
bounded response size, and a User-Agent that identifies the tool.
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any

import yaml

from .errors import ConfigError

ENV_PREFIX = "RECONPULSE_"

DEFAULT_USER_AGENT = "ReconPulse/{version} (authorized security testing; +https://github.com/your-org/reconpulse)"


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off", ""}:
        return False
    raise ConfigError(f"cannot interpret {value!r} as a boolean")


def _as_float(value: Any, name: str) -> float:
    try:
        return float(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{name} must be a number, got {value!r}") from exc


def _as_int(value: Any, name: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{name} must be an integer, got {value!r}") from exc


@dataclass
class AppConfig:
    """Runtime configuration for a scan."""

    timeout: int = 15
    max_redirects: int = 5
    rate_per_second: float = 1.0
    per_host_rate: float | None = None
    concurrency: int = 5
    max_response_bytes: int = 2_000_000
    user_agent: str = DEFAULT_USER_AGENT
    allow_private: bool = False
    verify_tls: bool = True
    log_level: str = "INFO"
    log_file: str | None = None
    output_dir: str = "reconpulse-output"
    cache_enabled: bool = True
    js_max_files: int = 50
    budget_total: int | None = None
    budget_per_host: int | None = None
    circuit_failure_threshold: int = 5
    circuit_timeout_streak: int = 3
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.timeout <= 0:
            raise ConfigError("timeout must be positive")
        if self.rate_per_second <= 0:
            raise ConfigError("rate_per_second must be positive")
        if self.concurrency <= 0:
            raise ConfigError("concurrency must be positive")
        if self.max_response_bytes <= 0:
            raise ConfigError("max_response_bytes must be positive")

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("extra", None)
        return data

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> AppConfig:
        known = {f.name for f in fields(cls)}
        kwargs: dict[str, Any] = {}
        extra: dict[str, Any] = {}
        for key, value in data.items():
            if key not in known:
                extra[key] = value
                continue
            if key in {
                "timeout",
                "max_redirects",
                "concurrency",
                "max_response_bytes",
                "js_max_files",
                "circuit_failure_threshold",
                "circuit_timeout_streak",
            }:
                kwargs[key] = _as_int(value, key)
            elif key == "per_host_rate":
                kwargs[key] = None if value is None else _as_float(value, key)
            elif key == "rate_per_second":
                kwargs[key] = _as_float(value, key)
            elif key in {"budget_total", "budget_per_host"}:
                kwargs[key] = None if value is None else _as_int(value, key)
            elif key in {"allow_private", "verify_tls", "cache_enabled"}:
                kwargs[key] = _as_bool(value)
            else:
                kwargs[key] = value
        kwargs["extra"] = extra
        return cls(**kwargs)

    @classmethod
    def load(
        cls,
        path: str | Path | None = None,
        *,
        environ: dict[str, str] | None = None,
        overrides: dict[str, Any] | None = None,
    ) -> AppConfig:
        config = cls()
        if path:
            file_path = Path(path)
            if not file_path.is_file():
                raise ConfigError(f"config file not found: {file_path}")
            try:
                raw = yaml.safe_load(file_path.read_text(encoding="utf-8")) or {}
            except yaml.YAMLError as exc:
                raise ConfigError(f"invalid YAML in {file_path}: {exc}") from exc
            if not isinstance(raw, dict):
                raise ConfigError(f"config file {file_path} must contain a mapping")
            if "reconpulse" in raw and isinstance(raw["reconpulse"], dict):
                raw = raw["reconpulse"]
            config = cls.from_mapping(raw)

        env = os.environ if environ is None else environ
        env_values: dict[str, Any] = {}
        for key, value in env.items():
            if not key.startswith(ENV_PREFIX):
                continue
            name = key[len(ENV_PREFIX) :].lower()
            if name:
                env_values[name] = value
        if env_values:
            merged = config.to_dict()
            merged.update(env_values)
            config = cls.from_mapping(merged)

        if overrides:
            cleaned = {k: v for k, v in overrides.items() if v is not None}
            if cleaned:
                merged = config.to_dict()
                merged.update(cleaned)
                config = cls.from_mapping(merged)
        return config
