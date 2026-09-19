"""Process-wide resolved application configuration."""

from __future__ import annotations

from cred_scan.orch.models import AppConfig

CONFIG: AppConfig | None = None


def set_config(config: AppConfig) -> None:
    global CONFIG
    CONFIG = config


def get_config() -> AppConfig:
    if CONFIG is None:
        raise RuntimeError("application configuration has not been loaded")
    return CONFIG
