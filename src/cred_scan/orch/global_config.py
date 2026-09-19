"""Process-wide resolved application configuration."""

from __future__ import annotations

from cred_scan.orch.models import AppConfig
from cred_scan.scan.exclusions import load_exclusions
from cred_scan.scan.models import ExclusionPolicy

CONFIG: AppConfig | None = None
_EXCLUSIONS: ExclusionPolicy | None = None


def set_config(config: AppConfig) -> None:
    global CONFIG, _EXCLUSIONS
    CONFIG = config
    _EXCLUSIONS = None


def get_config() -> AppConfig:
    if CONFIG is None:
        raise RuntimeError("application configuration has not been loaded")
    return CONFIG


def get_exclusions() -> ExclusionPolicy:
    """Load exclusions at first use and share them until the next run."""
    global _EXCLUSIONS
    if _EXCLUSIONS is None:
        _EXCLUSIONS = load_exclusions(get_config().exclusions)
    return _EXCLUSIONS
