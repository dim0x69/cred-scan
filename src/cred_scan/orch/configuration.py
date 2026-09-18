"""Config-relative YAML loading implementation."""

from __future__ import annotations

import logging
from pathlib import Path

from pydantic_settings import SettingsConfigDict

from cred_scan.orch.models import AppConfig
from cred_scan.orch.proto import ConfigLoader

LOGGER = logging.getLogger(__name__)


def _resolve_path(path: Path, base: Path) -> Path:
    return path if path.is_absolute() else (base / path).resolve()


def _resolve_config_paths(config: AppConfig, base: Path) -> AppConfig:
    config.workspace.workspace_dir = _resolve_path(
        config.workspace.workspace_dir, base
    )
    config.exclusions.paths = _resolve_path(config.exclusions.paths, base)
    config.exclusions.credentials = _resolve_path(
        config.exclusions.credentials, base
    )
    config.titus.executable = str(
        _resolve_path(Path(config.titus.executable), base)
    )
    return config


class YamlConfigLoader(ConfigLoader):
    async def load(self, path: Path) -> AppConfig:
        config_path = path.expanduser().resolve()
        try:
            if not config_path.is_file():
                raise FileNotFoundError(config_path)
            configured = type(
                "ConfiguredAppConfig",
                (AppConfig,),
                {
                    "model_config": SettingsConfigDict(
                        **{
                            **AppConfig.model_config,
                            "yaml_file": config_path,
                            "env_file": config_path.parent / ".env",
                        }
                    )
                },
            )
            return _resolve_config_paths(configured(), config_path.parent)
        except Exception:
            LOGGER.exception("configuration load failed path=%s", config_path)
            raise
