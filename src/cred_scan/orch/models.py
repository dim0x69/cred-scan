"""Orchestration configuration and boundary layout models."""

from __future__ import annotations

from cred_scan.backend.adapters.artifactory.models import ArtifactoryBackendConfig
from cred_scan.common.models import WorkspaceConfig
from pydantic import BaseModel, Field
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)
from cred_scan.scan.models import ExclusionFiles


class TitusConfig(BaseModel):
    executable: str
    arguments: tuple[str, ...] = ()
    internal_workers: int = Field(default=1, ge=1)


class JudgeLayerToolsConfig(BaseModel):
    """Whether the judge may read reported source locations."""

    enabled: bool = True


class JudgeConfig(BaseModel):
    provider: str = "azure"
    model: str = "gpt-5.6-luna"
    base_url: str | None = None
    api_version: str | None = None
    max_iterations: int = Field(default=10, ge=1, le=10)
    layer_tools: JudgeLayerToolsConfig = Field(default_factory=JudgeLayerToolsConfig)


class AppConfig(BaseSettings):
    workspace: WorkspaceConfig
    titus: TitusConfig
    judge: JudgeConfig = Field(default_factory=JudgeConfig)
    exclusions: ExclusionFiles
    backend: ArtifactoryBackendConfig
    artifactory_api_key: str | None = Field(
        default=None,
        validation_alias="ARTIFACTORY_API_KEY",
        repr=False,
    )
    azure_openai_api_key: str | None = Field(
        default=None,
        validation_alias="AZURE_OPENAI_API_KEY",
        repr=False,
    )

    model_config = SettingsConfigDict(
        extra="ignore",
        validate_by_name=True,
        env_file=None,
        env_file_encoding="utf-8",
        yaml_file=None,
        yaml_file_encoding="utf-8",
    )

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        yaml_settings = YamlConfigSettingsSource(settings_cls)
        return (
            init_settings,
            yaml_settings,
            env_settings,
            dotenv_settings,
        )