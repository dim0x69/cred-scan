"""Orchestration configuration and boundary layout models."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

from pydantic import (
    AnyHttpUrl,
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    field_validator,
    model_validator,
)
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)
from cred_scan.scan.models import ExclusionFiles

class ArtifactoryDockerBackendConfig(BaseModel):
    """Validated settings for the implemented Artifactory Docker backend."""

    model_config = ConfigDict(extra="forbid")

    name: Literal["artifactory_docker"]
    base_url: str
    platform: str

    @field_validator("base_url")
    @classmethod
    def require_https_url(cls, value: str) -> str:
        parsed = AnyHttpUrl(value)
        if parsed.scheme != "https":
            raise ValueError("Artifactory base_url must use HTTPS")
        return value

    @field_validator("platform")
    @classmethod
    def validate_platform(cls, value: str) -> str:
        if re.fullmatch(
            r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+){1,2}",
            value,
        ) is None:
            raise ValueError("platform must be os/architecture[/variant]")
        return value


class WorkspaceConfig(BaseModel):
    """Resolved workspace root used for all persisted results."""

    model_config = ConfigDict(validate_by_name=True, extra="forbid")

    workspace_dir: Path = Field(alias="workspace-dir")


class BoundaryPaths(BaseModel):
    """Transient immutable paths for one boundary; construction performs no I/O."""

    model_config = ConfigDict(frozen=True)

    boundary_id: str
    boundary_dir: Path

    @property
    def record(self) -> Path:
        return self.boundary_dir / "boundary.json"

    @property
    def scan_targets(self) -> Path:
        return self.boundary_dir / "scantargets.json"

    @property
    def operation_lock(self) -> Path:
        return self.boundary_dir / ".operation.lock"

    @property
    def report(self) -> Path:
        return self.boundary_dir / "report.json"

    @property
    def credentials(self) -> Path:
        return self.boundary_dir / "credentials.json"

    @property
    def datastore(self) -> Path:
        return self.boundary_dir / "titus.ds"

    @property
    def scratch_parent(self) -> Path:
        return self.boundary_dir / "scratch"


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
    backends: tuple[ArtifactoryDockerBackendConfig, ...] = Field(min_length=1)
    artifactory_access_token: SecretStr | None = Field(
        default=None,
        validation_alias="ARTIFACTORY_ACCESS_TOKEN",
        repr=False,
    )
    azure_openai_api_key: SecretStr | None = Field(
        default=None,
        validation_alias="AZURE_OPENAI_API_KEY",
        repr=False,
    )

    @model_validator(mode="after")
    def reject_duplicate_backend_names(self) -> AppConfig:
        names = tuple(backend.name for backend in self.backends)
        if len(set(names)) != len(names):
            raise ValueError("configured backend names must be unique")
        return self

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
