"""Docker-specific Artifactory configuration and scan scope schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import computed_field

from cred_scan.backend.base_models import BackendConfig, ScanScope, _pin_hash


class ArtifactoryDockerConfig(BackendConfig):
    """Configuration for the Artifactory Docker backend adapter."""

    kind: Literal["artifactory_docker"] = "artifactory_docker"
    base_url: str
    platform: str = "linux/amd64"


class DockerImageScanScope(ScanScope):
    """A Docker scan scope selected by the Artifactory Docker backend."""

    kind: Literal["docker"] = "docker"
    image: str
    digest: str
    platform: str
    root_digest: str
    tags: tuple[str, ...] = ()
    manifest_timestamp: datetime

    @computed_field
    @property
    def id(self) -> str:
        return self.image

    @computed_field
    @property
    def pin_id(self) -> str:
        return _pin_hash((self.digest,))
