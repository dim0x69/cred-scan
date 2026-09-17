"""Artifactory endpoint, repository, and Docker scope schemas; no runtime imports."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import computed_field

from backend.base_models import BackendConfig, ScanBoundary, ScanScope, _pin_hash


class ArtifactoryBackendConfig(BackendConfig):
    """Artifactory endpoint configuration for the runtime backend."""

    kind: Literal["artifactory"] = "artifactory"
    base_url: str
    platform: str = "linux/amd64"


class ArtifactoryRepository(ScanBoundary):
    """An Artifactory repository containing Docker image targets."""

    kind: Literal["artifactory"] = "artifactory"


class DockerImageScanScope(ScanScope):
    """A Docker scan scope pinned by the Artifactory backend."""

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
        # Titus scans the selected child manifest, not the parent index or
        # selection label. One child digest must have one resolvable target.
        return _pin_hash((self.digest,))
