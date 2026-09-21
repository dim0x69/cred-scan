"""Artifactory endpoint, repository, and Docker scope schemas; no runtime imports."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import computed_field

from cred_scan.backend.base_models import ScanBoundary, ScanScope, _version_hash


class ArtifactoryRepository(ScanBoundary):
    """An Artifactory repository containing Docker image targets."""

    kind: Literal["artifactory"] = "artifactory"


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
    def version_id(self) -> str:
        return _version_hash((self.digest,))
