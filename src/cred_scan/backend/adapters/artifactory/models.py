"""Artifactory endpoint, repository, and Docker scope schemas; no runtime imports."""

from __future__ import annotations

from typing import Literal
from cred_scan.backend.base_models import ScanBoundary
from cred_scan.backend.adapters.artifactory.docker import (
    ArtifactoryDockerConfig as ArtifactoryBackendConfig,  # noqa: F401
    DockerImageScanScope as DockerImageScanScope,
)


class ArtifactoryRepository(ScanBoundary):
    """An Artifactory repository containing Docker image targets."""

    kind: Literal["artifactory"] = "artifactory"
