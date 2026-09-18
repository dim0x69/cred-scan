"""Aggregate backend schemas: shared unions, immutable targets, and inventories."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, computed_field, model_validator

from cred_scan.backend.adapters.artifactory.models import (
    ArtifactoryBackendConfig as ArtifactoryBackendConfig,
)
from cred_scan.backend.adapters.artifactory.models import (
    ArtifactoryRepository as ArtifactoryRepository,
)
from cred_scan.backend.adapters.artifactory.models import (
    DockerImageScanScope as DockerImageScanScope,
)
from cred_scan.backend.base_models import (
    BackendConfig as BackendConfig,
)
from cred_scan.backend.base_models import (
    ScanBoundary as ScanBoundary,
)
from cred_scan.backend.base_models import (
    ScanScope as ScanScope,
)
from cred_scan.backend.base_models import (
    _pin_hash,
)


# H move to a GHES adapter.ghes module
class GitOrganization(ScanBoundary):
    """A GHES organization containing Git repository targets."""

    kind: Literal["git-organization"] = "git-organization"


ScanBoundaryRef = ArtifactoryRepository | GitOrganization


# H move to a adapters.artifactory.package module.
class PackageScanScope(ScanScope):
    """Future package scan-scope shape."""

    kind: Literal["package"] = "package"
    name: str
    uri: str
    digest: str
    ecosystem: str

    @computed_field
    @property
    def id(self) -> str:
        return f"{self.ecosystem}:{self.name}"

    @computed_field
    @property
    def pin_id(self) -> str:
        return _pin_hash((self.uri, self.digest))


# H move to a GHES adapter.ghes module
class GitRepositoryScanScope(ScanScope):
    """A Git repository scan scope pinned to a commit."""

    kind: Literal["git"] = "git"
    remote: str
    commit: str
    branch: Literal["main"] = "main"
    commit_timestamp: datetime

    @computed_field
    @property
    def id(self) -> str:
        return self.remote.removesuffix(".git")

    @computed_field
    @property
    def pin_id(self) -> str:
        return _pin_hash((self.commit, self.branch))


ScanScopeRef = DockerImageScanScope | PackageScanScope | GitRepositoryScanScope


def target_id_for(scope: ScanScope) -> str:
    """Return the stable ID for one immutable scan-scope pin."""
    return f"{scope.id}@{scope.pin_id}"


class ContentLocation(BaseModel):
    """Source-neutral locator for one file in one immutable target."""

    target_id: str = Field(min_length=1)
    locator: str = Field(min_length=1)
    source_path: str
    filename: str


class ScanTargetResult(BaseModel):
    """A replaceable target execution result."""

    status: Literal["pending", "running", "scanned", "partial", "failed"] = "pending"
    errors: tuple[str, ...] = ()
    retryable: bool = True
    return_code: int | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None


class ScanTarget(BaseModel):
    """One immutable scan-scope pin owned by one boundary and worker."""

    id: str
    backend_id: str
    boundary: ScanBoundaryRef
    scope: ScanScopeRef
    lifecycle: Literal["current", "superseded"] = "current"
    result: ScanTargetResult = Field(default_factory=ScanTargetResult)

    @model_validator(mode="after")
    def validate_pin_id(self) -> "ScanTarget":
        if self.id != target_id_for(self.scope):
            raise ValueError("target ID must match its immutable source pin")
        return self


class ScanBoundaryInventory(BaseModel):
    """One complete boundary inventory with retained scan-scope pins."""

    schema_version: Literal[7] = 7
    generated_at: datetime
    backend: BackendConfig
    boundary: ScanBoundaryRef
    lifecycle: Literal["active", "stale"] = "active"
    stale_reason: str | None = None
    targets: tuple[ScanTarget, ...] = ()
    errors: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_target_ownership(self) -> "ScanBoundaryInventory":
        if any(
            target.backend_id != self.backend.name or target.boundary != self.boundary
            for target in self.targets
        ):
            raise ValueError(
                "inventory targets must belong to its backend and boundary"
            )
        target_ids = [target.id for target in self.targets]
        if len(target_ids) != len(set(target_ids)):
            raise ValueError("inventory target IDs must be unique")
        return self

    def replace_target(self, replacement: ScanTarget) -> "ScanBoundaryInventory":
        existing = next(
            (item for item in self.targets if item.id == replacement.id), None
        )
        if existing is None:
            raise KeyError(f"target does not exist: {replacement.id}")
        if existing.model_dump(exclude={"result"}) != replacement.model_dump(
            exclude={"result"}
        ):
            raise ValueError("target updates must preserve pinned source identity")
        self.targets = tuple(
            replacement if target.id == replacement.id else target
            for target in self.targets
        )
        return self

    def complete_target(self, target: ScanTarget) -> "ScanBoundaryInventory":
        if target.result.status not in {"scanned", "partial", "failed"}:
            raise ValueError("target updates must be terminal")
        existing = next((item for item in self.targets if item.id == target.id), None)
        if existing is None:
            raise KeyError(f"target does not exist: {target.id}")
        if existing.result.status != "running":
            raise ValueError(f"target was not reserved: {target.id}")
        return self.replace_target(target)
