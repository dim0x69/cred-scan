"""Aggregate backend schemas: shared unions, immutable targets, and inventories."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, model_validator

from cred_scan.backend.adapters.artifactory.models import ArtifactoryRepository
from cred_scan.backend.adapters.artifactory.docker import DockerImageScanScope
from cred_scan.backend.adapters.artifactory.package import PackageScanScope
from cred_scan.backend.adapters.ghes import GitOrganization, GitRepositoryScanScope

from cred_scan.backend.base_models import ScanScope

ScanBoundaryRef = ArtifactoryRepository | GitOrganization


ScanScopeRef = DockerImageScanScope | PackageScanScope | GitRepositoryScanScope


class BoundaryRecord(BaseModel):
    """Durable boundary enrollment and current backend availability."""

    schema_version: Literal[1] = 1
    backend_id: str
    boundary: ScanBoundaryRef
    availability: Literal["available", "absent"] = "available"


def target_id_for(scope: ScanScope) -> str:
    """Return the stable ID for one immutable scan target."""
    return f"{scope.id}@{scope.version_id}"


class ContentLocation(BaseModel):
    """A normalized backend locator used during one read operation."""

    locator: str = Field(min_length=1)
    source_path: str
    filename: str


@dataclass(frozen=True)
class ContentRead:
    """Bytes and source metadata returned by a backend content read."""

    content: bytes
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
    """One immutable source version owned by its containing inventory."""

    id: str
    scope: ScanScopeRef
    result: ScanTargetResult = Field(default_factory=ScanTargetResult)

    @model_validator(mode="after")
    def validate_version_id(self) -> "ScanTarget":
        if self.id != target_id_for(self.scope):
            raise ValueError("target ID must match its immutable source version")
        return self


class ScanTargetInventory(BaseModel):
    """The latest selected scan targets and their results for one boundary."""

    schema_version: Literal[11] = 11
    publication_pending: bool = False
    generated_at: datetime
    boundary: ScanBoundaryRef
    targets: tuple[ScanTarget, ...] = ()
    errors: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_selection(self) -> "ScanTargetInventory":
        target_ids = [target.id for target in self.targets]
        if len(target_ids) != len(set(target_ids)):
            raise ValueError("inventory target IDs must be unique")
        scope_ids = [(target.scope.kind, target.scope.id) for target in self.targets]
        if len(scope_ids) != len(set(scope_ids)):
            raise ValueError("inventory must select only one scan target per scope")
        return self
