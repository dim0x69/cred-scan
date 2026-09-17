"""Shared workspace configuration and transient boundary paths."""

from __future__ import annotations

from pathlib import Path
from pydantic import BaseModel, ConfigDict, Field


class WorkspaceConfig(BaseModel):
    """Resolved workspace root and an optional results-directory override."""

    model_config = ConfigDict(validate_by_name=True)

    workspace_dir: Path = Field(alias="workspace-dir")
    results_dir: Path = Field(
        alias="results-dir",
        default_factory=lambda data: data["workspace_dir"],
    )


class BoundaryPaths(BaseModel):
    """Transient immutable paths for one boundary; construction performs no I/O."""

    model_config = ConfigDict(frozen=True)

    boundary_id: str
    boundary_dir: Path

    @property
    def inventory(self) -> Path:
        return self.boundary_dir / "inventory.json"

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
