"""GHES boundary and Git repository scope schemas; no runtime imports."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import computed_field

from cred_scan.backend.base_models import ScanBoundary, ScanScope, _pin_hash


class GitOrganization(ScanBoundary):
    """A GHES organization containing Git repository targets."""

    kind: Literal["git-organization"] = "git-organization"


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
