"""GHES boundary and Git repository scope schemas; no runtime imports."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import computed_field

from cred_scan.backend.base_models import ScanBoundary, ScanScope, _version_hash


class GitOrganization(ScanBoundary):
    """A GHES organization containing Git repository targets."""

    kind: Literal["git-organization"] = "git-organization"


class GitRepositoryScanScope(ScanScope):
    """A Git repository scan scope at an immutable commit."""

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
    def version_id(self) -> str:
        return _version_hash((self.commit, self.branch))
