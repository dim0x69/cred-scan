"""Artifactory package scan-scope schema; no runtime imports."""

from __future__ import annotations

from typing import Literal

from pydantic import computed_field

from cred_scan.backend.base_models import ScanScope, _pin_hash


class PackageScanScope(ScanScope):
    """A package scan scope pinned to an immutable artifact."""

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
