"""Storage port required by backend adapters."""

from typing import Protocol

from cred_scan.common.models import BoundaryPaths


class WorkspaceProtocol(Protocol):
    """Only the boundary path lookup needed by backend adapters."""

    def boundary(self, boundary_id: str) -> BoundaryPaths: ...
