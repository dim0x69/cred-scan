"""Backend-facing protocols and content transfer models."""

from __future__ import annotations

from typing import Protocol

from cred_scan.backend.models import (
    ContentLocation,
    ContentRead,
    ScanBoundaryRef,
    ScanBoundaryInventory,
    ScanTarget,
)


class UnsupportedTitusTargetError(RuntimeError):
    """The backend cannot construct a Titus invocation for a target."""


class BackendAdapter(Protocol):
    @property
    def name(self) -> str: ...

    async def aclose(self) -> None: ...

    def titus_scan_arguments(
        self, inventory: ScanBoundaryInventory, target: ScanTarget
    ) -> tuple[str, ...]: ...

    def content_reader(
        self, boundary: ScanBoundaryRef, targets: tuple[ScanTarget, ...]
    ) -> ContentReader:
        """Create a reader bound to a report boundary and nonempty pinned targets."""
        ...

    async def inventory(self) -> list[ScanBoundaryInventory]: ...


class ContentReader(Protocol):
    """Resolve and read backend paths for one scan boundary.

    Calls propagate cancellation after settling non-cancellable workers that
    still use scratch. The owner then closes the reader; adapters must not
    leave detached workers accessing files that aclose removes.
    """

    async def resolve_location(self, raw_path: str) -> ContentLocation: ...

    async def read(self, location: ContentLocation) -> ContentRead:
        """Return complete exact bytes and metadata for one location."""
        ...

    async def aclose(self) -> None: ...
