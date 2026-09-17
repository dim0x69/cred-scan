"""Backend-facing protocols and content transfer models."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from cred_scan.backend.models import (
    FileContent,
    ResolvedProvenance,
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

    async def resolve_provenance(
        self, raw_path: str, *, target_id: str | None = None
    ) -> ResolvedProvenance: ...

    async def read_file(self, path: str) -> FileContent:
        """Return the complete bytes of the exact pinned source file."""
        ...

    async def list_files(self, directory: str) -> tuple[str, ...]:
        """Return locators accepted unchanged by ``read_file``."""
        ...

    async def extract_file(self, path: str, destination: Path) -> Path:
        """Write the complete exact source file to ``destination``."""
        ...

    async def aclose(self) -> None: ...
