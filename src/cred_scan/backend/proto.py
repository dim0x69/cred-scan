"""Backend-facing protocols and content transfer models."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from contextlib import AbstractContextManager
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from cred_scan.backend.models import (
        ContentLocation,
        ContentRead,
        ScanBoundaryInventory,
        ScanTarget,
    )


ScratchDirectory = Callable[[], AbstractContextManager[Path]]


class UnsupportedTitusTargetError(RuntimeError):
    """The backend cannot construct a Titus invocation for a target."""


class BackendAdapter(ABC):
    """Runtime backend contract and shared identity surface."""

    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    async def aclose(self) -> None: ...

    @abstractmethod
    def titus_scan_arguments(
        self, inventory: ScanBoundaryInventory, target: ScanTarget
    ) -> tuple[str, ...]: ...

    @abstractmethod
    def content_reader(
        self,
        scratch_dir: ScratchDirectory,
    ) -> ContentReader:
        """Create a reader that interprets immutable occurrence paths directly."""
        ...

    @abstractmethod
    async def inventory(self, boundary_id: str) -> ScanBoundaryInventory: ...


class ContentReader(Protocol):
    """Resolve and read requested backend paths without boundary context.

    Implementations do not cache resolved locations or retrieved content.
    Calls propagate cancellation after settling
    non-cancellable workers that still use scratch. The owner then closes the
    reader; adapters must not
    leave detached workers accessing files that aclose removes.
    """

    async def resolve_location(self, raw_path: str) -> ContentLocation: ...

    async def read(self, location: ContentLocation | str) -> ContentRead:
        """Return complete exact bytes and metadata for one location."""
        ...

    async def aclose(self) -> None: ...
