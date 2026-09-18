"""Typed persistence and exclusive operation ownership."""

from collections.abc import Iterator
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Protocol, TypeVar

from pydantic import BaseModel

from cred_scan.common.models import BoundaryPaths

DocumentT = TypeVar("DocumentT", bound=BaseModel)


class WorkspaceProtocol(Protocol):
    """Resolved layout and validated JSON I/O, without feature lifecycle policy."""

    @property
    def workspace_dir(self) -> Path: ...

    def boundary(self, boundary_id: str) -> BoundaryPaths: ...

    def inventory_boundaries(self) -> Iterator[BoundaryPaths]: ...

    def operation_lock(self) -> AbstractContextManager[None]: ...

    def read(self, path: Path, model_type: type[DocumentT]) -> DocumentT | None: ...

    def write(
        self, path: Path, document: DocumentT, model_type: type[DocumentT]
    ) -> None: ...
