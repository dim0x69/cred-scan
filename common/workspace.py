"""Boundary paths, validated atomic JSON checkpoints, locking, and scratch."""

from __future__ import annotations

import fcntl
import json
import os
from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import quote, unquote

from common.models import BoundaryPaths, WorkspaceConfig
from common.proto import DocumentT, WorkspaceProtocol


class WorkspaceBusyError(RuntimeError):
    """Another inventory, scan, judge, or extract operation owns the workspace."""


class Workspace(WorkspaceProtocol):
    def __init__(self, config: WorkspaceConfig) -> None:
        self._results_dir = config.results_dir

    @property
    def results_dir(self) -> Path:
        return self._results_dir

    def boundary(self, boundary_id: str) -> BoundaryPaths:
        return BoundaryPaths(
            boundary_id=boundary_id,
            boundary_dir=self.results_dir / quote(boundary_id, safe=""),
        )

    def inventory_boundaries(self) -> Iterator[BoundaryPaths]:
        for inventory in self.results_dir.glob("*/inventory.json"):
            yield self.boundary(unquote(inventory.parent.name))

    def operation_lock(self) -> AbstractContextManager[None]:
        return _operation_lock(self.results_dir / ".operation.lock")

    def read(self, path: Path, model_type: type[DocumentT]) -> DocumentT | None:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        if not isinstance(payload, dict):
            raise ValueError(f"expected JSON object: {path}")
        return model_type.model_validate(payload)

    def write(
        self, path: Path, document: DocumentT, model_type: type[DocumentT]
    ) -> None:
        if not isinstance(document, model_type):
            raise TypeError(
                f"expected {model_type.__name__}, got {type(document).__name__}"
            )
        # model_copy bypasses validation. Revalidate before touching the destination.
        validated = model_type.model_validate(document.model_dump(mode="json"))
        payload = validated.model_dump(mode="json")
        path.parent.mkdir(parents=True, exist_ok=True)
        with _exclusive_lock(path.parent):
            temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
            try:
                with temporary.open("w", encoding="utf-8") as stream:
                    json.dump(payload, stream, indent=2, sort_keys=True)
                    stream.write("\n")
                    stream.flush()
                    os.fsync(stream.fileno())
                temporary.replace(path)
            finally:
                try:
                    temporary.unlink(missing_ok=True)
                except OSError:
                    pass  # Cleanup must not hide the write failure.


@contextmanager
def scratch_dir(parent: Path) -> Iterator[Path]:
    """Own one temporary child; leave other live scratch sessions alone."""
    parent.mkdir(parents=True, exist_ok=True)
    try:
        with TemporaryDirectory(prefix="scratch-", dir=parent) as directory:
            yield Path(directory)
    finally:
        try:
            parent.rmdir()
        except OSError:
            pass


@contextmanager
def _operation_lock(path: Path) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise WorkspaceBusyError(
                f"workspace operation already active: {path.parent}"
            ) from error
        try:
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


@contextmanager
def _exclusive_lock(directory: Path) -> Iterator[None]:
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)
