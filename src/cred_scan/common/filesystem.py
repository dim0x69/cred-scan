"""Small filesystem primitives shared by boundary-owned adapters."""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory


class ResourceBusyError(RuntimeError):
    """Another operation owns a requested filesystem resource."""


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


def fsync_directory(directory: Path) -> None:
    """Flush directory metadata after an atomic replacement."""
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
