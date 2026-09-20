"""Process ownership using a persistent, OS-managed boundary lock file."""

import fcntl
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


class BoundaryBusyError(RuntimeError):
    """Another command currently owns the boundary."""


@contextmanager
def boundary_lock(path: Path) -> Iterator[int]:
    """Hold an exclusive flock; never unlink the inode used by other owners.

    Titus inherits the descriptor. Closing our descriptor releases ownership
    only after any surviving child has also closed its copy.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as stream:
        try:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise BoundaryBusyError(f"boundary busy: {path.parent.name}") from error
        # No explicit LOCK_UN: a surviving Titus must retain the shared lock.
        yield stream.fileno()
