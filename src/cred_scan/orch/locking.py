"""Process ownership using persistent, OS-managed workspace and boundary locks."""

import asyncio
import fcntl
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path


class BoundaryBusyError(RuntimeError):
    """Another command currently owns the boundary."""


@asynccontextmanager
async def workspace_lock(path: Path, *, shared: bool) -> AsyncIterator[int]:
    """Hold a cross-process workspace gate, waiting without blocking the event loop.

    Inventory commands take an exclusive gate; source commands take a shared gate.
    The descriptor is inherited by Titus so a surviving child retains the gate.
    Do not explicitly unlock: closing the parent's descriptor releases the lock
    only after every inherited descriptor has also been closed.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as stream:
        operation = fcntl.LOCK_SH if shared else fcntl.LOCK_EX
        while True:
            try:
                fcntl.flock(stream.fileno(), operation | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                await asyncio.sleep(0.05)
        yield stream.fileno()


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
