"""Backend-scoped workspace discovery and command lifetime."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from pathlib import Path
from urllib.parse import quote, unquote

from cred_scan.backend.adapters.artifactory.docker import ArtifactoryDockerBackend
from cred_scan.backend.models import (
    BackendWorkspaceRecord,
    BoundaryRecord,
)
from cred_scan.backend.proto import BackendAdapter
from cred_scan.orch.boundary import Boundary
from cred_scan.orch.global_config import get_config
from cred_scan.orch.json_io import write_json_atomic
from cred_scan.orch.locking import BoundaryBusyError

LOGGER = logging.getLogger(__name__)


def configured_backend_names() -> tuple[str, ...]:
    """Return configured backend names in deterministic order."""
    return tuple(sorted(backend.name for backend in get_config().backends))


def _backend_record(path: Path) -> BackendWorkspaceRecord:
    try:
        record = BackendWorkspaceRecord.model_validate_json(
            path.read_text(encoding="utf-8")
        )
    except (FileNotFoundError, ValueError) as error:
        raise ValueError(f"invalid backend workspace record: {path}") from error
    if unquote(path.parent.name) != record.name:
        raise ValueError(
            f"backend record does not match directory: {path}"
        )
    return record


def load_configured_backend(backend_name: str) -> BackendAdapter:
    """Construct the configured adapter for one backend identity."""
    config = get_config()
    backend_config = next(
        (item for item in config.backends if item.name == backend_name),
        None,
    )
    if backend_config is None:
        raise ValueError(f"backend is not configured: {backend_name}")
    return ArtifactoryDockerBackend(
        name=backend_config.name,
        base_url=backend_config.base_url,
        platform=backend_config.platform,
    )


def _persisted_backend_paths(
    workspace_dir: Path,
    requested_backend: str | None = None,
) -> tuple[Path, ...]:
    if requested_backend is not None:
        path = workspace_dir / quote(requested_backend, safe="") / "backend.json"
        if not path.is_file():
            raise ValueError(
                f"backend workspace has not been inventoried: {requested_backend}"
            )
        return (path,)

    if not workspace_dir.is_dir():
        raise ValueError(f"no persisted backend workspaces: {workspace_dir}")
    paths = tuple(sorted(workspace_dir.glob("*/backend.json")))
    if not paths:
        raise ValueError(f"no persisted backend workspaces: {workspace_dir}")
    return paths


def iter_persisted_workspaces(
    workspace_dir: Path,
    requested_backend: str | None = None,
) -> Iterator[Workspace]:
    """Yield one configured backend workspace at a time."""
    for marker in _persisted_backend_paths(workspace_dir, requested_backend):
        record = _backend_record(marker)
        yield Workspace(
            load_configured_backend(record.name),
            marker.parent,
        )


def iter_configured_workspaces(
    workspace_dir: Path,
    requested_backend: str | None = None,
) -> Iterator[Workspace]:
    """Yield configured backend workspaces, creating paths when needed."""
    names = configured_backend_names()
    if requested_backend is not None:
        if requested_backend not in names:
            raise ValueError(f"backend is not configured: {requested_backend}")
        names = (requested_backend,)
    for name in names:
        yield Workspace(
            load_configured_backend(name),
            workspace_dir / quote(name, safe=""),
            create=True,
        )


def _write_backend_record(path: Path, record: BackendWorkspaceRecord) -> None:
    write_json_atomic(path, record.model_dump(mode="json"))


async def _new_boundary_ids(
    discovered: AsyncIterator[str],
    registered: set[str],
    limit: int | None,
) -> AsyncIterator[str]:
    """Yield unique unregistered IDs and always close backend discovery."""
    selected = 0
    seen: set[str] = set()
    try:
        if limit == 0:
            return
        async for boundary_id in discovered:
            if boundary_id in registered or boundary_id in seen:
                continue
            seen.add(boundary_id)
            yield boundary_id
            selected += 1
            if limit is not None and selected >= limit:
                break
    finally:
        close = getattr(discovered, "aclose", None)
        if close is not None:
            await close()


class Workspace:
    """Own one backend lifetime and its persisted boundaries."""

    def __init__(
        self,
        backend: BackendAdapter,
        backend_dir: Path,
        *,
        create: bool = False,
    ) -> None:
        self.backend = backend
        self.backend_name = backend.name
        self._backend_dir = backend_dir
        self._workspace_dir = backend_dir.parent
        self._boundaries_dir = self._backend_dir / "boundaries"
        self._workspace_dir.mkdir(parents=True, exist_ok=True)

        expected_dir = self._workspace_dir / quote(self.backend_name, safe="")
        if self._backend_dir != expected_dir:
            raise ValueError(
                f"backend directory does not match backend: {self._backend_dir}"
            )
        if self._backend_dir.exists() and not self._backend_dir.is_dir():
            raise ValueError(f"backend workspace is not a directory: {self._backend_dir}")
        if not self._backend_dir.exists():
            if not create:
                raise ValueError(
                    f"backend workspace has not been inventoried: {self.backend_name}"
                )
            self._backend_dir.mkdir(parents=True)
        marker = self._backend_dir / "backend.json"
        if marker.exists():
            if _backend_record(marker).name != self.backend_name:
                raise ValueError(
                    f"backend workspace does not match selected backend: {self._backend_dir}"
                )
        elif not create:
            raise ValueError(f"missing backend workspace record: {marker}")
        self._boundaries_dir.mkdir(parents=True, exist_ok=True)

        self._boundaries: tuple[Boundary, ...] | None = None
        self._closed = False

    async def __aenter__(self) -> "Workspace":
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.close()

    @property
    def workspace_dir(self) -> Path:
        return self._workspace_dir

    @property
    def backend_workspace_dir(self) -> Path:
        return self._backend_dir

    @property
    def boundaries(self) -> tuple[Boundary, ...]:
        """Construct unloaded boundaries in deterministic ID order."""
        if self._boundaries is None:
            self._boundaries = tuple(
                Boundary(self.backend, record_path.parent)
                for record_path in sorted(
                    self._boundaries_dir.glob("*/boundary.json"),
                    key=lambda item: unquote(item.parent.name),
                )
            )
        return self._boundaries

    def _registered_boundary_ids(self) -> set[str]:
        boundary_ids = set()
        for record_path in self._boundaries_dir.glob("*/boundary.json"):
            boundary_id = unquote(record_path.parent.name)
            record = Boundary._read(record_path, BoundaryRecord)
            if record is None or record.boundary.id != boundary_id:
                raise ValueError(
                    f"boundary record does not match directory: {record_path}"
                )
            if record.backend_id != self.backend.name:
                raise ValueError(
                    f"boundary record belongs to another backend: {record_path}"
                )
            boundary_ids.add(boundary_id)
        return boundary_ids

    def _available_boundaries(self) -> tuple[Boundary, ...]:
        available = []
        for boundary in self.boundaries:
            record = Boundary._read(boundary.paths.record, BoundaryRecord)
            if record is None or record.boundary.id != boundary.boundary_id:
                raise ValueError(
                    "boundary record does not match boundary path: "
                    f"{boundary.paths.record}"
                )
            if record.backend_id != self.backend.name:
                raise ValueError(
                    "boundary record belongs to another backend: "
                    f"{boundary.paths.record}"
                )
            if record.availability == "available":
                available.append(boundary)
        return tuple(available)

    def boundary(self, boundary_id: str) -> Boundary:
        """Return one unloaded boundary aggregate."""
        for boundary in self.boundaries:
            if boundary.boundary_id == boundary_id:
                return boundary
        return Boundary(
            self.backend,
            self._boundaries_dir / quote(boundary_id, safe=""),
        )

    async def _run_boundaries(
        self,
        operation: Callable[[Boundary], Awaitable[int | bool]],
        boundaries: tuple[Boundary, ...],
    ) -> int:
        """Run one command operation across boundaries concurrently."""

        async def run(boundary: Boundary) -> int:
            try:
                return int(await operation(boundary))
            except BoundaryBusyError as error:
                LOGGER.warning("skipping boundary: %s", error)
                return 0

        async with asyncio.TaskGroup() as group:
            tasks = [group.create_task(run(boundary)) for boundary in boundaries]
        return sum(task.result() for task in tasks)

    def _ensure_backend_record(self) -> None:
        marker = self._backend_dir / "backend.json"
        if not marker.exists():
            _write_backend_record(
                marker,
                BackendWorkspaceRecord(name=self.backend_name),
            )

    async def add(self, new_count: int | None = None) -> int:
        if new_count is not None and new_count < 0:
            raise ValueError("new_count must not be negative")
        registered = self._registered_boundary_ids()
        selected = [
            boundary_id
            async for boundary_id in _new_boundary_ids(
                self.backend.discover_boundaries(),
                registered,
                new_count,
            )
        ]
        result = await self._run_boundaries(
            Boundary.enroll_inventory,
            tuple(self.boundary(boundary_id) for boundary_id in selected),
        )
        if any(self._boundaries_dir.glob("*/boundary.json")):
            self._ensure_backend_record()
        return result

    async def update(self) -> int:
        boundary_ids = tuple(sorted(self._registered_boundary_ids()))
        return await self._run_boundaries(
            Boundary.refresh_inventory,
            tuple(self.boundary(boundary_id) for boundary_id in boundary_ids),
        )

    async def scan(self) -> int:
        return await self._run_boundaries(
            Boundary.scan,
            self._available_boundaries(),
        )

    async def judge(self) -> int:
        return await self._run_boundaries(
            Boundary.judge,
            self._available_boundaries(),
        )

    async def extract(self) -> int:
        return await self._run_boundaries(
            Boundary.extract,
            self._available_boundaries(),
        )

    async def close(self) -> None:
        if self._closed:
            return

        self._closed = True

        async def close_resources() -> None:
            try:
                if self._boundaries is not None:
                    await asyncio.gather(
                        *(boundary.aclose() for boundary in self._boundaries)
                    )
            finally:
                await self.backend.aclose()

        cleanup = asyncio.create_task(close_resources())
        cancelled = False
        while not cleanup.done():
            try:
                await asyncio.shield(cleanup)
            except asyncio.CancelledError:
                cancelled = True
        cleanup.result()
        if cancelled:
            raise asyncio.CancelledError
