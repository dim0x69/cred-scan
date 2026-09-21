"""Workspace boundary discovery and backend lifetime."""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Awaitable, Callable
from pathlib import Path
from urllib.parse import quote, unquote

from cred_scan.backend.adapters.artifactory.docker import ArtifactoryDockerBackend
from cred_scan.backend.models import BoundaryRecord
from cred_scan.backend.proto import BackendAdapter
from cred_scan.orch.boundary import Boundary
from cred_scan.orch.locking import BoundaryBusyError
from pydantic import TypeAdapter

from cred_scan.orch.models import BackendName
from cred_scan.orch.global_config import get_config

LOGGER = logging.getLogger(__name__)


class Workspace:
    """Own backend lifetime and the command's persisted boundaries."""

    def __init__(self) -> None:
        self._workspace_dir = get_config().workspace.workspace_dir
        self.backend = self._load_backend()
        self._boundaries: tuple[Boundary, ...] | None = None
        self._closed = False

    def _load_backend(self) -> BackendAdapter:
        """Load the adapter selected by the workspace's persisted name."""
        config = get_config()
        self._workspace_dir.mkdir(parents=True, exist_ok=True)
        marker = self._workspace_dir / "backend.json"
        backend_name = TypeAdapter(BackendName).validate_python(
            json.loads(marker.read_text()).get("name")
            if marker.exists()
            else config.backends[0].get("name")
        )
        backend_config = next(
            (item for item in config.backends if item.get("name") == backend_name),
            None,
        )
        if backend_config is None:
            raise ValueError(
                "workspace backend is not configured: "
                f"{backend_name}"
            )
        if backend_name == "artifactory_docker":
            if backend_config is None:
                raise AssertionError("backend configuration disappeared")
            return ArtifactoryDockerBackend(
                name=backend_name,
                base_url=str(backend_config["base_url"]),
                platform=str(backend_config.get("platform", "linux/amd64")),
            )
        raise ValueError(f"unsupported workspace backend: {backend_name}")

    async def __aenter__(self) -> "Workspace":
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.close()

    @property
    def workspace_dir(self) -> Path:
        return self._workspace_dir

    @property
    def boundaries(self) -> tuple[Boundary, ...]:
        """Construct unloaded boundaries in deterministic ID order."""
        if self._boundaries is None:
            self._boundaries = tuple(
                Boundary(self.backend, record_path.parent)
                for record_path in sorted(
                    self._workspace_dir.glob("*/boundary.json"),
                    key=lambda item: unquote(item.parent.name),
                )
            )
        return self._boundaries

    def _registered_boundary_ids(self) -> set[str]:
        boundary_ids = set()
        for record_path in self._workspace_dir.glob("*/boundary.json"):
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
                    f"boundary record does not match directory: {boundary.paths.record}"
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
            self._workspace_dir / quote(boundary_id, safe=""),
        )

    async def _run_boundaries(
        self,
        operation: Callable[[Boundary], Awaitable[int | bool]],
        boundaries: tuple[Boundary, ...] | None = None,
    ) -> int:
        """Run one command operation across boundaries concurrently."""

        async def run(boundary: Boundary) -> int:
            try:
                return int(await operation(boundary))
            except BoundaryBusyError as error:
                LOGGER.warning("skipping boundary: %s", error)
                return 0

        selected = self.boundaries if boundaries is None else boundaries
        async with asyncio.TaskGroup() as group:
            tasks = [
                group.create_task(run(boundary))
                for boundary in selected
            ]
        return sum(task.result() for task in tasks)

    async def inventory(self) -> int:
        discovered = await self.backend.discover_boundaries()
        discovered_ids = set(discovered)
        boundary_ids = self._registered_boundary_ids() | discovered_ids
        self._boundaries = tuple(
            Boundary(
                self.backend,
                self._workspace_dir / quote(boundary_id, safe=""),
            )
            for boundary_id in sorted(boundary_ids)
        )
        result = await self._run_boundaries(
            lambda boundary: (
                boundary.refresh_inventory()
                if boundary.boundary_id in discovered_ids
                else boundary.mark_absent()
            )
        )
        marker = self._workspace_dir / "backend.json"
        if not marker.exists() and any(self._workspace_dir.glob("*/boundary.json")):
            marker.write_text(json.dumps({"name": self.backend.name}, indent=2) + "\n")
        return result

    async def scan(self) -> int:
        return await self._run_boundaries(Boundary.scan, self._available_boundaries())

    async def judge(self) -> int:
        return await self._run_boundaries(Boundary.judge, self._available_boundaries())

    async def extract(self) -> int:
        return await self._run_boundaries(Boundary.extract, self._available_boundaries())

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
