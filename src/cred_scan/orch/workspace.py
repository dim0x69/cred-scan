"""Workspace-level configuration, boundary discovery, and backend lifetime."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from pathlib import Path
from urllib.parse import quote, unquote

from cred_scan.backend.adapters.artifactory.docker import ArtifactoryDockerBackend
from cred_scan.backend.proto import BackendAdapter
from cred_scan.orch.boundary import Boundary, BoundaryBusyError
from cred_scan.orch.models import AppConfig
from cred_scan.scan.exclusions import load_exclusions


class Workspace:
    """Own workspace services and one stable set of loaded boundaries."""

    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self._workspace_dir = config.workspace.workspace_dir
        self.backend: BackendAdapter = ArtifactoryDockerBackend(
            config.backend,
            config.artifactory_api_key or "",
        )
        self.policy = load_exclusions(config.exclusions)
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
    def boundaries(self) -> tuple[Boundary, ...]:
        """Load all persisted boundaries in deterministic ID order."""
        if self._boundaries is None:
            boundaries: list[Boundary] = []
            for inventory_path in sorted(
                self._workspace_dir.glob("*/inventory.json"),
                key=lambda item: unquote(item.parent.name),
            ):
                try:
                    boundaries.append(Boundary(self, inventory_path.parent))
                except BoundaryBusyError:
                    continue
            self._boundaries = tuple(boundaries)
        return self._boundaries

    def boundary(self, boundary_id: str) -> Boundary:
        """Return one fully loaded boundary."""
        for boundary in self.boundaries:
            if boundary.boundary_id == boundary_id:
                return boundary
        return Boundary(
            self,
            self._workspace_dir / quote(boundary_id, safe=""),
        )

    async def _run_boundaries(
        self, operation: Callable[[Boundary], Awaitable[int | bool]]
    ) -> int:
        """Run a stage across boundaries; each boundary serializes its own work."""

        async def run(boundary: Boundary) -> int:
            try:
                return int(await operation(boundary))
            except BoundaryBusyError:
                # Another process owns this boundary's operation sentinel.
                return 0

        async with asyncio.TaskGroup() as group:
            tasks = [group.create_task(run(boundary)) for boundary in self.boundaries]
        return sum(task.result() for task in tasks)

    async def inventory(self) -> int:
        return await self._run_boundaries(Boundary.refresh_inventory)

    async def scan(self) -> int:
        return await self._run_boundaries(Boundary.scan)

    async def judge(self) -> int:
        return await self._run_boundaries(Boundary.judge)

    async def extract(self) -> int:
        return await self._run_boundaries(Boundary.extract)

    async def close(self) -> None:
        if self._closed:
            return

        self._closed = True

        async def close_resources() -> None:
            try:
                if self._boundaries is not None:
                    # Settle every reader before releasing the shared backend.
                    results = await asyncio.gather(
                        *(boundary.aclose() for boundary in self._boundaries),
                        return_exceptions=True,
                    )
                    for result in results:
                        if isinstance(result, BaseException):
                            raise result
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
