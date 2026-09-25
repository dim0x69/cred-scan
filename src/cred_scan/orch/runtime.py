"""Concurrent backend and boundary command coordination."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Iterator
from contextlib import AsyncExitStack

from cred_scan.orch.global_config import get_config, set_config
from cred_scan.backend.models import SourceStage
from cred_scan.orch.models import AppConfig
from cred_scan.orch.workspace import (
    Workspace,
    iter_configured_workspaces,
    iter_persisted_workspaces,
)


class LocalRuntime:
    def __init__(self, config: AppConfig) -> None:
        set_config(config)

    async def _run_workspaces(
        self,
        workspaces: Iterator[Workspace],
        operation: Callable[[Workspace], Awaitable[int]],
    ) -> int:
        """Inventory runs alone for its backend by operating convention."""
        total = 0
        for workspace in workspaces:
            async with workspace:
                total += await operation(workspace)
        return total

    async def inventory_add(
        self,
        backend_name: str | None = None,
        new_count: int | None = None,
    ) -> int:
        if new_count is not None and new_count < 0:
            raise ValueError("new_count must not be negative")
        return await self._run_workspaces(
            iter_configured_workspaces(
                get_config().workspace.workspace_dir,
                backend_name,
            ),
            lambda workspace: workspace.add(new_count),
        )

    async def inventory_update(self, backend_name: str | None = None) -> int:
        return await self._run_workspaces(
            iter_persisted_workspaces(
                get_config().workspace.workspace_dir,
                backend_name,
            ),
            Workspace.update,
        )

    async def _run_sources(
        self,
        stage: SourceStage,
        backend_name: str | None,
        *,
        failed: bool,
    ) -> int:
        async with AsyncExitStack() as resources:
            # Capture every backend's ready set before the first operation starts.
            batches = []
            for workspace in iter_persisted_workspaces(
                get_config().workspace.workspace_dir,
                backend_name,
            ):
                resources.push_async_callback(workspace.close)
                batches.append((workspace, workspace.select(stage, failed=failed)))
            total = 0
            for workspace, selected in batches:
                async with workspace:
                    total += await workspace.run_selected(
                        stage, selected, failed=failed
                    )
            return total

    async def scan(
        self, backend_name: str | None = None, *, failed: bool = False
    ) -> int:
        return await self._run_sources("scan", backend_name, failed=failed)

    async def judge(
        self, backend_name: str | None = None, *, failed: bool = False
    ) -> int:
        return await self._run_sources("judge", backend_name, failed=failed)

    async def extract(
        self, backend_name: str | None = None, *, failed: bool = False
    ) -> int:
        return await self._run_sources("extract", backend_name, failed=failed)
