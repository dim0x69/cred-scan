"""Concurrent backend and boundary command coordination."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Iterator

from cred_scan.orch.global_config import get_config, set_config
from cred_scan.orch.locking import workspace_lock
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
        *,
        shared: bool,
    ) -> int:
        """Run a command per backend while holding its workspace gate.

        Args:
            workspaces: Backend workspaces to process, one at a time.
            operation: The command operation to run for each workspace.
            shared: If true, acquire a shared gate for scan/judge/extract. If
                false, acquire an exclusive gate for inventory add/update.

        Returns:
            The sum of the per-workspace operation results.
        """
        total = 0
        for workspace in workspaces:
            async with workspace_lock(
                workspace.workspace_lock_path,
                shared=shared,
            ) as descriptor:
                workspace.workspace_lock_fd = descriptor
                try:
                    async with workspace:
                        total += await operation(workspace)
                finally:
                    workspace.workspace_lock_fd = None
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
            shared=False,
        )

    async def inventory_update(self, backend_name: str | None = None) -> int:
        return await self._run_workspaces(
            iter_persisted_workspaces(
                get_config().workspace.workspace_dir,
                backend_name,
            ),
            Workspace.update,
            shared=False,
        )

    async def scan(self, backend_name: str | None = None) -> int:
        return await self._run_workspaces(
            iter_persisted_workspaces(
                get_config().workspace.workspace_dir,
                backend_name,
            ),
            Workspace.scan,
            shared=True,
        )

    async def judge(self, backend_name: str | None = None) -> int:
        return await self._run_workspaces(
            iter_persisted_workspaces(
                get_config().workspace.workspace_dir,
                backend_name,
            ),
            Workspace.judge,
            shared=True,
        )

    async def extract(self, backend_name: str | None = None) -> int:
        return await self._run_workspaces(
            iter_persisted_workspaces(
                get_config().workspace.workspace_dir,
                backend_name,
            ),
            Workspace.extract,
            shared=True,
        )
