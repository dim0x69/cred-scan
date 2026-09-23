import asyncio
import fcntl
import multiprocessing
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from cred_scan.orch import runtime as runtime_module
from cred_scan.orch.locking import workspace_lock
from cred_scan.orch.runtime import LocalRuntime


def _child_waits_for_shared_lock(
    path: str,
    started: Any,
    acquired: Any,
    release: Any,
) -> None:
    started.set()
    with Path(path).open("a+b") as stream:
        fcntl.flock(stream.fileno(), fcntl.LOCK_SH)
        acquired.set()
        release.wait(5)


class FakeWorkspace:
    def __init__(self, lock_path: Path) -> None:
        self.workspace_lock_path = lock_path
        self.workspace_lock_fd: int | None = None
        self.closed = False

    async def __aenter__(self) -> "FakeWorkspace":
        return self

    async def __aexit__(self, *_args: object) -> None:
        self.closed = True


def test_runtime_inventory_gate_waits_for_source_command(
    tmp_path: Path, app_config, monkeypatch
) -> None:
    async def scenario() -> None:
        runtime = LocalRuntime(app_config)
        lock_path = tmp_path / "backend" / ".workspace.lock"
        source_workspace = FakeWorkspace(lock_path)
        inventory_workspace = FakeWorkspace(lock_path)
        source_started = asyncio.Event()
        release_source = asyncio.Event()
        inventory_started = asyncio.Event()
        inventory_lock_attempted = asyncio.Event()
        release_inventory = asyncio.Event()
        acquire_workspace_lock = runtime_module.workspace_lock

        @asynccontextmanager
        async def observe_inventory_lock(path: Path, *, shared: bool):
            if not shared:
                inventory_lock_attempted.set()
            async with acquire_workspace_lock(path, shared=shared) as descriptor:
                yield descriptor

        monkeypatch.setattr(runtime_module, "workspace_lock", observe_inventory_lock)

        async def source(_workspace: FakeWorkspace) -> int:
            source_started.set()
            await release_source.wait()
            return 1

        async def inventory(_workspace: FakeWorkspace) -> int:
            assert source_workspace.closed
            inventory_started.set()
            await release_inventory.wait()
            return 1

        source_task = asyncio.create_task(
            runtime._run_workspaces(
                iter((source_workspace,)), source, shared=True
            )
        )
        await source_started.wait()
        inventory_task = asyncio.create_task(
            runtime._run_workspaces(
                iter((inventory_workspace,)), inventory, shared=False
            )
        )
        await inventory_lock_attempted.wait()
        assert not inventory_started.is_set()

        release_source.set()
        assert await source_task == 1
        await asyncio.wait_for(inventory_started.wait(), timeout=2)
        release_inventory.set()
        assert await inventory_task == 1
        assert inventory_workspace.closed

    asyncio.run(scenario())


def test_runtime_shared_gates_allow_concurrent_source_commands(
    tmp_path: Path, app_config
) -> None:
    async def scenario() -> None:
        runtime = LocalRuntime(app_config)
        lock_path = tmp_path / "backend" / ".workspace.lock"
        workspaces = (FakeWorkspace(lock_path), FakeWorkspace(lock_path))
        started = (asyncio.Event(), asyncio.Event())
        release = asyncio.Event()

        async def source(index: int):
            async def run(_workspace: FakeWorkspace) -> int:
                started[index].set()
                await release.wait()
                return 1

            return run

        tasks = [
            asyncio.create_task(
                runtime._run_workspaces(
                    iter((workspaces[index],)),
                    await source(index),
                    shared=True,
                )
            )
            for index in range(2)
        ]
        await asyncio.wait_for(
            asyncio.gather(*(event.wait() for event in started)), timeout=2
        )
        release.set()
        assert await asyncio.gather(*tasks) == [1, 1]

    asyncio.run(scenario())


def test_workspace_gates_are_independent_per_backend(
    tmp_path: Path, app_config
) -> None:
    async def scenario() -> None:
        runtime = LocalRuntime(app_config)
        source_workspace = FakeWorkspace(tmp_path / "backend-a" / ".workspace.lock")
        inventory_workspace = FakeWorkspace(tmp_path / "backend-b" / ".workspace.lock")
        source_started = asyncio.Event()
        release_source = asyncio.Event()
        inventory_started = asyncio.Event()
        release_inventory = asyncio.Event()

        async def source(_workspace: FakeWorkspace) -> int:
            source_started.set()
            await release_source.wait()
            return 1

        async def inventory(_workspace: FakeWorkspace) -> int:
            inventory_started.set()
            await release_inventory.wait()
            return 1

        source_task = asyncio.create_task(
            runtime._run_workspaces(
                iter((source_workspace,)), source, shared=True
            )
        )
        await source_started.wait()
        inventory_task = asyncio.create_task(
            runtime._run_workspaces(
                iter((inventory_workspace,)), inventory, shared=False
            )
        )
        await asyncio.wait_for(inventory_started.wait(), timeout=2)
        release_source.set()
        release_inventory.set()
        assert await asyncio.gather(source_task, inventory_task) == [1, 1]

    asyncio.run(scenario())


def test_workspace_gate_excludes_a_separate_process(tmp_path: Path) -> None:
    async def scenario() -> None:
        context = multiprocessing.get_context("spawn")
        lock_path = tmp_path / "backend" / ".workspace.lock"
        started = context.Event()
        acquired = context.Event()
        release = context.Event()
        child = context.Process(
            target=_child_waits_for_shared_lock,
            args=(str(lock_path), started, acquired, release),
        )
        child.start()
        try:
            async with workspace_lock(lock_path, shared=False):
                assert await asyncio.to_thread(started.wait, 5)
                assert not await asyncio.to_thread(acquired.wait, 0.1)
            assert await asyncio.to_thread(acquired.wait, 5)
        finally:
            release.set()
            await asyncio.to_thread(child.join, 5)
            if child.is_alive():
                child.terminate()
                await asyncio.to_thread(child.join, 5)
        assert child.exitcode == 0

    asyncio.run(scenario())
