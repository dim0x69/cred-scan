import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, Mock

import pytest

from cred_scan.backend.models import ScanTargetInventory
from cred_scan.backend.proto import UnsupportedTitusTargetError
from cred_scan.orch import global_config
from cred_scan.orch.models import AppConfig
from cred_scan.scan.titus import TitusCliScanner, _is_permanent_titus_error


@pytest.mark.parametrize(
    "line",
    [
        "Error: BLOB_UNKNOWN: blob unknown to registry",
        "GET failed with HTTP 404",
        "request denied: unauthorized",
        "Token failed verification: parse",
    ],
)
def test_registry_errors_are_permanent(line: str) -> None:
    assert _is_permanent_titus_error(line)


def test_transient_titus_errors_are_retryable() -> None:
    assert not _is_permanent_titus_error("connection reset by peer")


def test_unsupported_target_becomes_failed_without_starting_titus(
    app_config: AppConfig,
    repository_inventory: ScanTargetInventory,
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(global_config, "CONFIG", app_config)
    backend = Mock()
    backend.titus_scan_arguments.side_effect = UnsupportedTitusTargetError(
        "unsupported source"
    )
    scanner = TitusCliScanner(repository_inventory, backend)

    result = asyncio.run(
        scanner.scan(
            repository_inventory.targets[0],
            tmp_path / "scratch",
            tmp_path / "titus.ds",
        )
    )

    assert result.result.status == "failed"
    assert result.result.errors == ("unsupported source",)
    assert not result.result.retryable
    assert not (tmp_path / "scratch").exists()


@pytest.mark.parametrize("phase", ["scan", "export"])
def test_cancelled_titus_call_reaps_child_before_returning(
    app_config: AppConfig,
    repository_inventory: ScanTargetInventory,
    tmp_path: Path,
    monkeypatch,
    phase: str,
) -> None:
    monkeypatch.setattr(global_config, "CONFIG", app_config)
    # Exercise real subprocess cancellation without invoking Titus or any backend.
    spawn = asyncio.create_subprocess_exec

    async def scenario():
        started = asyncio.Event()
        children = []
        commands = []

        async def synthetic_child(*args, **kwargs):
            commands.append(args)
            child = await spawn(
                sys.executable, "-c", "import time; time.sleep(60)", **kwargs
            )
            children.append(child)
            started.set()
            return child

        monkeypatch.setattr(asyncio, "create_subprocess_exec", synthetic_child)
        backend = Mock()
        backend.titus_scan_arguments.return_value = (
            "--docker",
            "--artifactory-repository",
            repository_inventory.boundary.name,
            "registry/docker-local/team/api@sha256:manifest",
        )
        app_config.titus.internal_workers = 7
        scanner = TitusCliScanner(repository_inventory, backend)
        if phase == "scan":
            operation = scanner.scan(
                repository_inventory.targets[0],
                tmp_path / "scratch",
                tmp_path / "titus.ds",
            )
        else:
            operation = scanner.export_report(tmp_path / "titus.ds")
        task = asyncio.create_task(operation)
        try:
            await started.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert children[0].returncode is not None
            if phase == "scan":
                assert commands[0][commands[0].index("--workers") + 1] == str(
                    app_config.titus.internal_workers
                )
            flag = "--output" if phase == "scan" else "--datastore"
            assert commands[0][commands[0].index(flag) + 1] == str(
                tmp_path / "titus.ds"
            )
        finally:
            for child in children:
                if child.returncode is None:
                    child.kill()
                    await child.wait()

    asyncio.run(asyncio.wait_for(scenario(), timeout=5))


@pytest.mark.parametrize("phase", ["scan", "export"])
def test_repeated_cancellation_waits_for_reaping(
    app_config, repository_inventory, tmp_path, monkeypatch, phase
):
    monkeypatch.setattr(global_config, "CONFIG", app_config)
    async def scenario():
        entered, reaping, release = asyncio.Event(), asyncio.Event(), asyncio.Event()
        process = Mock(returncode=None)

        async def lines():
            entered.set()
            await asyncio.Event().wait()
            yield b""

        process.stderr = lines()
        communicates = 0

        async def communicate():
            nonlocal communicates
            communicates += 1
            if phase == "export" and communicates == 1:
                entered.set()
                await asyncio.Event().wait()
            reaping.set()
            await release.wait()
            process.returncode = -9
            return b"", b""

        process.communicate = AsyncMock(side_effect=communicate)
        monkeypatch.setattr(
            asyncio, "create_subprocess_exec", AsyncMock(return_value=process)
        )
        backend = Mock(titus_scan_arguments=Mock(return_value=("synthetic",)))
        scanner = TitusCliScanner(repository_inventory, backend)
        operation = (
            scanner.scan(
                repository_inventory.targets[0],
                tmp_path / "scratch",
                tmp_path / "titus.ds",
            )
            if phase == "scan"
            else scanner.export_report(tmp_path / "titus.ds")
        )
        task = asyncio.create_task(operation)
        await entered.wait()
        task.cancel()
        await reaping.wait()
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        process.kill.assert_called_once()
        assert process.returncode == -9

    asyncio.run(asyncio.wait_for(scenario(), 3))


@pytest.mark.parametrize("phase", ["scan", "export"])
@pytest.mark.parametrize("launch_fails", [False, True])
def test_cancellation_during_launch_waits_and_reaps(
    app_config, repository_inventory, tmp_path, monkeypatch, phase, launch_fails
):
    monkeypatch.setattr(global_config, "CONFIG", app_config)
    async def scenario():
        launching, release = asyncio.Event(), asyncio.Event()
        process = Mock(returncode=None)
        process.communicate = AsyncMock(return_value=(b"", b""))

        async def launch(*_, **kwargs):
            launching.set()
            await release.wait()
            if launch_fails:
                raise OSError("launch failed during cancellation")
            return process

        monkeypatch.setattr(asyncio, "create_subprocess_exec", launch)
        scanner = TitusCliScanner(
            repository_inventory,
            Mock(titus_scan_arguments=Mock(return_value=("synthetic",))),
        )
        operation = (
            scanner.scan(
                repository_inventory.targets[0],
                tmp_path / "scratch",
                tmp_path / "titus.ds",
            )
            if phase == "scan"
            else scanner.export_report(tmp_path / "titus.ds")
        )
        task = asyncio.create_task(operation)
        await launching.wait()
        task.cancel()
        await asyncio.sleep(0)
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        if launch_fails:
            process.kill.assert_not_called()
            process.communicate.assert_not_awaited()
        else:
            process.kill.assert_called_once()
            process.communicate.assert_awaited_once()

    asyncio.run(asyncio.wait_for(scenario(), 3))
