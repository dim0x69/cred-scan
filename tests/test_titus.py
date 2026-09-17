import asyncio
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest

from cred_scan.backend.models import ScanBoundaryInventory
from cred_scan.backend.proto import UnsupportedTitusTargetError
from cred_scan.orch.models import AppConfig
from cred_scan.scan.models import ExclusionPolicy
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
    repository_inventory: ScanBoundaryInventory,
    tmp_path: Path,
) -> None:
    backend = Mock()
    backend.titus_scan_arguments.side_effect = UnsupportedTitusTargetError(
        "unsupported source"
    )
    scanner = TitusCliScanner(app_config.titus, repository_inventory, backend)

    result = asyncio.run(
        scanner.scan(
            repository_inventory.targets[0],
            tmp_path / "scratch",
            tmp_path / "titus.ds",
            ExclusionPolicy(path_file="path-exclusions.list"),
        )
    )

    assert result.result.status == "failed"
    assert result.result.errors == ("unsupported source",)
    assert not result.result.retryable
    assert not (tmp_path / "scratch").exists()


@pytest.mark.parametrize("phase", ["scan", "export"])
def test_cancelled_titus_call_reaps_child_before_returning(
    app_config: AppConfig,
    repository_inventory: ScanBoundaryInventory,
    tmp_path: Path,
    monkeypatch,
    phase: str,
) -> None:
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
        scanner = TitusCliScanner(
            app_config.titus,
            repository_inventory,
            backend,
        )
        if phase == "scan":
            operation = scanner.scan(
                repository_inventory.targets[0],
                tmp_path / "scratch",
                tmp_path / "titus.ds",
                ExclusionPolicy(path_file="path-exclusions.list"),
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
