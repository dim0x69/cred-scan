"""Current boundary ownership, concurrency, and sequential scan recovery."""

import asyncio
from unittest.mock import AsyncMock, Mock
from urllib.parse import quote

import pytest

from cred_scan.backend.models import ContentLocation, ContentRead, target_id_for
from cred_scan.orch import boundary as boundary_module
from cred_scan.orch import workspace as workspace_module
from cred_scan.orch.models import AppConfig
from cred_scan.orch.runtime import LocalRuntime
from cred_scan.orch.workspace import Workspace
from cred_scan.scan.models import CredentialsDocument, JudgmentResult, TitusReport


@pytest.fixture
def make_workspace(tmp_path, app_config, repository_inventory, monkeypatch):
    backend = Mock()
    backend.name = app_config.backend.name
    backend.aclose = AsyncMock()
    readers = []

    def reader(*_):
        value = Mock(aclose=AsyncMock())
        value.resolve_location = AsyncMock(
            side_effect=lambda path: ContentLocation(
                locator=path,
                source_path="app.env",
                filename="app.env",
            )
        )
        value.read = AsyncMock(
            return_value=ContentRead(
                content=b"synthetic", source_path="app.env", filename="app.env"
            )
        )
        readers.append(value)
        return value

    backend.content_reader.side_effect = reader
    monkeypatch.setattr(
        workspace_module, "ArtifactoryDockerBackend", Mock(return_value=backend)
    )
    monkeypatch.setattr(
        boundary_module, "DspyFindingJudge", lambda _: Mock(judge=AsyncMock())
    )
    for path in (app_config.exclusions.paths, app_config.exclusions.credentials):
        path.write_text("")

    def make(boundaries=1, targets=1):
        for index in range(boundaries):
            boundary = repository_inventory.boundary.model_copy(
                update={"id": f"boundary-{index}", "name": f"repo-{index}"}
            )
            selected = []
            for target_index in range(targets):
                target = repository_inventory.targets[0].model_copy(deep=True)
                target.boundary = boundary
                target.scope.image = f"registry/repo-{index}/image-{target_index}"
                target.id = target_id_for(target.scope)
                selected.append(target)
            inventory = repository_inventory.model_copy(
                update={"boundary": boundary, "targets": tuple(selected)}
            )
            path = tmp_path / quote(boundary.id, safe="") / "inventory.json"
            path.parent.mkdir()
            path.write_text(inventory.model_dump_json())
        workspace = Workspace(app_config)
        # Load once; these are the same owned objects used by every operation.
        assert len(workspace.boundaries) == boundaries
        backend.inventory = AsyncMock(
            side_effect=lambda identity: next(
                item.inventory.model_copy(deep=True)
                for item in workspace.boundaries
                if item.boundary_id == identity
            )
        )
        return workspace

    return make


def completed(target, status="scanned", retryable=True):
    target.result.status = status
    target.result.retryable = retryable
    return target


def export_for(boundary):
    return AsyncMock(
        return_value=TitusReport(boundary_id=boundary.boundary_id, generated_at="now")
    )


def test_one_scanner_runs_targets_and_retries_sequentially(make_workspace):
    workspace = make_workspace(targets=3)
    boundary = workspace.boundaries[0]
    scanner = boundary.scanner
    calls, scratch_paths = [], []

    async def scan(target, scratch, datastore, policy):
        assert boundary.scanner is scanner
        assert datastore == boundary.paths.datastore
        assert scratch.exists() and boundary.paths.operation_lock.exists()
        calls.append(target.id)
        scratch_paths.append(scratch)
        persisted = type(boundary.inventory).model_validate_json(
            boundary.paths.inventory.read_text()
        )
        statuses = {item.id: item.result.status for item in persisted.targets}
        assert statuses[target.id] == "running"
        for previous in boundary.inventory.targets:
            if previous.id == target.id:
                break
            assert statuses[previous.id] == "scanned"
        await asyncio.sleep(0)
        return completed(target, "failed" if len(calls) == 1 else "scanned")

    scanner.scan = AsyncMock(side_effect=scan)
    scanner.export_report = export_for(boundary)

    async def scenario():
        async with workspace:
            assert await workspace.scan() == 1

    asyncio.run(scenario())
    ids = [target.id for target in boundary.inventory.targets]
    assert calls == [ids[0], ids[0], ids[1], ids[2]]
    assert scratch_paths[0] == scratch_paths[1]
    assert len(set(scratch_paths)) == 3
    assert all(not path.exists() for path in scratch_paths)
    scanner.export_report.assert_awaited_once()
    assert not boundary.paths.operation_lock.exists()
    assert all(
        target.result.status == "scanned" for target in boundary.inventory.targets
    )


@pytest.mark.parametrize("retryable,attempts", [(False, 1), (True, 3)])
def test_failed_target_does_not_block_later_targets_or_export(
    make_workspace, retryable, attempts
):
    workspace = make_workspace(targets=2)
    boundary = workspace.boundaries[0]
    first = boundary.inventory.targets[0].id
    boundary.scanner.scan = AsyncMock(
        side_effect=lambda target, *_: completed(
            target, "failed" if target.id == first else "scanned", retryable
        )
    )
    boundary.scanner.export_report = export_for(boundary)

    async def scenario():
        async with workspace:
            assert await workspace.scan() == 1

    asyncio.run(scenario())
    assert boundary.scanner.scan.await_count == attempts + 1
    assert boundary.report.incomplete
    assert boundary.credentials.incomplete
    boundary.scanner.export_report.assert_awaited_once()


@pytest.mark.parametrize("stage", ["inventory", "scan", "judge", "extract"])
def test_workspace_runs_distinct_boundaries_concurrently(
    make_workspace, monkeypatch, stage
):
    workspace = make_workspace(boundaries=2)
    entered = set()

    async def scenario():
        both = asyncio.Event()

        async def work(boundary):
            async with boundary.operation():
                entered.add(boundary.boundary_id)
                if len(entered) == 2:
                    both.set()
                await both.wait()
                return 1

        method = "refresh_inventory" if stage == "inventory" else stage
        monkeypatch.setattr(boundary_module.Boundary, method, work)
        async with workspace:
            assert await asyncio.wait_for(getattr(workspace, stage)(), 2) == 2

    asyncio.run(scenario())
    assert entered == {"boundary-0", "boundary-1"}


def test_all_stages_on_one_boundary_are_serialized(make_workspace, credential):
    workspace = make_workspace()
    boundary = workspace.boundaries[0]
    events = []

    async def scenario():
        entered, release = asyncio.Event(), asyncio.Event()

        async def discover(_):
            events.append("inventory")
            entered.set()
            await release.wait()
            return boundary.inventory.model_copy(deep=True)

        workspace.backend.inventory.side_effect = discover

        async def scan(target, *_):
            events.append("scan")
            await asyncio.sleep(0)
            return completed(target)

        boundary.scanner.scan = AsyncMock(side_effect=scan)
        boundary.scanner.export_report = export_for(boundary)
        boundary.credentials = CredentialsDocument(
            boundary_id=boundary.boundary_id,
            report_generated_at="now",
            credentials={credential.credential_id: credential},
        )
        boundary._has_credentials = True

        async def judge(*_):
            events.append("judge")
            await asyncio.sleep(0)
            return JudgmentResult(verdict="VALID")

        boundary.judge_service.judge.side_effect = judge
        original = boundary.extractor.extract

        async def extract(*args):
            events.append("extract")
            return await original(*args)

        boundary.extractor.extract = AsyncMock(side_effect=extract)
        async with workspace:
            inventory = asyncio.create_task(boundary.refresh_inventory())
            await entered.wait()
            scans = asyncio.create_task(boundary.scan())
            judgments = asyncio.create_task(boundary.judge())
            extractions = asyncio.create_task(boundary.extract())
            await asyncio.sleep(0)
            assert events == ["inventory"]
            release.set()
            assert await asyncio.gather(inventory, scans, judgments, extractions) == [
                True,
                True,
                1,
                1,
            ]

    asyncio.run(asyncio.wait_for(scenario(), 3))
    assert events == ["inventory", "scan", "judge", "extract"]
    assert not boundary.paths.operation_lock.exists()
    result = boundary.credentials.credentials[credential.credential_id].extraction
    assert (
        boundary.paths.boundary_dir / result.output_path
    ).read_bytes() == b"synthetic"


def test_cancellation_preserves_completed_targets_and_leaves_unstarted_pending(
    make_workspace,
):
    workspace = make_workspace(targets=3)
    boundary = workspace.boundaries[0]
    calls = []

    async def scenario():
        entered = asyncio.Event()

        async def scan(target, scratch, *_):
            calls.append(target.id)
            if len(calls) == 2:
                entered.set()
                try:
                    await asyncio.Event().wait()
                finally:
                    assert scratch.exists() and boundary.paths.operation_lock.exists()
            return completed(target)

        boundary.scanner.scan = AsyncMock(side_effect=scan)
        boundary.scanner.export_report = export_for(boundary)
        async with workspace:
            task = asyncio.create_task(workspace.scan())
            await entered.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert [t.result.status for t in boundary.inventory.targets] == [
                "scanned",
                "running",
                "pending",
            ]
            assert not boundary.paths.scratch_parent.exists()
            assert not boundary.paths.operation_lock.exists()
            boundary.scanner.export_report.assert_not_awaited()
            boundary.scanner.scan.side_effect = lambda target, *_: completed(target)
            assert await workspace.scan() == 1
            assert boundary.scanner.scan.await_count == 4

    asyncio.run(asyncio.wait_for(scenario(), 3))


def test_workspace_failure_waits_for_other_boundary_cleanup(make_workspace):
    workspace = make_workspace(boundaries=2)
    first, second = workspace.boundaries

    async def scenario():
        entered = asyncio.Event()
        settled = []

        async def fail(*_):
            await entered.wait()
            raise RuntimeError("injected failure")

        async def cancelled(target, scratch, *_):
            entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                assert scratch.exists() and second.paths.operation_lock.exists()
                await asyncio.sleep(0)
                settled.append(True)

        first.scanner.scan = AsyncMock(side_effect=fail)
        second.scanner.scan = AsyncMock(side_effect=cancelled)
        with pytest.raises(ExceptionGroup, match="TaskGroup"):
            async with workspace:
                await workspace.scan()
        assert settled == [True]
        workspace.backend.aclose.assert_awaited_once()
        for boundary in workspace.boundaries:
            assert not boundary.paths.operation_lock.exists()
            assert not boundary.paths.scratch_parent.exists()
            boundary.reader.aclose.assert_awaited_once()

    asyncio.run(asyncio.wait_for(scenario(), 3))


def test_configuration_has_only_titus_internal_parallelism(app_config):
    assert "scan_concurrency" not in AppConfig.model_fields
    assert "scan_concurrency" not in AppConfig.model_json_schema()["properties"]
    app_config.titus.internal_workers = 5
    assert app_config.titus.internal_workers == 5


@pytest.mark.parametrize("stage", ["inventory", "scan", "judge", "extract"])
def test_runtime_returns_all_boundary_counts(make_workspace, monkeypatch, stage):
    workspace = make_workspace(boundaries=2)
    monkeypatch.setattr(
        "cred_scan.orch.runtime.Workspace", Mock(return_value=workspace)
    )
    method = "refresh_inventory" if stage == "inventory" else stage
    operation = AsyncMock(return_value=1)
    monkeypatch.setattr(boundary_module.Boundary, method, operation)
    assert asyncio.run(getattr(LocalRuntime(workspace.config), stage)()) == 2
    assert operation.await_count == 2


def test_busy_boundary_does_not_block_other_boundaries(make_workspace):
    workspace = make_workspace(boundaries=2)
    busy, available = workspace.boundaries
    busy.paths.operation_lock.write_text("another owner")
    available.scanner.scan = AsyncMock(side_effect=lambda target, *_: completed(target))
    available.scanner.export_report = export_for(available)

    async def scenario():
        async with workspace:
            assert await workspace.scan() == 1

    asyncio.run(scenario())
    assert busy.paths.operation_lock.read_text() == "another owner"
    assert busy.inventory.targets[0].result.status == "pending"


def test_file_exists_from_stage_is_not_mistaken_for_busy_boundary(make_workspace):
    workspace = make_workspace()
    workspace.boundaries[0].scanner.scan = AsyncMock(
        side_effect=FileExistsError("bad output")
    )

    async def scenario():
        with pytest.raises(ExceptionGroup) as error:
            async with workspace:
                await workspace.scan()
        assert isinstance(error.value.exceptions[0], FileExistsError)

    asyncio.run(scenario())


def test_close_settles_all_readers_before_backend_despite_repeated_cancellation(
    make_workspace,
):
    workspace = make_workspace(boundaries=2)

    async def scenario():
        entered, release = asyncio.Event(), asyncio.Event()
        finished = []

        async def close_reader():
            entered.set()
            await release.wait()
            finished.append(True)

        for boundary in workspace.boundaries:
            boundary.reader.aclose.side_effect = close_reader
        task = asyncio.create_task(workspace.close())
        await entered.wait()
        task.cancel()
        await asyncio.sleep(0)
        task.cancel()
        await asyncio.sleep(0)
        workspace.backend.aclose.assert_not_awaited()
        assert not task.done()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert len(finished) == 2
        workspace.backend.aclose.assert_awaited_once()

    asyncio.run(asyncio.wait_for(scenario(), 3))
