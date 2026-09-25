"""Backend discovery enrolls boundaries only from complete validated responses."""

import asyncio
from datetime import UTC, datetime
from unittest.mock import AsyncMock, Mock

import httpx
import pytest

from cred_scan.backend.adapters.artifactory.common import ArtifactoryError
from cred_scan.backend.adapters.artifactory.docker import ArtifactoryDockerBackend
from cred_scan.backend.adapters.artifactory.models import (
    ArtifactoryRepository,
    DockerImageScanScope,
)
from cred_scan.backend.models import (
    BackendWorkspaceRecord,
    BoundaryRecord,
    ScanTargetInventory,
    ScanTarget,
    target_id_for,
)
from cred_scan.orch import global_config
from cred_scan.orch import boundary as boundary_module
from cred_scan.orch import workspace as workspace_module
from cred_scan.orch.models import AppConfig, TitusConfig, WorkspaceConfig
from cred_scan.orch.workspace import Workspace
from cred_scan.scan.models import CredentialsDocument, ExclusionFiles, TitusReport


def run(coroutine):
    return asyncio.run(coroutine)


def http_backend(handler) -> ArtifactoryDockerBackend:
    backend = object.__new__(ArtifactoryDockerBackend)
    backend._name = "artifactory_docker"
    backend.base_url = "https://artifactory.example/artifactory"
    backend.platform = "linux/amd64"
    backend.session = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        follow_redirects=True,
        trust_env=False,
    )
    return backend


def inventory(boundary_id: str, *, with_target: bool = False) -> ScanTargetInventory:
    name = boundary_id.rsplit(":", 1)[-1]
    boundary = ArtifactoryRepository(id=boundary_id, name=name)
    targets = ()
    if with_target:
        scope = DockerImageScanScope(
            image=f"artifactory.example/{name}/image",
            digest="sha256:old",
            root_digest="sha256:old",
            platform="linux/amd64",
            manifest_timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        )
        targets = (
            ScanTarget(
                id=target_id_for(scope),
                scope=scope,
            ),
        )
    return ScanTargetInventory(
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
        boundary=boundary,
        targets=targets,
    )


def configured_workspace(tmp_path, monkeypatch, backend) -> Workspace:
    config = AppConfig(
        workspace=WorkspaceConfig(workspace_dir=tmp_path),
        titus=TitusConfig(executable="unused-titus"),
        exclusions=ExclusionFiles(
            paths=tmp_path / "paths.list",
            credentials=tmp_path / "credentials.list",
        ),
        backends=(
            {
                "name": "artifactory_docker",
                "base_url": "https://artifactory.example",
                "platform": "linux/amd64",
            },
        ),
        artifactory_access_token="synthetic-token",
    )
    global_config.set_config(config)
    monkeypatch.setattr(
        workspace_module,
        "ArtifactoryDockerBackend",
        Mock(return_value=backend),
    )
    return Workspace(
        backend,
        tmp_path / "artifactory_docker",
        create=True,
    )


def write_boundary(tmp_path, document: ScanTargetInventory):
    path = (
        tmp_path
        / "artifactory_docker"
        / "boundaries"
        / document.boundary.id.replace(":", "%3A")
    )
    path.mkdir(parents=True)
    backend_dir = path.parents[1]
    (backend_dir / "backend.json").write_text(
        BackendWorkspaceRecord(name="artifactory_docker").model_dump_json()
    )
    (path / "boundary.json").write_text(
        BoundaryRecord(
            backend_id="artifactory_docker",
            boundary=document.boundary,
        ).model_dump_json()
    )
    (path / "scantargets.json").write_text(document.model_dump_json())
    return path


def test_new_boundary_id_iterator_deduplicates_and_closes_on_exhaustion():
    closed = False

    async def discover():
        nonlocal closed
        try:
            yield "first"
            yield "second"
            yield "first"
        finally:
            closed = True

    async def collect():
        return tuple(
            [
                boundary_id
                async for boundary_id in workspace_module._new_boundary_ids(
                    discover(), set(), None
                )
            ]
        )

    assert run(collect()) == ("first", "second")
    assert closed


def test_inventory_add_limits_streamed_new_ids_and_closes_discovery(
    tmp_path, monkeypatch
):
    existing_id = "artifactory:artifactory_docker:existing"
    first_id = "artifactory:artifactory_docker:first"
    second_id = "artifactory:artifactory_docker:second"
    write_boundary(tmp_path, inventory(existing_id))
    backend = Mock(name="backend")
    backend.name = "artifactory_docker"
    backend.aclose = AsyncMock()
    backend.content_reader.return_value = Mock(aclose=AsyncMock())
    backend.inventory = AsyncMock(return_value=inventory(first_id))
    closed = False

    async def discover():
        nonlocal closed
        try:
            yield existing_id
            yield first_id
            yield second_id
        finally:
            closed = True

    backend.discover_boundaries = Mock(return_value=discover())
    workspace = configured_workspace(tmp_path, monkeypatch, backend)

    assert run(workspace.add(new_count=1)) == 1

    assert closed
    backend.inventory.assert_awaited_once_with(first_id)
    assert not (
        tmp_path
        / "artifactory_docker"
        / "boundaries"
        / second_id.replace(":", "%3A")
        / "boundary.json"
    ).exists()


def test_inventory_add_zero_limit_closes_discovery_without_inventory(
    tmp_path, monkeypatch
):
    boundary_id = "artifactory:artifactory_docker:unused"
    backend = Mock(name="backend")
    backend.name = "artifactory_docker"
    backend.inventory = AsyncMock(return_value=inventory(boundary_id))

    class Discovery:
        closed = False

        def __aiter__(self):
            return self

        async def __anext__(self):
            return boundary_id

        async def aclose(self):
            self.closed = True

    discovery = Discovery()
    backend.discover_boundaries = Mock(return_value=discovery)
    workspace = configured_workspace(tmp_path, monkeypatch, backend)

    assert run(workspace.add(new_count=0)) == 0

    assert discovery.closed
    backend.inventory.assert_not_awaited()


def test_inventory_add_rechecks_enrollment_under_boundary_ownership(
    tmp_path, monkeypatch
):
    boundary_id = "artifactory:artifactory_docker:raced"
    backend = Mock(name="backend")
    backend.name = "artifactory_docker"
    backend.inventory = AsyncMock(return_value=inventory(boundary_id))

    async def discover():
        yield boundary_id

    backend.discover_boundaries = Mock(return_value=discover())
    workspace = configured_workspace(tmp_path, monkeypatch, backend)
    run_boundaries = workspace._run_boundaries

    async def write_registration_before_ownership(operation, boundaries):
        boundary_path = boundaries[0].paths.boundary_dir
        boundary_path.mkdir(parents=True, exist_ok=True)
        record = BoundaryRecord(
            backend_id=backend.name,
            boundary=inventory(boundary_id).boundary,
            availability="absent",
        )
        (boundary_path / "boundary.json").write_text(record.model_dump_json())
        return await run_boundaries(operation, boundaries)

    monkeypatch.setattr(
        workspace,
        "_run_boundaries",
        write_registration_before_ownership,
    )

    assert run(workspace.add()) == 0

    saved = BoundaryRecord.model_validate_json(
        (
            tmp_path
            / "artifactory_docker"
            / "boundaries"
            / boundary_id.replace(":", "%3A")
            / "boundary.json"
        ).read_text()
    )
    assert saved.availability == "absent"
    backend.inventory.assert_not_awaited()


def test_inventory_enrolls_initial_and_new_boundaries(tmp_path, monkeypatch):
    first_id = "artifactory:artifactory_docker:first"
    second_id = "artifactory:artifactory_docker:second"
    backend = Mock(name="backend")
    backend.name = "artifactory_docker"
    backend.aclose = AsyncMock()
    backend.content_reader.return_value = Mock(aclose=AsyncMock())
    backend.discover_boundaries = AsyncMock(return_value=(first_id,))
    documents = {first_id: inventory(first_id), second_id: inventory(second_id)}
    backend.inventory = AsyncMock(
        side_effect=lambda boundary_id: documents[boundary_id]
    )
    workspace = configured_workspace(tmp_path, monkeypatch, backend)

    async def scenario():
        async with workspace:

            async def first_discovery():
                yield first_id

            backend.discover_boundaries = Mock(return_value=first_discovery())
            assert await workspace.add() == 1

            async def second_discovery():
                yield first_id
                yield second_id

            backend.discover_boundaries = Mock(return_value=second_discovery())
            assert await workspace.add() == 1

    run(scenario())

    assert {
        path.parent.name
        for path in tmp_path.glob("artifactory_docker/boundaries/*/scantargets.json")
    } == {first_id.replace(":", "%3A"), second_id.replace(":", "%3A")}
    assert (
        len(tuple(tmp_path.glob("artifactory_docker/boundaries/*/boundary.json"))) == 2
    )
    assert (tmp_path / "artifactory_docker/backend.json").is_file()


def test_inventory_add_partial_enrollment_failure_keeps_backend_discoverable(
    tmp_path, monkeypatch
):
    completed_id = "artifactory:artifactory_docker:completed"
    failed_id = "artifactory:artifactory_docker:failed"
    completed_path = (
        tmp_path
        / "artifactory_docker"
        / "boundaries"
        / completed_id.replace(":", "%3A")
    )
    completed_record_written = asyncio.Event()
    original_write = boundary_module.Boundary._write

    def signal_completed_record(self, path, document, model_type):
        original_write(self, path, document, model_type)
        if self.boundary_id == completed_id and path.name == "boundary.json":
            completed_record_written.set()

    monkeypatch.setattr(
        boundary_module.Boundary,
        "_write",
        signal_completed_record,
    )

    async def discover():
        yield completed_id
        yield failed_id

    async def inventory_for(boundary_id):
        if boundary_id == failed_id:
            await completed_record_written.wait()
            raise ArtifactoryError("enrollment failed")
        return inventory(boundary_id)

    backend = Mock(name="backend")
    backend.name = "artifactory_docker"
    backend.aclose = AsyncMock()
    backend.discover_boundaries = Mock(return_value=discover())
    backend.inventory = AsyncMock(side_effect=inventory_for)
    workspace = configured_workspace(tmp_path, monkeypatch, backend)
    backend_record_path = tmp_path / "artifactory_docker" / "backend.json"

    with pytest.raises(ExceptionGroup) as raised:
        run(workspace.add())

    assert any(
        isinstance(error, ArtifactoryError) and "enrollment failed" in str(error)
        for error in raised.value.exceptions
    )
    backend_record = BackendWorkspaceRecord.model_validate_json(
        backend_record_path.read_text()
    )
    assert backend_record.name == backend.name
    assert workspace_module._persisted_backend_paths(tmp_path) == (backend_record_path,)
    assert (completed_path / "boundary.json").is_file()
    assert (completed_path / "scantargets.json").is_file()


def test_inventory_add_cancellation_keeps_backend_discoverable(tmp_path, monkeypatch):
    boundary_id = "artifactory:artifactory_docker:blocked"
    inventory_started = asyncio.Event()

    async def discover():
        yield boundary_id

    async def blocked_inventory(_boundary_id):
        inventory_started.set()
        await asyncio.Future()

    backend = Mock(name="backend")
    backend.name = "artifactory_docker"
    backend.aclose = AsyncMock()
    backend.discover_boundaries = Mock(return_value=discover())
    backend.inventory = AsyncMock(side_effect=blocked_inventory)
    workspace = configured_workspace(tmp_path, monkeypatch, backend)
    backend_record_path = tmp_path / "artifactory_docker" / "backend.json"

    async def cancel_add():
        task = asyncio.create_task(workspace.add())
        await inventory_started.wait()
        marker_was_written_before_inventory = backend_record_path.is_file()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        return marker_was_written_before_inventory

    assert run(cancel_add())
    assert workspace_module._persisted_backend_paths(tmp_path) == (backend_record_path,)
    assert not tuple(
        (tmp_path / "artifactory_docker" / "boundaries").glob("*/boundary.json")
    )
    run(backend.aclose())


def test_inventory_add_discovery_failure_does_not_write_backend_marker(
    tmp_path, monkeypatch
):
    boundary_id = "artifactory:artifactory_docker:unselected"

    async def discover_then_fail():
        yield boundary_id
        raise ArtifactoryError("discovery failed")

    backend = Mock(name="backend")
    backend.name = "artifactory_docker"
    backend.inventory = AsyncMock()
    backend.discover_boundaries = Mock(return_value=discover_then_fail())
    workspace = configured_workspace(tmp_path, monkeypatch, backend)

    with pytest.raises(ArtifactoryError, match="discovery failed"):
        run(workspace.add())

    assert not (tmp_path / "artifactory_docker" / "backend.json").exists()
    assert not tuple(
        (tmp_path / "artifactory_docker" / "boundaries").glob("*/boundary.json")
    )
    backend.inventory.assert_not_awaited()


def test_empty_inventory_add_does_not_create_backend_marker(tmp_path, monkeypatch):
    async def discover():
        if False:
            yield "unreachable"

    backend = Mock(name="backend")
    backend.name = "artifactory_docker"
    backend.inventory = AsyncMock()
    backend.discover_boundaries = Mock(return_value=discover())
    workspace = configured_workspace(tmp_path, monkeypatch, backend)

    assert run(workspace.add()) == 0

    assert not (tmp_path / "artifactory_docker" / "backend.json").exists()
    backend.inventory.assert_not_awaited()


def test_inventory_add_repairs_marker_for_registered_boundaries(tmp_path, monkeypatch):
    boundary_id = "artifactory:artifactory_docker:registered"
    write_boundary(tmp_path, inventory(boundary_id))
    backend_record_path = tmp_path / "artifactory_docker" / "backend.json"
    backend_record_path.unlink()

    async def discover():
        yield boundary_id

    backend = Mock(name="backend")
    backend.name = "artifactory_docker"
    backend.inventory = AsyncMock()
    backend.discover_boundaries = Mock(return_value=discover())
    workspace = configured_workspace(tmp_path, monkeypatch, backend)

    assert run(workspace.add()) == 0

    assert (
        BackendWorkspaceRecord.model_validate_json(backend_record_path.read_text()).name
        == backend.name
    )
    backend.inventory.assert_not_awaited()


def test_boundary_discovery_failure_preserves_existing_inventory(tmp_path, monkeypatch):
    boundary_id = "artifactory:artifactory_docker:existing"
    boundary_path = write_boundary(tmp_path, inventory(boundary_id))
    targets_path = boundary_path / "scantargets.json"
    before = targets_path.read_bytes()
    backend = Mock(name="backend")
    backend.name = "artifactory_docker"

    async def failed_discovery():
        raise ArtifactoryError("repository discovery failed")
        yield "unreachable"

    backend.discover_boundaries = failed_discovery
    workspace = configured_workspace(tmp_path, monkeypatch, backend)

    with pytest.raises(ArtifactoryError, match="repository discovery failed"):
        run(workspace.add())

    assert targets_path.read_bytes() == before
    backend.inventory.assert_not_called()


def test_update_dispatches_sorted_registered_boundary_ids(tmp_path, monkeypatch):
    boundary_ids = (
        "artifactory:artifactory_docker:z-last",
        "artifactory:artifactory_docker:a-first",
    )
    for boundary_id in boundary_ids:
        write_boundary(tmp_path, inventory(boundary_id))
    backend = Mock(name="backend")
    backend.name = "artifactory_docker"
    workspace = configured_workspace(tmp_path, monkeypatch, backend)
    captured: list[str] = []

    async def capture(operation, boundaries):
        assert operation.__name__ == "refresh_inventory"
        captured.extend(boundary.boundary_id for boundary in boundaries)
        return len(boundaries)

    monkeypatch.setattr(workspace, "_run_boundaries", capture)

    assert run(workspace.update()) == 2

    assert captured == sorted(boundary_ids)
    backend.discover_boundaries.assert_not_called()


def test_update_checks_registered_boundary_existence(tmp_path, monkeypatch):
    boundary_id = "artifactory:artifactory_docker:missing"
    boundary_path = write_boundary(tmp_path, inventory(boundary_id))
    backend = Mock(name="backend")
    backend.name = "artifactory_docker"
    backend.inventory = AsyncMock(return_value=None)
    workspace = configured_workspace(tmp_path, monkeypatch, backend)

    assert run(workspace.update()) == 1

    record = BoundaryRecord.model_validate_json(
        (boundary_path / "boundary.json").read_text()
    )
    assert record.availability == "absent"
    assert not (boundary_path / "scantargets.json").exists()
    backend.inventory.assert_awaited_once_with(boundary_id)

    backend.inventory.return_value = inventory(boundary_id)
    assert run(workspace.update()) == 1
    restored = BoundaryRecord.model_validate_json(
        (boundary_path / "boundary.json").read_text()
    )
    assert restored.availability == "available"
    assert (boundary_path / "scantargets.json").is_file()


def test_source_dependent_commands_skip_absent_boundaries(tmp_path, monkeypatch):
    boundary_id = "artifactory:artifactory_docker:absent"
    boundary_path = write_boundary(tmp_path, inventory(boundary_id))
    record = BoundaryRecord.model_validate_json(
        (boundary_path / "boundary.json").read_text()
    ).model_copy(update={"availability": "absent"})
    (boundary_path / "boundary.json").write_text(record.model_dump_json())
    (boundary_path / "scantargets.json").unlink()
    backend = Mock(name="backend")
    backend.name = "artifactory_docker"
    backend.aclose = AsyncMock()
    workspace = configured_workspace(tmp_path, monkeypatch, backend)

    async def scenario():
        async with workspace:
            assert await workspace.scan() == 0
            assert await workspace.judge() == 0
            assert await workspace.extract() == 0

    run(scenario())
    backend.content_reader.assert_not_called()


def test_absent_boundary_skip_does_not_cancel_sibling_work(tmp_path, monkeypatch):
    absent_id = "artifactory:artifactory_docker:absent"
    sibling_id = "artifactory:artifactory_docker:sibling"
    absent_path = write_boundary(tmp_path, inventory(absent_id))
    write_boundary(tmp_path, inventory(sibling_id))
    absent = BoundaryRecord.model_validate_json(
        (absent_path / "boundary.json").read_text()
    ).model_copy(update={"availability": "absent"})
    (absent_path / "boundary.json").write_text(absent.model_dump_json())
    (absent_path / "scantargets.json").unlink()

    backend = Mock(name="backend")
    backend.name = "artifactory_docker"
    backend.aclose = AsyncMock()
    workspace = configured_workspace(tmp_path, monkeypatch, backend)
    active = asyncio.Event()
    skipped_absent = asyncio.Event()
    finish_active = asyncio.Event()
    cancelled = False

    async def operation(boundary):
        nonlocal cancelled
        if boundary.boundary_id == absent_id:
            result = await boundary.scan()
            skipped_absent.set()
            return result
        active.set()
        try:
            await finish_active.wait()
            return True
        except asyncio.CancelledError:
            cancelled = True
            raise

    async def scenario():
        task = asyncio.create_task(
            workspace._run_boundaries(operation, workspace.boundaries)
        )
        await asyncio.wait_for(asyncio.gather(active.wait(), skipped_absent.wait()), 2)
        finish_active.set()
        return await task

    assert run(scenario()) == 1
    assert not cancelled
    backend.content_reader.assert_not_called()


def test_source_operation_starts_all_boundary_services(tmp_path, monkeypatch):
    boundary_id = "artifactory:artifactory_docker:available"
    write_boundary(tmp_path, inventory(boundary_id))
    record_path = next(tmp_path.rglob("boundary.json"))
    record = BoundaryRecord.model_validate_json(record_path.read_text())
    record.phase = "judge"
    record_path.write_text(record.model_dump_json())
    record_path.with_name("report.json").write_text(
        TitusReport(boundary_id=boundary_id, generated_at="now").model_dump_json()
    )
    record_path.with_name("credentials.json").write_text(
        CredentialsDocument(
            boundary_id=boundary_id, report_generated_at="now"
        ).model_dump_json()
    )
    reader = Mock(aclose=AsyncMock())
    backend = Mock(name="backend")
    backend.name = "artifactory_docker"
    backend.content_reader.return_value = reader
    backend.aclose = AsyncMock()
    scanner_factory = Mock(return_value=Mock())
    judge_factory = Mock(return_value=Mock())
    extractor_factory = Mock(return_value=Mock())
    monkeypatch.setattr(boundary_module, "TitusCliScanner", scanner_factory)
    monkeypatch.setattr(boundary_module, "DspyFindingJudge", judge_factory)
    monkeypatch.setattr(boundary_module, "EvidenceExtractor", extractor_factory)
    workspace = configured_workspace(tmp_path, monkeypatch, backend)

    async def scenario():
        async with workspace:
            assert await workspace.judge() == 0

    run(scenario())
    backend.content_reader.assert_called_once()
    scanner_factory.assert_called_once()
    judge_factory.assert_called_once()
    extractor_factory.assert_called_once()
    reader.aclose.assert_awaited_once()


@pytest.mark.parametrize("catalog", [{}, {"repositories": []}])
def test_only_valid_empty_catalog_can_clear_selected_targets(
    tmp_path, monkeypatch, catalog
):
    boundary_id = "artifactory:artifactory_docker:repo"
    boundary_path = write_boundary(tmp_path, inventory(boundary_id, with_target=True))
    targets_path = boundary_path / "scantargets.json"
    before = targets_path.read_bytes()

    async def handler(request):
        if request.url.path == "/artifactory/api/repositories":
            return httpx.Response(
                200,
                json=[{"key": "repo", "packageType": "Docker", "type": "LOCAL"}],
            )
        if request.url.path.endswith("/_catalog"):
            return httpx.Response(200, json=catalog)
        raise AssertionError(f"unexpected request: {request.url}")

    backend = http_backend(handler)
    workspace = configured_workspace(tmp_path, monkeypatch, backend)
    try:
        if catalog:
            assert run(workspace.update()) == 1
            saved = ScanTargetInventory.model_validate_json(targets_path.read_text())
            assert saved.targets == ()
        else:
            with pytest.raises(ExceptionGroup) as raised:
                run(workspace.update())
            assert any(
                isinstance(error, ArtifactoryError) for error in raised.value.exceptions
            )
            assert targets_path.read_bytes() == before
    finally:
        run(backend.aclose())


def test_discovers_supported_local_docker_boundaries():
    async def handler(request):
        assert request.url.path == "/artifactory/api/repositories"
        return httpx.Response(
            200,
            json=[
                {"key": "docker-local", "packageType": "Docker", "type": "LOCAL"},
                {"key": "docker-remote", "packageType": "Docker", "type": "REMOTE"},
                {"key": "generic-local", "packageType": "Generic", "type": "LOCAL"},
            ],
        )

    backend = http_backend(handler)

    async def collect():
        return tuple(
            [boundary_id async for boundary_id in backend.discover_boundaries()]
        )

    try:
        assert run(collect()) == ("artifactory:artifactory_docker:docker-local",)
    finally:
        run(backend.aclose())


def test_continuation_404_preserves_previous_inventory(tmp_path, monkeypatch):
    boundary_id = "artifactory:artifactory_docker:repo"
    boundary_path = write_boundary(tmp_path, inventory(boundary_id, with_target=True))
    record_path = boundary_path / "boundary.json"
    targets_path = boundary_path / "scantargets.json"
    before_record = record_path.read_bytes()
    before_targets = targets_path.read_bytes()

    async def handler(request):
        if request.url.path == "/artifactory/api/repositories":
            return httpx.Response(
                200,
                json=[{"key": "repo", "packageType": "Docker", "type": "LOCAL"}],
            )
        if request.url.path.endswith("/v2/_catalog"):
            if request.url.params.get("page") == "2":
                return httpx.Response(404, text="continuation missing")
            return httpx.Response(
                200,
                json={"repositories": ["image"]},
                headers={"Link": '<?page=2>; rel="next"'},
            )
        raise AssertionError(f"unexpected request: {request.url}")

    backend = http_backend(handler)
    workspace = configured_workspace(tmp_path, monkeypatch, backend)
    try:
        with pytest.raises(ExceptionGroup) as raised:
            run(workspace.update())
    finally:
        run(backend.aclose())

    assert any(
        isinstance(error, ArtifactoryError)
        and "continuation page returned 404" in str(error)
        for error in raised.value.exceptions
    )
    assert record_path.read_bytes() == before_record
    assert targets_path.read_bytes() == before_targets


def test_pagination_failure_preserves_previous_inventory(tmp_path, monkeypatch):
    boundary_id = "artifactory:artifactory_docker:repo"
    boundary_path = write_boundary(tmp_path, inventory(boundary_id, with_target=True))
    record_path = boundary_path / "boundary.json"
    targets_path = boundary_path / "scantargets.json"
    before_record = record_path.read_bytes()
    before_targets = targets_path.read_bytes()

    async def handler(request):
        if request.url.path == "/artifactory/api/repositories":
            return httpx.Response(
                200,
                json=[{"key": "repo", "packageType": "Docker", "type": "LOCAL"}],
            )
        if request.url.path.endswith("/v2/_catalog"):
            return httpx.Response(
                200,
                json={"repositories": ["image"]},
                headers={"Link": '<?page=2>; rel="next"'},
            )
        raise AssertionError(f"unexpected request: {request.url}")

    backend = http_backend(handler)
    workspace = configured_workspace(tmp_path, monkeypatch, backend)
    try:
        with pytest.raises(ExceptionGroup) as raised:
            run(workspace.update())
    finally:
        run(backend.aclose())

    assert any(
        isinstance(error, ArtifactoryError) and "pagination loop" in str(error)
        for error in raised.value.exceptions
    )
    assert record_path.read_bytes() == before_record
    assert targets_path.read_bytes() == before_targets


@pytest.mark.parametrize(
    ("old_timestamp_header", "new_timestamp_header"),
    [
        (None, None),
        ("not-a-date", "not-a-date"),
        (None, "Thu, 01 Jan 2026 00:00:00 GMT"),
    ],
    ids=["all-missing", "all-malformed", "mixed"],
)
def test_unusable_manifest_timestamps_fail_latest_selection(
    old_timestamp_header, new_timestamp_header
):
    async def handler(request):
        if request.url.path.endswith("/tags/list"):
            return httpx.Response(200, json={"tags": ["old", "new"]})
        if request.url.path.endswith("/manifests/old"):
            timestamp_header = old_timestamp_header
        elif request.url.path.endswith("/manifests/new"):
            timestamp_header = new_timestamp_header
        else:
            raise AssertionError(f"unexpected request: {request.url}")
        return httpx.Response(
            200,
            json={"schemaVersion": 2},
            headers=(
                {"Last-Modified": timestamp_header}
                if timestamp_header is not None
                else {}
            ),
        )

    backend = http_backend(handler)
    try:
        with pytest.raises(ArtifactoryError, match="usable manifest timestamp"):
            run(backend._select_latest("repo", "image", "linux/amd64"))
    finally:
        run(backend.aclose())


@pytest.mark.parametrize(
    "timestamp_header",
    [None, "not-a-date"],
    ids=["missing", "malformed"],
)
def test_timestamp_discovery_failure_preserves_previous_inventory(
    tmp_path, monkeypatch, timestamp_header
):
    boundary_id = "artifactory:artifactory_docker:repo"
    boundary_path = write_boundary(tmp_path, inventory(boundary_id, with_target=True))
    record_path = boundary_path / "boundary.json"
    targets_path = boundary_path / "scantargets.json"
    before_record = record_path.read_bytes()
    before_targets = targets_path.read_bytes()

    async def handler(request):
        if request.url.path == "/artifactory/api/repositories":
            return httpx.Response(
                200,
                json=[{"key": "repo", "packageType": "Docker", "type": "LOCAL"}],
            )
        if request.url.path.endswith("/v2/_catalog"):
            return httpx.Response(200, json={"repositories": ["image"]})
        if request.url.path.endswith("/tags/list"):
            return httpx.Response(200, json={"tags": ["old", "new"]})
        if request.url.path.endswith("/manifests/old"):
            return httpx.Response(
                200,
                json={"schemaVersion": 2},
                headers=(
                    {"Last-Modified": timestamp_header}
                    if timestamp_header is not None
                    else {}
                ),
            )
        if request.url.path.endswith("/manifests/new"):
            return httpx.Response(
                200,
                json={"schemaVersion": 2},
                headers={"Last-Modified": "Thu, 01 Jan 2026 00:00:00 GMT"},
            )
        raise AssertionError(f"unexpected request: {request.url}")

    backend = http_backend(handler)
    workspace = configured_workspace(tmp_path, monkeypatch, backend)
    try:
        with pytest.raises(ExceptionGroup) as raised:
            run(workspace.update())
    finally:
        run(backend.aclose())

    assert any(
        isinstance(error, ArtifactoryError)
        and "usable manifest timestamp" in str(error)
        for error in raised.value.exceptions
    )
    assert record_path.read_bytes() == before_record
    assert targets_path.read_bytes() == before_targets


def test_tag_pagination_is_complete_before_latest_selection():
    async def handler(request):
        if request.url.params.get("page") == "2":
            return httpx.Response(200, json={"tags": ["new"]})
        return httpx.Response(
            200,
            json={"tags": ["old"]},
            headers={
                "Link": "<https://artifactory.example/artifactory/api/docker/"
                'repo/v2/image/tags/list?page=2>; rel="next"'
            },
        )

    backend = http_backend(handler)
    old = datetime(2026, 1, 1, tzinfo=UTC)
    new = datetime(2026, 2, 1, tzinfo=UTC)
    backend._platform_manifest = AsyncMock(
        side_effect=lambda _repository, _image, tag, _platform: (
            f"sha256:{tag}-root",
            f"sha256:{tag}",
            new if tag == "new" else old,
        )
    )
    try:
        selected = run(backend._select_latest("repo", "image", "linux/amd64"))
    finally:
        run(backend.aclose())

    assert selected is not None
    assert selected.digest == "sha256:new"
    assert selected.tags == ("new",)


@pytest.mark.parametrize(
    ("method", "payload", "message"),
    [
        ("images", [], "catalog was not an object"),
        ("images", {}, "catalog repositories was not an array"),
        ("images", {"repositories": "image"}, "repositories was not an array"),
        ("images", {"repositories": [""]}, "contained an invalid name"),
        ("tags", [], "tag list was not an object"),
        ("tags", {}, "tag list tags was not an array"),
        ("tags", {"tags": "latest"}, "tags was not an array"),
        ("tags", {"tags": [1]}, "contained an invalid name"),
    ],
)
def test_catalog_and_tag_payloads_fail_closed(method, payload, message):
    async def handler(_request):
        return httpx.Response(200, json=payload)

    backend = http_backend(handler)
    try:
        operation = (
            backend.list_images("repo")
            if method == "images"
            else backend.list_tags("repo", "image")
        )
        with pytest.raises(ArtifactoryError, match=message):
            run(operation)
    finally:
        run(backend.aclose())


def test_empty_catalog_and_tag_lists_are_successful():
    async def handler(request):
        field = "repositories" if request.url.path.endswith("_catalog") else "tags"
        return httpx.Response(200, json={field: []})

    backend = http_backend(handler)
    try:
        assert run(backend.list_images("repo")) == set()
        assert run(backend.list_tags("repo", "image")) == []
    finally:
        run(backend.aclose())
