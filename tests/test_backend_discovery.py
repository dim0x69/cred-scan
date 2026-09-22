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
from cred_scan.scan.models import ExclusionFiles


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


def inventory(
    boundary_id: str, *, with_target: bool = False
) -> ScanTargetInventory:
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


def test_inventory_enrolls_initial_and_new_boundaries(tmp_path, monkeypatch):
    first_id = "artifactory:artifactory_docker:first"
    second_id = "artifactory:artifactory_docker:second"
    backend = Mock(name="backend")
    backend.name = "artifactory_docker"
    backend.aclose = AsyncMock()
    backend.content_reader.return_value = Mock(aclose=AsyncMock())
    backend.discover_boundaries = AsyncMock(return_value=(first_id,))
    documents = {first_id: inventory(first_id), second_id: inventory(second_id)}
    backend.inventory = AsyncMock(side_effect=lambda boundary_id: documents[boundary_id])
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
        for path in tmp_path.glob(
            "artifactory_docker/boundaries/*/scantargets.json"
        )
    } == {first_id.replace(":", "%3A"), second_id.replace(":", "%3A")}
    assert len(
        tuple(tmp_path.glob("artifactory_docker/boundaries/*/boundary.json"))
    ) == 2
    assert (tmp_path / "artifactory_docker/backend.json").is_file()


def test_boundary_discovery_failure_preserves_existing_inventory(
    tmp_path, monkeypatch
):
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


def test_update_checks_registered_boundary_existence(
    tmp_path, monkeypatch
):
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


def test_source_operation_starts_all_boundary_services(tmp_path, monkeypatch):
    boundary_id = "artifactory:artifactory_docker:available"
    write_boundary(tmp_path, inventory(boundary_id))
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
    boundary_path = write_boundary(
        tmp_path, inventory(boundary_id, with_target=True)
    )
    targets_path = boundary_path / "scantargets.json"
    before = targets_path.read_bytes()

    async def handler(request):
        if request.url.path == "/artifactory/api/repositories":
            return httpx.Response(
                200,
                json=[
                    {"key": "repo", "packageType": "Docker", "type": "LOCAL"}
                ],
            )
        if request.url.path.endswith("/_catalog"):
            return httpx.Response(200, json=catalog)
        raise AssertionError(f"unexpected request: {request.url}")

    backend = http_backend(handler)
    workspace = configured_workspace(tmp_path, monkeypatch, backend)
    try:
        if catalog:
            assert run(workspace.update()) == 1
            saved = ScanTargetInventory.model_validate_json(
                targets_path.read_text()
            )
            assert saved.targets == ()
        else:
            with pytest.raises(ExceptionGroup) as raised:
                run(workspace.update())
            assert any(
                isinstance(error, ArtifactoryError)
                for error in raised.value.exceptions
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
            [
                boundary_id
                async for boundary_id in backend.discover_boundaries()
            ]
        )

    try:
        assert run(collect()) == (
            "artifactory:artifactory_docker:docker-local",
        )
    finally:
        run(backend.aclose())


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
                json=[
                    {"key": "repo", "packageType": "Docker", "type": "LOCAL"}
                ],
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
        isinstance(error, ArtifactoryError)
        and "pagination loop" in str(error)
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
                json=[
                    {"key": "repo", "packageType": "Docker", "type": "LOCAL"}
                ],
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
