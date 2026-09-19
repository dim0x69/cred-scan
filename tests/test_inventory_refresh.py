"""Failed discovery must not replace the last successful inventory snapshot."""

import asyncio
from datetime import UTC, datetime
from unittest.mock import AsyncMock, Mock
from urllib.parse import quote

import pytest

from cred_scan.backend.adapters.artifactory.docker import ArtifactoryDockerBackend, DockerImageScanScope
from cred_scan.backend.adapters.artifactory.models import ArtifactoryRepository
from cred_scan.backend.inventory import merge_inventory
from cred_scan.backend.models import ScanBoundaryInventory, ScanTarget, target_id_for
from cred_scan.orch import boundary as boundary_module
from cred_scan.orch.boundary import Boundary


@pytest.fixture
def previous():
    repository = ArtifactoryRepository(id="artifactory:primary:repo", name="repo")
    scope = DockerImageScanScope(
        image="registry/repo/image", digest="sha256:old", root_digest="sha256:old",
        platform="linux/amd64", manifest_timestamp=datetime(2026, 1, 1, tzinfo=UTC),
    )
    target = ScanTarget(
        id=target_id_for(scope), backend_id="primary", boundary=repository, scope=scope,
    )
    target.result.status = "scanned"
    return ScanBoundaryInventory(
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
        boundary=repository, targets=(target,),
    )


def discovery(previous, *, partial=True):
    target = previous.targets[0].model_copy(deep=True)
    target.scope.digest = "sha256:new"
    target.id = target_id_for(target.scope)
    return previous.model_copy(update={
        "generated_at": datetime(2026, 2, 1, tzinfo=UTC),
        "targets": (target,) if partial else (),
        "lifecycle": "active", "stale_reason": None,
        "errors": ("incomplete discovery", "incomplete discovery"),
    })


@pytest.mark.parametrize("partial", [False, True])
@pytest.mark.parametrize("stale", [False, True])
def test_failed_merge_preserves_snapshot(previous, partial, stale):
    if stale:
        previous.lifecycle = "stale"
        previous.stale_reason = "previous absence"
    before = previous.model_dump()
    with pytest.raises(ValueError, match="incomplete inventory discovery"):
        merge_inventory(previous, discovery(previous, partial=partial))
    assert previous.model_dump() == before


def test_initial_partial_discovery_does_not_adopt_targets(previous):
    with pytest.raises(ValueError, match="incomplete inventory discovery"):
        merge_inventory(None, discovery(previous))


@pytest.fixture
def loaded_boundary(previous, tmp_path, monkeypatch):
    path = tmp_path / quote(previous.boundary.id, safe="")
    path.mkdir()
    (path / "inventory.json").write_text(previous.model_dump_json())
    backend = Mock()
    backend.inventory = AsyncMock()
    backend.content_reader.return_value = Mock(aclose=AsyncMock())
    monkeypatch.setattr(boundary_module, "DspyFindingJudge", Mock())
    monkeypatch.setattr(boundary_module, "TitusCliScanner", Mock())
    boundary = Boundary(backend, path)
    return boundary


@pytest.mark.parametrize("error", [OSError("discovery unavailable"), KeyError("missing boundary")])
def test_refresh_raises_without_changing_inventory(loaded_boundary, error):
    boundary = loaded_boundary
    before = boundary.paths.inventory.read_bytes()
    snapshot = boundary.inventory.model_dump()
    boundary.backend.inventory.side_effect = error
    with pytest.raises(type(error)) as raised:
        asyncio.run(boundary.refresh_inventory())
    assert raised.value is error
    assert boundary.paths.inventory.read_bytes() == before
    assert boundary.inventory.model_dump() == snapshot
    boundary.reader.aclose.assert_not_awaited()
    assert boundary.backend.content_reader.call_count == 1
    assert not boundary.paths.operation_lock.exists()


def test_backend_failure_after_one_selected_image_propagates(previous):
    backend = object.__new__(ArtifactoryDockerBackend)
    backend._name = "primary"
    backend.platform = "linux/amd64"
    backend.repositories = AsyncMock(return_value=[{
        "key": "repo", "packageType": "docker", "type": "local",
    }])
    backend.list_images = AsyncMock(return_value=["first", "second"])
    error = OSError("second image unavailable")
    backend._select_latest = AsyncMock(side_effect=[previous.targets[0].scope, error])
    with pytest.raises(OSError) as raised:
        asyncio.run(backend.inventory(previous.boundary.id))
    assert raised.value is error
    assert backend._select_latest.await_count == 2


def test_successful_refresh_updates_inventory(loaded_boundary):
    boundary = loaded_boundary
    successful = discovery(boundary.inventory).model_copy(update={"errors": ()})
    boundary.backend.inventory.return_value = successful
    assert asyncio.run(boundary.refresh_inventory())
    saved = ScanBoundaryInventory.model_validate_json(boundary.paths.inventory.read_text())
    assert saved.generated_at == successful.generated_at
    assert saved.targets[-1].id == successful.targets[0].id
    assert saved.targets[-1].result.status == "pending"
    assert saved.errors == ()


def test_cancelled_discovery_does_not_checkpoint_failure(loaded_boundary):
    boundary = loaded_boundary
    before = boundary.paths.inventory.read_bytes()
    boundary.backend.inventory.side_effect = asyncio.CancelledError()
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(boundary.refresh_inventory())
    assert boundary.paths.inventory.read_bytes() == before
    assert not boundary.paths.operation_lock.exists()
