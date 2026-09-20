import asyncio
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, Mock

import pytest
from pydantic import ValidationError

from cred_scan.backend.inventory import merge_inventory
from cred_scan.backend.models import (
    ArtifactoryRepository,
    BackendConfig,
    DockerImageScanScope,
    GitOrganization,
    GitRepositoryScanScope,
    PackageScanScope,
    ScanBoundaryInventory,
    ScanTarget,
    target_id_for,
)
from cred_scan.scan.models import CredentialsDocument, TitusReport
from cred_scan.orch.models import WorkspaceConfig
from cred_scan.orch.workspace import Workspace
from cred_scan.extract.evidence import evidence_path
from cred_scan.orch import inventory, workspace as workspace_module
from cred_scan.orch.execution import BoundaryExecution, PhaseStatus
from cred_scan.orch.models import AppConfig


def make_workspace(tmp_path):
    return Workspace(WorkspaceConfig(workspace_dir=tmp_path))


def make_inventory(
    backend_name: str = "primary", digest: str = "sha256:first"
) -> ScanBoundaryInventory:
    repository = ArtifactoryRepository(
        id="artifactory:primary:docker-local", name="docker-local"
    )
    scope = DockerImageScanScope(
        image="registry/docker-local/team/api",
        digest=digest,
        root_digest="sha256:first",
        platform="linux/amd64",
        manifest_timestamp=datetime.now(timezone.utc),
    )
    target = ScanTarget(
        id=target_id_for(scope),
        backend_id=backend_name,
        boundary=repository,
        scope=scope,
    )
    return ScanBoundaryInventory(
        generated_at=datetime.now(timezone.utc),
        backend=BackendConfig(name=backend_name),
        boundary=repository,
        targets=(target,),
    )


def test_scope_identity_is_stable_while_pin_changes():
    first = DockerImageScanScope(
        image="registry/docker-local/team/api",
        digest="sha256:first",
        root_digest="sha256:first",
        platform="linux/amd64",
        manifest_timestamp=datetime.now(timezone.utc),
    )
    second = first.model_copy(update={"digest": "sha256:second"})

    assert first.id == second.id
    assert first.pin_id != second.pin_id
    assert target_id_for(first) != target_id_for(second)


def test_workspace_inventory_round_trip(
    app_config: AppConfig, repository_inventory: ScanBoundaryInventory
):
    workspace = Workspace(app_config.workspace)
    repository = workspace.boundary(repository_inventory.boundary.id)
    workspace.write(repository.inventory, repository_inventory, ScanBoundaryInventory)

    assert repository.inventory.exists()
    loaded = workspace.read(repository.inventory, ScanBoundaryInventory)
    assert loaded is not None
    assert loaded.backend.name == "primary"
    assert loaded.boundary == repository_inventory.boundary
    assert not list(repository.boundary_dir.rglob("*.lock"))


def test_typed_workspace_distinguishes_missing_and_invalid_documents(tmp_path):
    workspace = make_workspace(tmp_path)
    repository = workspace.boundary("repository")

    assert workspace.read(repository.inventory, ScanBoundaryInventory) is None
    with pytest.raises(TypeError, match="expected ScanBoundaryInventory"):
        workspace.write(
            repository.inventory,
            TitusReport(
                boundary_id="repository",
                generated_at="2026-01-01T00:00:00+00:00",
            ),
            ScanBoundaryInventory,
        )

    repository.inventory.parent.mkdir(parents=True, exist_ok=True)
    repository.inventory.write_text('{"schema_version": 1}')
    with pytest.raises(ValidationError):
        workspace.read(repository.inventory, ScanBoundaryInventory)


def test_evidence_paths_are_safe_and_repository_relative(tmp_path):
    workspace = make_workspace(tmp_path)
    repository = workspace.boundary("repository")
    destination = evidence_path(repository.boundary_dir, "credential/one", "app.env")

    assert (
        destination
        == repository.boundary_dir / "evidence" / "credential%2Fone" / "app.env"
    )
    assert destination.relative_to(repository.boundary_dir).as_posix() == (
        "evidence/credential%2Fone/app.env"
    )
    colon_destination = evidence_path(
        repository.boundary_dir, "credential/one", "app:prod.env"
    )
    assert colon_destination.name == "app:prod.env"


def test_backend_inventory_merge_adds_new_pins_without_removing_old_targets(tmp_path):
    workspace = make_workspace(tmp_path)
    first = make_inventory()
    repository = workspace.boundary(first.boundary.id)
    workspace.write(repository.inventory, first, ScanBoundaryInventory)

    later = make_inventory(digest="sha256:later")
    merged = merge_inventory(
        workspace.read(repository.inventory, ScanBoundaryInventory), later
    )
    workspace.write(repository.inventory, merged, ScanBoundaryInventory)

    result = workspace.read(repository.inventory, ScanBoundaryInventory)
    assert result is not None
    scope = result.targets[0].scope
    assert isinstance(scope, DockerImageScanScope)
    assert scope.digest == "sha256:first"
    assert result.targets[0].lifecycle == "superseded"
    assert len(result.targets) == 2
    assert result.targets[1].scope.digest == "sha256:later"
    assert result.targets[1].result.status == "pending"


def test_inventory_merge_uses_latest_discovery_errors():
    current = make_inventory()
    current.errors = ("temporary failure",)
    discovered = make_inventory()
    discovered.errors = ("current failure", "current failure")

    result = merge_inventory(current, discovered)

    assert result.errors == ("current failure",)
    assert result.targets[0].scope == current.targets[0].scope


def test_inventory_merge_retains_distinct_pins_within_discovery():
    discovered = make_inventory()
    duplicate = make_inventory(digest="sha256:duplicate").targets[0]
    discovered.targets = discovered.targets + (duplicate,)

    result = merge_inventory(None, discovered)

    assert len(result.targets) == 2
    digests = set()
    for target in result.targets:
        assert isinstance(target.scope, DockerImageScanScope)
        digests.add(target.scope.digest)
    assert digests == {"sha256:first", "sha256:duplicate"}


def test_inventory_merge_retains_canonical_git_target_ids():
    boundary = GitOrganization(id="git:ghes-primary:security", name="security")
    backend = BackendConfig(name="ghes-primary")
    scope = GitRepositoryScanScope(
        remote="https://git.example/security/payments.git",
        commit="abc123",
        commit_timestamp=datetime.now(timezone.utc),
    )
    current_target = ScanTarget(
        id=target_id_for(scope),
        backend_id=backend.name,
        boundary=boundary,
        scope=scope,
    )
    current = ScanBoundaryInventory(
        generated_at=datetime.now(timezone.utc),
        backend=backend,
        boundary=boundary,
        targets=(current_target,),
    )
    newer = scope.model_copy(update={"commit": "newer-commit"})
    other = GitRepositoryScanScope(
        remote="https://git.example/security/identity.git",
        commit="def456",
        commit_timestamp=datetime.now(timezone.utc),
    )
    discovered = current.model_copy(
        update={
            "targets": tuple(
                ScanTarget(
                    id=target_id_for(pin),
                    backend_id=backend.name,
                    boundary=boundary,
                    scope=pin,
                )
                for pin in (newer, other)
            )
        }
    )

    result = merge_inventory(current, discovered)

    assert len(result.targets) == 3
    assert isinstance(result.targets[0].scope, GitRepositoryScanScope)
    assert isinstance(result.targets[1].scope, GitRepositoryScanScope)
    assert isinstance(result.targets[2].scope, GitRepositoryScanScope)
    assert result.targets[0].scope.commit == "abc123"
    assert result.targets[0].lifecycle == "superseded"
    assert result.targets[1].scope.commit == "newer-commit"
    assert result.targets[1].lifecycle == "current"
    assert result.targets[2].scope.commit == "def456"


def test_inventory_document_has_backend_configuration_only(tmp_path):
    workspace = make_workspace(tmp_path)
    inventory_document = make_inventory()
    repository = workspace.boundary(inventory_document.boundary.id)
    workspace.write(repository.inventory, inventory_document, ScanBoundaryInventory)
    payload = json.loads(repository.inventory.read_text())

    assert payload["backend"] == {"name": "primary"}
    assert "backend" not in payload["boundary"]
    assert "backend" not in payload["targets"][0]["boundary"]


def test_inventory_merge_rejects_backend_mismatch(tmp_path):
    current = make_inventory("primary")
    discovered = make_inventory("other")

    with pytest.raises(ValueError, match="another backend"):
        merge_inventory(current, discovered)


def test_inventory_rejects_targets_from_another_boundary(repository_inventory):
    target = repository_inventory.targets[0].model_copy(update={"backend_id": "other"})
    with pytest.raises(ValueError, match="belong to its backend and boundary"):
        ScanBoundaryInventory(
            generated_at=repository_inventory.generated_at,
            backend=repository_inventory.backend,
            boundary=repository_inventory.boundary,
            targets=(target,),
        )


def test_run_inventory_retires_error_only_empty_boundary(
    app_config, repository_inventory, monkeypatch
):
    workspace = Workspace(app_config)
    failed = repository_inventory.model_copy(
        update={"targets": (), "errors": ("temporary failure",)}
    )
    paths = workspace.boundary(failed.boundary.id)
    workspace.write(
        paths.execution,
        BoundaryExecution(boundary_id=failed.boundary.id),
        BoundaryExecution,
    )
    workspace.write(paths.inventory, failed, ScanBoundaryInventory)
    backend = Mock(
        inventory=AsyncMock(
            return_value=[repository_inventory.model_copy(update={"targets": ()})]
        ),
        aclose=AsyncMock(),
    )
    monkeypatch.setattr(
        workspace_module, "ArtifactoryDockerBackend", Mock(return_value=backend)
    )

    async def refresh():
        async with workspace.operation("inventory"):
            return await inventory.run_inventory(app_config, workspace)

    assert asyncio.run(refresh()) == 1
    refreshed = workspace.read(paths.inventory, ScanBoundaryInventory)
    assert refreshed.targets == () and refreshed.errors == ()
    assert refreshed.lifecycle == "active"
    backend.aclose.assert_awaited_once()


def test_run_inventory_persists_adapter_returned_boundaries(
    app_config, repository_inventory, monkeypatch
):
    backend = Mock(
        inventory=AsyncMock(return_value=[repository_inventory]), aclose=AsyncMock()
    )
    monkeypatch.setattr(
        workspace_module, "ArtifactoryDockerBackend", Mock(return_value=backend)
    )
    workspace = Workspace(app_config)

    async def refresh():
        async with workspace.operation("inventory"):
            return await inventory.run_inventory(app_config, workspace)

    assert asyncio.run(refresh()) == 1
    paths = workspace.boundary(repository_inventory.boundary.id)
    state = workspace.read(paths.execution, BoundaryExecution)
    assert state.scan == PhaseStatus.READY
    assert (
        workspace.read(paths.inventory, ScanBoundaryInventory) == repository_inventory
    )
    backend.aclose.assert_awaited_once()


@pytest.mark.parametrize("kind", ["docker", "git", "package"])
def test_scope_ids_are_canonical_and_version_independent(kind):
    if kind == "docker":
        scope = make_inventory().targets[0].scope
        changed = scope.model_copy(update={"digest": "sha256:new"})
    elif kind == "git":
        scope = GitRepositoryScanScope(
            remote="https://git.example/org/repo.git",
            commit="first",
            commit_timestamp=datetime.now(timezone.utc),
        )
        changed = scope.model_copy(update={"commit": "second"})
    else:
        scope = PackageScanScope(
            ecosystem="npm",
            name="pkg",
            uri="https://packages.example/pkg",
            digest="sha256:first",
        )
        changed = scope.model_copy(update={"digest": "sha256:new"})
    assert scope.id == changed.id
    assert scope.pin_id != changed.pin_id
    payload = scope.model_dump(mode="json")
    payload.update(id="tampered", pin_id="tampered")
    restored = type(scope).model_validate(payload)
    assert restored.id == scope.id
    assert restored.pin_id == scope.pin_id


def test_docker_selection_metadata_does_not_create_another_scan_pin():
    scope = make_inventory().targets[0].scope
    changed = scope.model_copy(
        update={
            "root_digest": "sha256:new-index",
            "platform": "linux/amd64/v2",
            "tags": ("new-tag",),
            "manifest_timestamp": datetime.now(timezone.utc),
        }
    )
    assert target_id_for(scope) == target_id_for(changed)


@pytest.mark.parametrize("field", ["id", "scope"])
def test_inventory_persistence_rejects_noncanonical_pin_without_replacing_file(
    tmp_path, field
):
    current = make_inventory()
    workspace = make_workspace(tmp_path)
    path = workspace.boundary(current.boundary.id).inventory
    workspace.write(path, current, ScanBoundaryInventory)
    original = path.read_bytes()
    payload = current.model_dump(mode="json")
    if field == "id":
        payload["targets"][0]["id"] = "legacy-logical-id"
        changed = current.targets[0].model_copy(update={"id": "legacy-logical-id"})
    else:
        payload["targets"][0]["scope"]["digest"] = "sha256:changed"
        changed = current.targets[0].model_copy(
            update={
                "scope": current.targets[0].scope.model_copy(
                    update={"digest": "sha256:changed"}
                )
            }
        )
    with pytest.raises(ValidationError, match="target ID must match"):
        ScanBoundaryInventory.model_validate(payload)
    with pytest.raises(ValidationError, match="target ID must match"):
        workspace.write(
            path,
            current.model_copy(update={"targets": (changed,)}),
            ScanBoundaryInventory,
        )
    assert path.read_bytes() == original


@pytest.mark.parametrize("version", [5, 6, 7])
def test_inventory_rejects_previous_identity_schema(version):
    payload = make_inventory().model_dump(mode="json")
    payload["schema_version"] = version
    with pytest.raises(ValidationError, match="schema_version"):
        ScanBoundaryInventory.model_validate(payload)


@pytest.mark.parametrize("status", ["scanned", "partial", "failed"])
def test_rediscovery_reuses_historical_pin_and_execution_result(tmp_path, status):
    first = make_inventory()
    first.targets[0].result.status = status
    first.targets[0].result.errors = ("retained diagnostic",)
    old = first.model_copy(deep=True)
    newer = make_inventory(digest="sha256:new")
    merged = merge_inventory(first, newer)
    restored = merge_inventory(merged, make_inventory())
    assert len(restored.targets) == 2
    assert restored.targets[0] == old.targets[0]
    assert restored.targets[1].lifecycle == "superseded"
    assert first == old  # Merging must not mutate its input checkpoint.
    assert merge_inventory(restored, make_inventory()).targets == restored.targets
    workspace = make_workspace(tmp_path)
    path = workspace.boundary(first.boundary.id).inventory
    workspace.write(path, restored, ScanBoundaryInventory)
    assert workspace.read(path, ScanBoundaryInventory) == restored


def test_repeated_multi_pin_discovery_is_idempotent():
    first = make_inventory()
    second = make_inventory(digest="sha256:new")
    discovered = first.model_copy(update={"targets": first.targets + second.targets})
    merged = merge_inventory(None, discovered)
    merged.targets[0].result.status = "scanned"
    merged.targets[1].result.status = "partial"
    repeated = merge_inventory(merged, discovered)
    assert repeated.targets == merged.targets
    assert [target.lifecycle for target in repeated.targets] == [
        "superseded",
        "current",
    ]
    assert len({target.id for target in repeated.targets}) == 2


def test_same_pin_discovery_preserves_result_and_scope_snapshot():
    current = make_inventory()
    current.targets[0].result.status = "scanned"
    fresh = make_inventory()
    scope = fresh.targets[0].scope
    assert isinstance(scope, DockerImageScanScope)
    scope.tags = ("new-tag",)
    scope.root_digest = "sha256:new-index"
    assert merge_inventory(current, fresh).targets == current.targets


def test_duplicate_discovery_does_not_reset_result():
    current = make_inventory()
    current.targets[0].result.status = "scanned"
    fresh = make_inventory()
    fresh.targets = fresh.targets * 2
    result = merge_inventory(current, fresh)
    assert result.targets == current.targets
    assert len(merge_inventory(None, fresh).targets) == 1


def test_new_pin_starts_pending_even_if_discovery_carries_execution_state():
    fresh = make_inventory()
    fresh.targets[0].result.status = "scanned"
    assert merge_inventory(None, fresh).targets[0].result.status == "pending"


@pytest.mark.parametrize("lifecycle", ["active", "stale"])
@pytest.mark.parametrize("partial_pin", [False, True])
def test_failed_discovery_preserves_all_lifecycle_and_execution_state(
    lifecycle, partial_pin
):
    current = make_inventory()
    current.lifecycle = lifecycle
    current.stale_reason = "absent" if lifecycle == "stale" else None
    current.targets[0].scope.lifecycle = lifecycle
    current.targets[0].result.status = "scanned"
    failed = make_inventory(digest="sha256:new")
    failed.errors = ("discovery failed", "discovery failed")
    if not partial_pin:
        failed.targets = ()
    result = merge_inventory(current, failed)
    assert result.targets == current.targets
    assert result.lifecycle == current.lifecycle
    assert result.stale_reason == current.stale_reason
    assert result.errors == ("discovery failed",)


def test_initial_partial_discovery_records_errors_without_promoting_pins():
    partial = make_inventory()
    partial.errors = ("incomplete version selection",)
    merged = merge_inventory(None, partial)
    assert merged.targets == ()
    assert merged.errors == partial.errors


def test_authoritative_scope_absence_and_return_preserve_all_pins():
    first = make_inventory()
    second = make_inventory(digest="sha256:new")
    history = merge_inventory(first, second)
    absent = second.model_copy(update={"targets": ()})
    stale = merge_inventory(history, absent)
    assert all(target.scope.lifecycle == "stale" for target in stale.targets)
    assert [target.id for target in stale.targets] == [
        target.id for target in history.targets
    ]
    returned = merge_inventory(stale, second)
    assert returned.targets == history.targets


def test_boundary_failure_and_reappearance_preserve_artifacts(
    app_config, repository_inventory, monkeypatch
):
    workspace = Workspace(app_config)
    paths = workspace.boundary(repository_inventory.boundary.id)
    workspace.write(paths.inventory, repository_inventory, ScanBoundaryInventory)
    workspace.write(
        paths.execution,
        BoundaryExecution(boundary_id=repository_inventory.boundary.id),
        BoundaryExecution,
    )
    workspace.write(
        paths.report,
        TitusReport(boundary_id=repository_inventory.boundary.id, generated_at="old"),
        TitusReport,
    )
    workspace.write(
        paths.credentials,
        CredentialsDocument(
            boundary_id=repository_inventory.boundary.id, report_generated_at="old"
        ),
        CredentialsDocument,
    )
    evidence = evidence_path(paths.boundary_dir, "synthetic", "app.env")
    evidence.parent.mkdir(parents=True)
    evidence.write_bytes(b"historical artifact")
    artifacts = {p: p.read_bytes() for p in (paths.report, paths.credentials, evidence)}
    backend = Mock(inventory=AsyncMock(), aclose=AsyncMock())
    monkeypatch.setattr(
        workspace_module, "ArtifactoryDockerBackend", Mock(return_value=backend)
    )

    async def refresh():
        async with workspace.operation("inventory"):
            await inventory.run_inventory(app_config, workspace)

    backend.inventory.return_value = []
    asyncio.run(refresh())
    assert workspace.read(paths.inventory, ScanBoundaryInventory).lifecycle == "stale"
    backend.inventory.return_value = [
        repository_inventory.model_copy(update={"targets": (), "errors": ("HTTP 503",)})
    ]
    asyncio.run(refresh())
    failed = workspace.read(paths.inventory, ScanBoundaryInventory)
    assert failed.lifecycle == "stale" and failed.errors == ("HTTP 503",)
    backend.inventory.return_value = [repository_inventory]
    asyncio.run(refresh())
    returned = workspace.read(paths.inventory, ScanBoundaryInventory)
    assert returned.lifecycle == "active" and returned.stale_reason is None
    assert returned.targets == repository_inventory.targets
    assert all(p.read_bytes() == content for p, content in artifacts.items())
    assert backend.aclose.await_count == 3
