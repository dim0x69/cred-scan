"""The boundary/scope distinction and its persisted field contract."""

from datetime import UTC, datetime
from urllib.parse import quote

import pytest
from pydantic import ValidationError

from cred_scan.backend.models import (
    ArtifactoryRepository,
    BackendConfig,
    DockerImageScanScope,
    GitOrganization,
    GitRepositoryScanScope,
    PackageScanScope,
    ScanBoundary,
    ScanBoundaryInventory,
    ScanScope,
    ScanTarget,
    target_id_for,
)
from cred_scan.common.models import WorkspaceConfig
from cred_scan.orch.workspace import Workspace
from cred_scan.scan.models import CredentialsDocument, TitusReport


@pytest.mark.parametrize("kind", ["docker", "git", "package"])
def test_boundary_contains_logical_scopes_and_immutable_target_pins(kind):
    now = datetime(2026, 1, 1, tzinfo=UTC)
    if kind == "git":
        boundary = GitOrganization(id="git:primary:team", name="team")
        scope = GitRepositoryScanScope(
            remote="https://git.example/team/api.git",
            commit="abc123",
            commit_timestamp=now,
        )
    else:
        boundary = ArtifactoryRepository(id="artifactory:primary:local", name="local")
        scope = (
            DockerImageScanScope(
                image="registry/local/api",
                digest="sha256:manifest",
                root_digest="sha256:index",
                platform="linux/amd64",
                manifest_timestamp=now,
            )
            if kind == "docker"
            else PackageScanScope(
                name="api",
                uri="https://packages.example/api",
                digest="sha256:artifact",
                ecosystem="npm",
            )
        )
    assert isinstance(boundary, ScanBoundary)
    assert isinstance(scope, ScanScope)
    assert not isinstance(scope, ScanBoundary)
    target = ScanTarget(
        id=target_id_for(scope),
        backend_id="primary",
        boundary=boundary,
        scope=scope,
    )
    inventory = ScanBoundaryInventory(
        generated_at=now,
        backend=BackendConfig(name="primary"),
        boundary=boundary,
        targets=(target,),
    )
    payload = inventory.model_dump(mode="json")
    assert payload["schema_version"] == 8
    assert payload["boundary"] == boundary.model_dump(mode="json")
    assert "scope" not in payload
    stored_target = payload["targets"][0]
    assert stored_target["boundary"] == payload["boundary"]
    assert stored_target["scope"]["kind"] == kind
    assert "source" not in stored_target
    restored = ScanBoundaryInventory.model_validate(payload)
    assert restored == inventory
    assert restored.targets[0].id == f"{scope.id}@{scope.pin_id}"


def test_schema_number_only_does_not_upgrade_old_inventory_fields(repository_inventory):
    payload = repository_inventory.model_dump(mode="json")
    payload["scope"] = payload.pop("boundary")
    target = payload["targets"][0]
    target["source"] = target.pop("scope")
    target["scope"] = target.pop("boundary")
    with pytest.raises(ValidationError):
        ScanBoundaryInventory.model_validate(payload)


@pytest.mark.parametrize("kind", ["report", "credentials"])
def test_documents_use_boundary_id_and_reject_legacy_fields_and_versions(kind):
    document = (
        TitusReport(boundary_id="boundary", generated_at="now")
        if kind == "report"
        else CredentialsDocument(boundary_id="boundary", report_generated_at="now")
    )
    payload = document.model_dump(mode="json")
    assert payload["schema_version"] == (2 if kind == "report" else 8)
    assert payload["boundary_id"] == "boundary"
    assert "scope_id" not in payload
    assert type(document).model_validate(payload) == document
    old_fields = {**payload, "scope_id": payload["boundary_id"]}
    del old_fields["boundary_id"]
    with pytest.raises(ValidationError):
        type(document).model_validate(old_fields)
    with pytest.raises(ValidationError):
        type(document).model_validate(
            {
                **payload,
                "schema_version": 1 if kind == "report" else 3,
            }
        )


def test_workspace_boundary_identifier_and_paths_are_unchanged(
    tmp_path, repository_inventory
):
    boundary_id = repository_inventory.boundary.id
    workspace = Workspace(WorkspaceConfig(workspace_dir=tmp_path))
    boundary = workspace.boundary(boundary_id)
    assert boundary.boundary_id == boundary_id
    assert boundary.boundary_dir == tmp_path / quote(boundary_id, safe="")
    assert boundary.datastore == boundary.boundary_dir / "titus.ds"
    workspace.write(boundary.inventory, repository_inventory, ScanBoundaryInventory)
    assert (
        workspace.read(boundary.inventory, ScanBoundaryInventory)
        == repository_inventory
    )
