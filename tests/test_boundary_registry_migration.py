"""Legacy inventory files migrate without touching historical boundary data."""

import json
from datetime import UTC, datetime

from cred_scan.backend.adapters.artifactory.docker import DockerImageScanScope
from cred_scan.backend.adapters.artifactory.models import ArtifactoryRepository
from cred_scan.backend.models import (
    BoundaryRecord,
    ScanTarget,
    ScanTargetInventory,
    target_id_for,
)
from cred_scan.tools.migrate_workspace_schema import migrate_workspace


def test_migrates_inventory_to_boundary_record_and_scan_targets(tmp_path):
    boundary = ArtifactoryRepository(
        id="artifactory:artifactory_docker:repo",
        name="repo",
    )
    scope = DockerImageScanScope(
        image="artifactory.example/repo/image",
        digest="sha256:manifest",
        root_digest="sha256:root",
        platform="linux/amd64",
        manifest_timestamp=datetime(2026, 1, 1, tzinfo=UTC),
    )
    document = ScanTargetInventory(
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
        boundary=boundary,
        targets=(ScanTarget(id=target_id_for(scope), scope=scope),),
    )
    tmp_path.joinpath("backend.json").write_text(
        json.dumps({"name": "artifactory_docker"})
    )
    boundary_path = tmp_path / "artifactory%3Aartifactory_docker%3Arepo"
    boundary_path.mkdir()
    legacy = boundary_path / "inventory.json"
    legacy_payload = document.model_dump(mode="json")
    legacy_payload["schema_version"] = 10
    legacy_payload["lifecycle"] = "active"
    legacy_payload["stale_reason"] = None
    legacy_payload["targets"][0]["backend_id"] = "artifactory_docker"
    legacy_payload["targets"][0]["boundary"] = boundary.model_dump(mode="json")
    legacy.write_text(json.dumps(legacy_payload))
    datastore = boundary_path / "titus.ds"
    datastore.write_bytes(b"historical datastore")
    evidence = boundary_path / "evidence" / "credential" / "app.env"
    evidence.parent.mkdir(parents=True)
    evidence.write_bytes(b"historical evidence")

    assert migrate_workspace(tmp_path) == 1
    assert legacy.is_file()
    assert not (boundary_path / "boundary.json").exists()

    assert migrate_workspace(tmp_path, apply=True) == 1

    assert not legacy.exists()
    restored = ScanTargetInventory.model_validate_json(
        (boundary_path / "scantargets.json").read_text()
    )
    stored_target = restored.model_dump(mode="json")["targets"][0]
    assert "backend_id" not in stored_target
    assert "boundary" not in stored_target
    record = BoundaryRecord.model_validate_json(
        (boundary_path / "boundary.json").read_text()
    )
    assert restored == document
    assert record.backend_id == "artifactory_docker"
    assert record.boundary == boundary
    assert record.availability == "available"
    backup = (
        tmp_path
        / ".inventory-v10-backup"
        / boundary_path.name
        / "inventory.json"
    )
    assert json.loads(backup.read_text()) == legacy_payload
    assert datastore.read_bytes() == b"historical datastore"
    assert evidence.read_bytes() == b"historical evidence"
    assert migrate_workspace(tmp_path) == 0
