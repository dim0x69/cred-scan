"""Inventory 8/9 -> 10 preserves history and requests one publication pass."""

import json
from datetime import UTC, datetime
from urllib.parse import quote

import pytest

from cred_scan.backend.adapters.artifactory.docker import DockerImageScanScope
from cred_scan.backend.adapters.artifactory.models import ArtifactoryRepository
from cred_scan.backend.models import ScanTargetInventory, ScanTarget, target_id_for
from cred_scan.scan.models import Credential, CredentialOccurrence, CredentialsDocument, TitusReport
from cred_scan.tools.migrate_workspace_schema import migrate_workspace


def test_latest_inventory_migration_preserves_history_and_ids(tmp_path):
    repository = ArtifactoryRepository(id="artifactory:primary:repo", name="repo")
    scope = DockerImageScanScope(
        image="registry/repo/image", digest="sha256:current", root_digest="sha256:root",
        platform="linux/amd64", manifest_timestamp=datetime(2026, 1, 1, tzinfo=UTC),
    )
    selected = ScanTarget(
        id=target_id_for(scope), backend_id="primary", boundary=repository, scope=scope,
    )
    selected.result.status = "scanned"
    inventory = ScanTargetInventory(
        generated_at=datetime(2026, 1, 1, tzinfo=UTC), boundary=repository,
        targets=(selected,),
    )
    legacy = inventory.model_dump(mode="json")
    legacy["schema_version"] = 8
    current = legacy["targets"][0]
    current["lifecycle"] = "current"
    current["scope"]["lifecycle"] = "active"
    current["scope"]["pin_id"] = current["scope"].pop("version_id")
    old = json.loads(json.dumps(current))
    old["id"] = "historical-target"
    old["lifecycle"] = "superseded"
    stale = json.loads(json.dumps(current))
    stale["id"] = "absent-scope-target"
    stale["scope"]["lifecycle"] = "stale"
    legacy["targets"] = [old, current, stale]
    boundary_dir = tmp_path / quote(repository.id, safe="")
    boundary_dir.mkdir()
    path = boundary_dir / "inventory.json"
    path.write_text(json.dumps(legacy))
    original = path.read_bytes()
    document = CredentialsDocument(
        boundary_id=repository.id, report_generated_at="old",
        credentials={"old": Credential(
            credential_id="old", occurrences=(CredentialOccurrence(locator="historical-source"),),
            judgment={"verdict": "VALID"}, extraction={"status": "RETAINED", "output_path": "evidence/old/app.env"},
        )},
    )
    (boundary_dir / "credentials.json").write_text(document.model_dump_json())
    (boundary_dir / "report.json").write_text(TitusReport(boundary_id=repository.id, generated_at="old").model_dump_json())
    (boundary_dir / "titus.ds").write_bytes(b"cumulative Titus history")
    evidence = boundary_dir / "evidence/old/app.env"
    evidence.parent.mkdir(parents=True)
    evidence.write_bytes(b"historical evidence")
    preserved = {p: p.read_bytes() for p in boundary_dir.rglob("*") if p.is_file() and p != path}

    assert migrate_workspace(tmp_path) == 1
    assert path.read_bytes() == original
    assert migrate_workspace(tmp_path, apply=True) == 1
    migrated = ScanTargetInventory.model_validate_json(path.read_text())
    assert migrated == inventory.model_copy(update={"publication_pending": True})
    assert migrated.targets[0].id == selected.id
    assert "pin_id" not in migrated.model_dump_json()
    backup = tmp_path / ".inventory-v8-backup" / boundary_dir.name / "inventory.json"
    assert backup.read_bytes() == original
    assert all(p.read_bytes() == content for p, content in preserved.items())
    assert migrate_workspace(tmp_path, apply=True) == 0


def test_schema_9_without_datastore_does_not_request_publication(tmp_path):
    repository = ArtifactoryRepository(id="artifactory:primary:repo", name="repo")
    inventory = ScanTargetInventory(
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
        boundary=repository,
    )
    payload = inventory.model_dump(mode="json")
    payload["schema_version"] = 9
    payload.pop("publication_pending")
    boundary_dir = tmp_path / quote(repository.id, safe="")
    boundary_dir.mkdir()
    (boundary_dir / "inventory.json").write_text(json.dumps(payload))

    assert migrate_workspace(tmp_path, apply=True) == 1
    migrated = ScanTargetInventory.model_validate_json(
        (boundary_dir / "inventory.json").read_text()
    )
    assert not migrated.publication_pending
    assert (boundary_dir / ".operation.lock").is_file()


def test_migration_requires_existing_workspace(tmp_path):
    with pytest.raises(ValueError, match="does not exist"):
        migrate_workspace(tmp_path / "absent", apply=True)
