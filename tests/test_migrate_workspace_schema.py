import copy
import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from cred_scan.backend.models import ScanBoundaryInventory
from cred_scan.scan.models import CredentialsDocument
from cred_scan.tools.migrate_workspace_schema import migrate_workspace


def _inventory(repository_inventory: ScanBoundaryInventory) -> dict:
    return repository_inventory.model_dump(mode="json")


def _old_credentials(inventory: ScanBoundaryInventory, version: int = 5) -> dict:
    target = inventory.targets[0]
    locator = (
        "docker://registry/docker-local/team/api@sha256:manifest/"
        "sha256:layer:etc/app.env"
    )
    payload = {
        "schema_version": version,
        "boundary_id": inventory.boundary.id,
        "report_generated_at": "now",
        "credentials": {
            "credential": {
                "credential_id": "credential",
                "credential": "SECRET",
                "occurrences": [
                    {
                        "target_id": target.id,
                        "locations": [
                            {
                                "provenance": {
                                    "kind": "docker-layer",
                                    "raw_path": locator,
                                    "registry": "registry",
                                    "repository": "docker-local",
                                    "image": "team/api",
                                    "manifest": "sha256:manifest",
                                    "layer": "sha256:layer",
                                    "path": "etc/app.env",
                                },
                                "source_path": "etc/app.env",
                                "filename": "app.env",
                            }
                        ],
                        "finding_ids": ["finding"],
                    }
                ],
                "judgment": {"verdict": "PENDING", "reasoning": ""},
                "extraction": None,
            }
        },
        "errors": [],
    }
    if version == 6:
        location = payload["credentials"]["credential"]["occurrences"][0]["locations"][0]
        location["locator"] = location.pop("provenance")["raw_path"]
        location["target_id"] = target.id
    return payload


@pytest.mark.parametrize("version", [5, 6])
def test_workspace_migration_converts_typed_provenance(
    tmp_path: Path, repository_inventory, version
) -> None:
    boundary = tmp_path / "boundary"
    boundary.mkdir()
    (boundary / "inventory.json").write_text(
        json.dumps(_inventory(repository_inventory)), encoding="utf-8"
    )
    (boundary / "report.json").write_text(
        json.dumps(
            {
                "schema_version": 2,
                "boundary_id": repository_inventory.boundary.id,
                "generated_at": "now",
                "findings": [],
            }
        ),
        encoding="utf-8",
    )
    credentials = boundary / "credentials.json"
    credentials.write_text(json.dumps(_old_credentials(repository_inventory, version)))

    assert migrate_workspace(tmp_path) == 1
    assert json.loads(credentials.read_text())["schema_version"] == version
    assert migrate_workspace(tmp_path, apply=True) == 1
    migrated = json.loads(credentials.read_text())
    occurrence = migrated["credentials"]["credential"]["occurrences"][0]
    assert migrated["schema_version"] == 8
    assert occurrence["locator"].startswith("docker://")
    assert "target_id" not in occurrence
    assert "locations" not in occurrence
    assert "provenance" not in occurrence
    assert ScanBoundaryInventory.model_validate(_inventory(repository_inventory))


def test_workspace_migration_rejects_unmatched_report_locator(
    tmp_path: Path, repository_inventory
) -> None:
    boundary = tmp_path / "boundary"
    boundary.mkdir()
    (boundary / "inventory.json").write_text(
        json.dumps(_inventory(repository_inventory)), encoding="utf-8"
    )
    (boundary / "report.json").write_text(
        json.dumps(
            {
                "schema_version": 2,
                "boundary_id": repository_inventory.boundary.id,
                "generated_at": "now",
                "findings": [
                    {
                        "Matches": [
                            {
                                "file_path": (
                                    "docker://registry/docker-local/team/api@"
                                    "sha256:missing/sha256:layer:etc/app.env"
                                )
                            }
                        ]
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="does not identify exactly one"):
        migrate_workspace(tmp_path)


def _seed_boundary(root, name, inventory, credentials=None):
    boundary = root / name
    boundary.mkdir()
    (boundary / "inventory.json").write_text(inventory.model_dump_json())
    (boundary / "report.json").write_text(json.dumps({
        "schema_version": 2,
        "boundary_id": inventory.boundary.id,
        "generated_at": "now",
        "findings": [],
    }))
    if credentials is not None:
        (boundary / "credentials.json").write_text(json.dumps(credentials))
    return boundary


def test_migration_allows_inventory_only_boundary(tmp_path, repository_inventory):
    scanned = _seed_boundary(
        tmp_path, "a-scanned", repository_inventory,
        _old_credentials(repository_inventory),
    )
    new = _seed_boundary(tmp_path, "z-new", repository_inventory)
    (new / "report.json").unlink()
    inventory_bytes = (new / "inventory.json").read_bytes()

    assert migrate_workspace(tmp_path) == 1
    assert migrate_workspace(tmp_path, apply=True) == 1
    assert migrate_workspace(tmp_path) == 0
    assert json.loads((scanned / "credentials.json").read_text())["schema_version"] == 8
    assert (new / "inventory.json").read_bytes() == inventory_bytes
    assert sorted(path.name for path in new.iterdir()) == ["inventory.json"]


@pytest.mark.parametrize("artifact", ["credentials.json", "titus.ds", "evidence"])
def test_missing_report_for_results_prevents_all_writes(
    tmp_path, repository_inventory, artifact
):
    scanned = _seed_boundary(
        tmp_path, "a-valid", repository_inventory,
        _old_credentials(repository_inventory),
    )
    broken = _seed_boundary(tmp_path, "z-broken", repository_inventory)
    (broken / "report.json").unlink()
    if artifact == "credentials.json":
        (broken / artifact).write_text(json.dumps(_old_credentials(repository_inventory)))
    else:
        (broken / artifact).mkdir()
    original = (scanned / "credentials.json").read_bytes()

    with pytest.raises(ValueError, match="missing report for existing scan results"):
        migrate_workspace(tmp_path, apply=True)
    assert (scanned / "credentials.json").read_bytes() == original


def test_present_report_is_validated_without_credentials(tmp_path, repository_inventory):
    boundary = _seed_boundary(tmp_path, "boundary", repository_inventory)
    (boundary / "report.json").write_text("not JSON")
    with pytest.raises(ValueError, match="invalid JSON"):
        migrate_workspace(tmp_path, apply=True)


@pytest.mark.parametrize("version", [5, 6])
@pytest.mark.parametrize("status", ["RETAINED", "ERROR"])
@pytest.mark.parametrize("append_observations", [False, True])
def test_migration_removes_fingerprint_preserving_evidence_and_history(
    tmp_path, repository_inventory, version, status, append_observations
):
    original = _old_credentials(repository_inventory, version)
    candidate = original["credentials"]["credential"]
    evidence_bytes = b"historical evidence"
    evidence_relative = "evidence/credential/app.env"
    extraction = {
        "status": status,
        "source_fingerprint": "obsolete-source-fingerprint",
        "output_path": evidence_relative if status == "RETAINED" else None,
        "size": len(evidence_bytes) if status == "RETAINED" else None,
        "sha256": hashlib.sha256(evidence_bytes).hexdigest() if status == "RETAINED" else None,
        "error": "temporary failure" if status == "ERROR" else None,
    }
    candidate["extraction"] = extraction
    candidate["judgment"] = {"verdict": "VALID", "reasoning": "historical judgment"}
    if append_observations:
        later = copy.deepcopy(candidate["occurrences"][0]["locations"][0])
        if version == 5:
            later["provenance"]["raw_path"] = later["provenance"]["raw_path"].replace(
                "app.env", "later.env"
            )
            later["provenance"]["path"] = "etc/later.env"
        else:
            later["locator"] = later["locator"].replace("app.env", "later.env")
        later["source_path"] = "etc/later.env"
        later["filename"] = "later.env"
        candidate["occurrences"][0]["locations"].append(later)

    boundary = _seed_boundary(tmp_path, "boundary", repository_inventory, original)
    evidence = boundary / evidence_relative
    evidence.parent.mkdir(parents=True)
    evidence.write_bytes(evidence_bytes)
    datastore = boundary / "titus.ds"
    datastore.mkdir()
    (datastore / "sentinel").write_bytes(b"untouched datastore")
    unchanged = {
        path: path.read_bytes()
        for path in boundary.rglob("*")
        if path.is_file() and path.name != "credentials.json"
    }
    credentials_path = boundary / "credentials.json"
    before = credentials_path.read_bytes()
    assert migrate_workspace(tmp_path) == 1
    assert credentials_path.read_bytes() == before
    assert migrate_workspace(tmp_path, apply=True) == 1
    migrated = CredentialsDocument.model_validate_json(credentials_path.read_text())
    saved = migrated.credentials["credential"]
    assert migrated.schema_version == 8
    assert saved.extraction.model_dump(mode="json") == {
        key: value for key, value in extraction.items() if key != "source_fingerprint"
    }
    assert saved.judgment.model_dump(mode="json") == candidate["judgment"]
    assert saved.credential == candidate["credential"]
    assert len(saved.occurrences) == (2 if append_observations else 1)
    assert all(path.read_bytes() == content for path, content in unchanged.items())
    after = credentials_path.read_bytes()
    assert migrate_workspace(tmp_path, apply=True) == 0
    assert credentials_path.read_bytes() == after


@pytest.mark.parametrize("version", [5, 6])
def test_runtime_rejects_unmigrated_credentials(repository_inventory, version):
    with pytest.raises(ValidationError, match="schema_version"):
        CredentialsDocument.model_validate(_old_credentials(repository_inventory, version))


def test_migration_handles_mixed_versions_without_rewriting_current(
    tmp_path, repository_inventory
):
    for version in (5, 6, 7):
        payload = _old_credentials(repository_inventory, min(version, 6))
        payload["schema_version"] = version
        _seed_boundary(tmp_path, f"schema-{version}", repository_inventory, payload)
    current = tmp_path / "schema-7" / "credentials.json"
    unchanged = current.read_bytes()
    assert migrate_workspace(tmp_path) == 3
    assert migrate_workspace(tmp_path, apply=True) == 3
    assert current.read_bytes() != unchanged
    assert migrate_workspace(tmp_path, apply=True) == 0
    for path in tmp_path.rglob("credentials.json"):
        assert CredentialsDocument.model_validate_json(path.read_text()).schema_version == 8


def test_current_schema_with_removed_field_fails_before_any_writes(
    tmp_path, repository_inventory
):
    valid = _seed_boundary(
        tmp_path, "a-valid", repository_inventory, _old_credentials(repository_inventory, 6)
    )
    invalid = _old_credentials(repository_inventory, 6)
    invalid["schema_version"] = 8
    invalid["credentials"]["credential"]["extraction"] = {
        "status": "ERROR", "error": "failure", "source_fingerprint": "obsolete"
    }
    broken = _seed_boundary(tmp_path, "z-invalid", repository_inventory, invalid)
    before = {p: p.read_bytes() for p in [valid / "credentials.json", broken / "credentials.json"]}
    with pytest.raises(ValueError, match="invalid CredentialsDocument"):
        migrate_workspace(tmp_path, apply=True)
    assert all(path.read_bytes() == content for path, content in before.items())
