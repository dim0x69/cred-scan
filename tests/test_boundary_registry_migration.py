"""Offline phase migration preserves historical results and source artifacts."""

import json
from urllib.parse import quote

import pytest

from cred_scan.backend.models import BoundaryRecord, ScanTargetInventory
from cred_scan.scan.models import CredentialsDocument, TitusReport
from cred_scan.tools.migrate_workspace_schema import migrate_workspace


def legacy_workspace(tmp_path, inventory):
    backend = tmp_path / "artifactory_docker"
    backend.mkdir()
    (backend / "backend.json").write_text(
        json.dumps({"schema_version": 1, "name": backend.name})
    )
    path = backend / "boundaries" / quote(inventory.boundary.id, safe="")
    path.mkdir(parents=True)
    (path / "boundary.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "backend_id": backend.name,
                "boundary": inventory.boundary.model_dump(mode="json"),
                "availability": "available",
            }
        )
    )
    old = inventory.model_dump(mode="json")
    old.update(schema_version=11, publication_pending=False)
    old["targets"][0]["result"].update(
        status="partial", retryable=False, errors=["warning"]
    )
    (path / "scantargets.json").write_text(json.dumps(old))
    (path / "report.json").write_text(
        json.dumps(
            {
                "schema_version": 2,
                "boundary_id": inventory.boundary.id,
                "generated_at": "now",
                "incomplete": True,
                "errors": ["report error"],
                "findings": [{"secret": "synthetic"}],
            }
        )
    )
    credentials = {}
    for index, verdict in enumerate(
        ["VALID", "INVALID", "UNKNOWN", "ERROR", "PENDING"]
    ):
        credentials[str(index)] = {
            "credential_id": str(index),
            "credential": "synthetic",
            "occurrences": [{"locator": "immutable:source"}],
            "judgment": {"verdict": verdict, "reasoning": "diagnostic"},
            "extraction": (
                {
                    "status": "RETAINED",
                    "output_path": "evidence/file",
                    "size": 8,
                    "sha256": "legacy-hash",
                }
                if index == 0
                else {"status": "ERROR", "error": "read failure"}
                if index == 2
                else None
            ),
        }
    (path / "credentials.json").write_text(
        json.dumps(
            {
                "schema_version": 8,
                "boundary_id": inventory.boundary.id,
                "report_generated_at": "now",
                "incomplete": True,
                "errors": ["conversion error"],
                "credentials": credentials,
            }
        )
    )
    (path / "titus.ds").write_bytes(b"cumulative datastore")
    (path / "evidence").mkdir()
    (path / "evidence" / "file").write_bytes(b"retained")
    return path


def test_migration_preserves_history_and_backs_up_all_documents(
    tmp_path, repository_inventory
):
    path = legacy_workspace(tmp_path, repository_inventory)
    originals = {p: p.read_bytes() for p in path.rglob("*") if p.is_file()}
    assert migrate_workspace(tmp_path) == 1
    assert {p: p.read_bytes() for p in originals} == originals
    assert migrate_workspace(tmp_path, apply=True) == 1
    record = BoundaryRecord.model_validate_json((path / "boundary.json").read_text())
    assert record.phase == "judge"
    inventory = ScanTargetInventory.model_validate_json(
        (path / "scantargets.json").read_text()
    )
    assert inventory.targets[0].result.status == "failed"
    assert inventory.targets[0].result.errors == ("warning",)
    assert "retryable" not in inventory.targets[0].result.model_dump()
    assert "publication_pending" not in inventory.model_dump()
    report = TitusReport.model_validate_json((path / "report.json").read_text())
    assert report.findings == ({"secret": "synthetic"},)
    assert report.errors == ("report error",)
    credentials = CredentialsDocument.model_validate_json(
        (path / "credentials.json").read_text()
    )
    assert credentials.errors == ("conversion error",)
    assert "incomplete" not in credentials.model_dump()
    assert [c.judgment.status for c in credentials.credentials.values()] == [
        "completed",
        "completed",
        "completed",
        "failed",
        "pending",
    ]
    assert credentials.credentials["3"].judgment.error == "diagnostic"
    assert credentials.credentials["3"].judgment.reasoning == ""
    assert [c.extraction.status for c in credentials.credentials.values()] == [
        "retained",
        "pending",
        "failed",
        "pending",
        "pending",
    ]
    for source, original in originals.items():
        if source.suffix == ".json":
            backup = tmp_path / ".phase-migration-backup" / source.relative_to(tmp_path)
            assert backup.read_bytes() == original
        else:
            assert source.read_bytes() == original
    assert migrate_workspace(tmp_path, apply=True) == 0


@pytest.mark.parametrize(
    "case,phase",
    [
        ("publication", "scan"),
        ("running", "scan"),
        ("pending", "scan"),
        ("unpublished", "scan"),
        ("null_extraction", "extract"),
        ("finished", "done"),
        ("absent", "scan"),
    ],
)
def test_initial_phase(tmp_path, repository_inventory, case, phase):
    path = legacy_workspace(tmp_path, repository_inventory)
    if case in {"publication", "running", "pending"}:
        data = json.loads((path / "scantargets.json").read_text())
        if case == "publication":
            data["publication_pending"] = True
        else:
            data["targets"][0]["result"]["status"] = case
        (path / "scantargets.json").write_text(json.dumps(data))
    elif case == "unpublished":
        (path / "report.json").unlink()
        (path / "credentials.json").unlink()
    elif case in {"null_extraction", "finished"}:
        data = json.loads((path / "credentials.json").read_text())
        data["credentials"] = (
            {"1": data["credentials"]["1"]}
            if case == "null_extraction"
            else {"0": data["credentials"]["0"]}
        )
        (path / "credentials.json").write_text(json.dumps(data))
    elif case == "absent":
        data = json.loads((path / "boundary.json").read_text())
        data["availability"] = "absent"
        (path / "boundary.json").write_text(json.dumps(data))
        (path / "scantargets.json").unlink()
    migrate_workspace(tmp_path, apply=True)
    assert (
        BoundaryRecord.model_validate_json((path / "boundary.json").read_text()).phase
        == phase
    )


def test_ambiguous_publication_requires_explicit_phase(tmp_path, repository_inventory):
    path = legacy_workspace(tmp_path, repository_inventory)
    data = json.loads((path / "report.json").read_text())
    data["generated_at"] = "newer"
    (path / "report.json").write_text(json.dumps(data))
    original = (path / "boundary.json").read_bytes()
    with pytest.raises(ValueError, match="ambiguous publication"):
        migrate_workspace(tmp_path, apply=True)
    assert (path / "boundary.json").read_bytes() == original
    migrate_workspace(
        tmp_path, apply=True, phases={repository_inventory.boundary.id: "scan"}
    )
    assert (
        BoundaryRecord.model_validate_json((path / "boundary.json").read_text()).phase
        == "scan"
    )


def test_invalid_retained_metadata_rejects_migration_before_writes(
    tmp_path, repository_inventory
):
    path = legacy_workspace(tmp_path, repository_inventory)
    data = json.loads((path / "credentials.json").read_text())
    del data["credentials"]["0"]["extraction"]["size"]
    (path / "credentials.json").write_text(json.dumps(data))
    originals = {p: p.read_bytes() for p in path.rglob("*") if p.is_file()}
    with pytest.raises(ValueError, match="invalid CredentialsDocument"):
        migrate_workspace(tmp_path, apply=True)
    assert {p: p.read_bytes() for p in originals} == originals
    assert not (tmp_path / ".phase-migration-backup").exists()


def test_override_cannot_hide_pending_extraction(tmp_path, repository_inventory):
    path = legacy_workspace(tmp_path, repository_inventory)
    data = json.loads((path / "credentials.json").read_text())
    data["credentials"] = {"1": data["credentials"]["1"]}
    (path / "credentials.json").write_text(json.dumps(data))
    with pytest.raises(ValueError, match="bypasses pending work"):
        migrate_workspace(
            tmp_path, apply=True, phases={repository_inventory.boundary.id: "done"}
        )
    assert json.loads((path / "boundary.json").read_text())["schema_version"] == 1
