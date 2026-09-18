"""Operator-only current-format upgrade; no historical-schema compatibility."""

import json

import pytest
from pydantic import ValidationError

from cred_scan.backend.models import ScanBoundaryInventory
from cred_scan.common.models import WorkspaceConfig
from cred_scan.common.workspace import WorkspaceBusyError
from cred_scan.orch.workspace import Workspace
from cred_scan.orch.execution import BoundaryExecution, Phase, PhaseStatus
from cred_scan.scan.models import (
    CredentialsDocument,
    ExtractionResult,
    JudgmentResult,
    TitusReport,
)
from cred_scan.tools.migrate_workspace_schema import migrate_workspace


def seed(tmp_path, inventory, document=None, *, name=None):
    if name is not None:
        boundary = inventory.boundary.model_copy(update={"id": name})
        inventory = inventory.model_copy(
            update={
                "boundary": boundary,
                "targets": tuple(
                    t.model_copy(update={"boundary": boundary})
                    for t in inventory.targets
                ),
            }
        )
        if document is not None:
            document = document.model_copy(update={"boundary_id": name})
    store = Workspace(WorkspaceConfig(workspace_dir=tmp_path))
    paths = store.boundary(inventory.boundary.id)
    paths.boundary_dir.mkdir(parents=True, exist_ok=True)
    payload = inventory.model_dump(mode="json")
    payload["schema_version"] = 7
    paths.inventory.write_text(json.dumps(payload))
    if document is not None:
        store.write(
            paths.report,
            TitusReport(
                boundary_id=inventory.boundary.id,
                generated_at=document.report_generated_at,
            ),
            TitusReport,
        )
        store.write(paths.credentials, document, CredentialsDocument)
    return store, paths


def snapshot(root):
    return {
        p.relative_to(root): p.read_bytes()
        for p in root.rglob("*")
        if p.is_file() and p.name != ".operation.lock"
    }


def test_inventory_only_upgrade_dry_run_and_apply(tmp_path, repository_inventory):
    store, paths = seed(tmp_path, repository_inventory)
    before = snapshot(tmp_path)
    assert migrate_workspace(tmp_path) == 1
    assert snapshot(tmp_path) == before
    assert migrate_workspace(tmp_path, apply=True) == 1
    inventory = store.read(paths.inventory, ScanBoundaryInventory)
    assert inventory == repository_inventory
    state = store.read(paths.execution, BoundaryExecution)
    assert state.scan == PhaseStatus.READY
    assert not state.scan_publication_pending
    after = snapshot(tmp_path)
    assert migrate_workspace(tmp_path, apply=True) == 0
    assert snapshot(tmp_path) == after


def test_results_and_history_survive_with_conservative_publication(
    tmp_path, repository_inventory, credential
):
    repository_inventory.targets[0].result.status = "scanned"
    repository_inventory.targets[0].lifecycle = "superseded"
    repository_inventory.lifecycle = "stale"
    valid = credential.model_copy(
        update={
            "credential_id": "retained",
            "judgment": JudgmentResult(verdict="VALID"),
            "extraction": ExtractionResult(
                status="RETAINED",
                output_path="evidence/retained/app.env",
                size=999,
                sha256="not-audit-input",
            ),
        }
    )
    missing = credential.model_copy(
        update={"credential_id": "missing", "judgment": JudgmentResult(verdict="VALID")}
    )
    credential.judgment = JudgmentResult(verdict="ERROR")
    document = CredentialsDocument(
        boundary_id=repository_inventory.boundary.id,
        report_generated_at="old",
        credentials={c.credential_id: c for c in (credential, valid, missing)},
    )
    store, paths = seed(tmp_path, repository_inventory, document)
    paths.datastore.mkdir()
    (paths.datastore / "opaque.db").write_bytes(b"datastore bytes")
    evidence = paths.boundary_dir / valid.extraction.output_path
    evidence.parent.mkdir(parents=True)
    evidence.write_bytes(b"do not audit or modify")
    before = snapshot(tmp_path)
    assert migrate_workspace(tmp_path, apply=True) == 1
    for path, content in before.items():
        if path != paths.inventory.relative_to(tmp_path):
            assert (tmp_path / path).read_bytes() == content
    assert store.read(paths.inventory, ScanBoundaryInventory) == repository_inventory
    state = store.read(paths.execution, BoundaryExecution)
    assert state.scan_publication_pending
    assert [state.status(p) for p in Phase] == [PhaseStatus.READY] * 3


@pytest.mark.parametrize(
    "defect",
    [
        "inventory-version",
        "credential-version",
        "report-version",
        "boundary",
        "pin",
        "corrupt",
    ],
)
@pytest.mark.parametrize("apply", [False, True])
def test_preflight_all_boundaries_before_writing(
    tmp_path, repository_inventory, credential, defect, apply
):
    document = CredentialsDocument(
        boundary_id=repository_inventory.boundary.id,
        report_generated_at="old",
        credentials={credential.credential_id: credential},
    )
    seed(tmp_path, repository_inventory, document, name="a")
    _, paths = seed(tmp_path, repository_inventory, document, name="z")
    if defect == "corrupt":
        paths.credentials.write_text("{")
    else:
        path = (
            paths.inventory
            if defect in {"inventory-version", "pin"}
            else paths.report
            if defect == "report-version"
            else paths.credentials
        )
        payload = json.loads(path.read_text())
        if defect.endswith("version"):
            payload["schema_version"] = 0
        elif defect == "boundary":
            payload["boundary_id"] = "wrong"
        else:
            payload["targets"][0]["id"] = "noncanonical"
        path.write_text(json.dumps(payload))
    before = snapshot(tmp_path)
    with pytest.raises((ValueError, ValidationError)):
        migrate_workspace(tmp_path, apply=apply)
    assert snapshot(tmp_path) == before


@pytest.mark.parametrize("failure_path", ["execution.json", "inventory.json"])
def test_interrupted_upgrade_resumes_without_rewriting_completed_boundaries(
    tmp_path, repository_inventory, monkeypatch, failure_path
):
    _, first = seed(tmp_path, repository_inventory, name="a")
    _, second = seed(tmp_path, repository_inventory, name="b")
    write = Workspace.write

    def fail(self, path, document, model):
        if path == second.boundary_dir / failure_path:
            raise OSError("interrupted")
        return write(self, path, document, model)

    with monkeypatch.context() as patch:
        patch.setattr(Workspace, "write", fail)
        with pytest.raises(OSError):
            migrate_workspace(tmp_path, apply=True)
    assert json.loads(first.inventory.read_text())["schema_version"] == 8
    assert json.loads(second.inventory.read_text())["schema_version"] == 7
    completed = (first.inventory.read_bytes(), first.execution.read_bytes())
    assert migrate_workspace(tmp_path, apply=True) == 1
    assert (first.inventory.read_bytes(), first.execution.read_bytes()) == completed
    assert migrate_workspace(tmp_path) == 0


def test_upgrade_requires_operation_lock(tmp_path, repository_inventory):
    store, _ = seed(tmp_path, repository_inventory)
    with store.operation_lock():
        with pytest.raises(WorkspaceBusyError):
            migrate_workspace(tmp_path, apply=True)


def test_runtime_rejects_old_inventory_without_defaulting(repository_inventory):
    payload = repository_inventory.model_dump(mode="json")
    payload["schema_version"] = 7
    with pytest.raises(ValidationError, match="schema_version"):
        ScanBoundaryInventory.model_validate(payload)


def test_upgraded_inventory_requires_valid_execution(tmp_path, repository_inventory):
    _, paths = seed(tmp_path, repository_inventory)
    assert migrate_workspace(tmp_path, apply=True) == 1
    paths.execution.unlink()
    with pytest.raises(ValueError, match="missing execution"):
        migrate_workspace(tmp_path)


def test_migration_requires_existing_workspace(tmp_path):
    with pytest.raises(ValueError, match="does not exist"):
        migrate_workspace(tmp_path / "absent")


def test_migration_validation_error_does_not_print_credential_values(
    tmp_path, repository_inventory, credential
):
    document = CredentialsDocument(
        boundary_id=repository_inventory.boundary.id,
        report_generated_at="old",
        credentials={credential.credential_id: credential},
    )
    _, paths = seed(tmp_path, repository_inventory, document)
    payload = json.loads(paths.credentials.read_text())
    payload["credentials"][credential.credential_id]["judgment"]["verdict"] = (
        "unsupported"
    )
    paths.credentials.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match="invalid CredentialsDocument") as caught:
        migrate_workspace(tmp_path, apply=True)
    assert credential.credential not in str(caught.value)
    assert not paths.execution.exists()
