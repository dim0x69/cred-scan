"""Real filesystem fault tests; no live workspaces or services."""

import asyncio
import json
import subprocess
import sys
from contextlib import nullcontext
from pathlib import Path
from unittest.mock import Mock

import pytest
from pydantic import ValidationError

from cred_scan.backend.models import ScanBoundaryInventory
from cred_scan.common import workspace as storage
from cred_scan.common.models import WorkspaceConfig
from cred_scan.common.workspace import Workspace, WorkspaceBusyError, scratch_dir
from cred_scan.scan.models import CredentialsDocument, TitusReport


@pytest.mark.parametrize("failure", ["serialize", "fsync", "replace"])
def test_failed_write_preserves_checkpoint(
    tmp_path, repository_inventory, monkeypatch, failure
):
    workspace = Workspace(WorkspaceConfig(workspace_dir=tmp_path))
    path = workspace.boundary(repository_inventory.boundary.id).inventory
    workspace.write(path, repository_inventory, ScanBoundaryInventory)
    original = path.read_bytes()
    failing = Mock(side_effect=OSError("injected write failure"))
    with monkeypatch.context() as patch:
        if failure == "serialize":
            patch.setattr(storage.json, "dump", failing)
        elif failure == "fsync":
            patch.setattr(storage.os, "fsync", failing)
        else:
            patch.setattr(Path, "replace", failing)
        with pytest.raises(OSError, match="injected write failure"):
            workspace.write(
                path,
                repository_inventory.model_copy(update={"errors": ("new",)}),
                ScanBoundaryInventory,
            )
    assert path.read_bytes() == original
    assert not list(path.parent.glob(".*.tmp"))
    reopened = Workspace(WorkspaceConfig(workspace_dir=tmp_path))
    assert reopened.read(path, ScanBoundaryInventory) == repository_inventory
    workspace.write(path, repository_inventory, ScanBoundaryInventory)  # Lock released.


def test_operation_lock_is_shared_and_released_after_exception(tmp_path):
    config = WorkspaceConfig(workspace_dir=tmp_path)
    first, second = Workspace(config), Workspace(config)
    with pytest.raises(RuntimeError, match="interrupted"):
        with first.operation_lock():
            with pytest.raises(WorkspaceBusyError):
                with second.operation_lock():
                    raise AssertionError("overlapping ownership")
            raise RuntimeError("interrupted")
    with second.operation_lock():
        pass


@pytest.mark.parametrize("cancel", [False, True])
def test_scratch_scopes_clean_only_their_own_children(tmp_path, cancel):
    boundary = Workspace(WorkspaceConfig(workspace_dir=tmp_path)).boundary("boundary")

    async def scenario():
        with scratch_dir(boundary.scratch_parent) as outer:
            marker = outer / "keep"
            marker.write_text("owned by another task")
            entered = asyncio.Event()

            async def worker():
                with scratch_dir(boundary.scratch_parent) as inner:
                    assert inner != outer
                    (inner / "temporary").write_text("scratch")
                    entered.set()
                    if cancel:
                        await asyncio.Event().wait()
                    raise RuntimeError("interrupted")

            task = asyncio.create_task(worker())
            await entered.wait()
            if cancel:
                task.cancel()
            with pytest.raises(asyncio.CancelledError if cancel else RuntimeError):
                await task
            assert marker.read_text() == "owned by another task"
            assert list(boundary.scratch_parent.iterdir()) == [outer]
        assert not boundary.scratch_parent.exists()

    asyncio.run(asyncio.wait_for(scenario(), timeout=3))


@pytest.mark.parametrize("kind", ["inventory", "report", "credentials"])
def test_typed_roundtrip_and_invalid_copy_preserve_files(
    tmp_path, repository_inventory, credential, kind
):
    workspace = Workspace(WorkspaceConfig(workspace_dir=tmp_path))
    paths = workspace.boundary(repository_inventory.boundary.id)
    documents = {
        "inventory": repository_inventory,
        "report": TitusReport(boundary_id=paths.boundary_id, generated_at="now"),
        "credentials": CredentialsDocument(
            boundary_id=paths.boundary_id,
            report_generated_at="now",
            credentials={credential.credential_id: credential},
        ),
    }
    document = documents[kind]
    model_type = type(document)
    path = getattr(paths, kind)
    workspace.write(path, document, model_type)
    original = path.read_bytes()
    assert json.loads(original) == document.model_dump(mode="json")
    assert (
        Workspace(WorkspaceConfig(workspace_dir=tmp_path)).read(path, model_type)
        == document
    )
    evidence = paths.boundary_dir / "evidence" / "credential" / "keep.env"
    evidence.parent.mkdir(parents=True)
    evidence.write_bytes(b"historical evidence")
    updates = {
        "inventory": {
            "targets": (
                repository_inventory.targets[0].model_copy(update={"id": "invalid"}),
            )
        },
        "report": {"generated_at": []},
        "credentials": {"credentials": {"wrong-index-key": credential}},
    }
    warning = (
        pytest.warns(UserWarning, match="serializer warnings")
        if kind == "report"
        else nullcontext()
    )
    with warning, pytest.raises(ValidationError):
        workspace.write(path, document.model_copy(update=updates[kind]), model_type)
    assert path.read_bytes() == original
    assert evidence.read_bytes() == b"historical evidence"


@pytest.mark.parametrize("payload", ["not json", "[]", '{"schema_version": 3}'])
def test_only_missing_document_returns_none(tmp_path, payload):
    workspace = Workspace(WorkspaceConfig(workspace_dir=tmp_path))
    path = tmp_path / "credentials.json"
    assert workspace.read(path, CredentialsDocument) is None
    path.write_text(payload)
    with pytest.raises(ValueError):
        workspace.read(path, CredentialsDocument)


def test_wrong_model_is_rejected_before_creating_boundary(tmp_path):
    workspace = Workspace(WorkspaceConfig(workspace_dir=tmp_path))
    paths = workspace.boundary("boundary")
    with pytest.raises(TypeError, match="expected ScanBoundaryInventory"):
        workspace.write(
            paths.inventory,
            TitusReport(boundary_id="boundary", generated_at="now"),
            ScanBoundaryInventory,
        )
    assert not paths.boundary_dir.exists()


def test_paths_are_frozen_io_free_and_inventory_discovery_includes_stale(
    tmp_path, repository_inventory
):
    workspace = Workspace(WorkspaceConfig(workspace_dir=tmp_path))
    paths = workspace.boundary(repository_inventory.boundary.id)
    assert set(type(paths).model_fields) == {"boundary_id", "boundary_dir"}
    assert not paths.boundary_dir.exists()
    assert list(workspace.inventory_boundaries()) == []
    with pytest.raises(ValidationError, match="frozen"):
        setattr(paths, "boundary_id", "other")
    stale = repository_inventory.model_copy(update={"lifecycle": "stale"})
    workspace.write(paths.inventory, stale, ScanBoundaryInventory)
    orphan = workspace.boundary("not-inventoried")
    orphan.boundary_dir.mkdir()
    orphan.credentials.write_text("{}")
    assert list(workspace.inventory_boundaries()) == [paths]


def test_file_is_fsynced_before_atomic_replacement(
    tmp_path, repository_inventory, monkeypatch
):
    workspace = Workspace(WorkspaceConfig(workspace_dir=tmp_path))
    path = workspace.boundary(repository_inventory.boundary.id).inventory
    events = []
    fsync, replace = storage.os.fsync, Path.replace

    def record_fsync(descriptor):
        events.append("fsync")
        return fsync(descriptor)

    def record_replace(temporary, destination):
        assert temporary.parent == destination.parent
        assert not destination.exists()
        assert json.loads(temporary.read_text()) == repository_inventory.model_dump(
            mode="json"
        )
        events.append("replace")
        return replace(temporary, destination)

    monkeypatch.setattr(storage.os, "fsync", record_fsync)
    monkeypatch.setattr(Path, "replace", record_replace)
    workspace.write(path, repository_inventory, ScanBoundaryInventory)
    assert events == ["fsync", "replace"]


def test_operation_lock_excludes_a_separate_process(tmp_path):
    workspace = Workspace(WorkspaceConfig(workspace_dir=tmp_path))
    code = """
import sys
from cred_scan.common.models import WorkspaceConfig
from cred_scan.common.workspace import Workspace, WorkspaceBusyError
try:
    with Workspace(WorkspaceConfig(workspace_dir=sys.argv[1])).operation_lock():
        print('acquired')
except WorkspaceBusyError:
    print('busy')
"""

    def child():
        return subprocess.run(
            [sys.executable, "-B", "-c", code, str(tmp_path)],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout.strip()

    with workspace.operation_lock():
        assert child() == "busy"
    assert child() == "acquired"
