"""Boundary ownership and interrupted publication recovery regressions."""

import asyncio
import subprocess
import sys
from datetime import UTC, datetime
from unittest.mock import AsyncMock, Mock
from urllib.parse import quote

import pytest

from cred_scan.backend.adapters.artifactory.models import ArtifactoryRepository
from cred_scan.backend.models import ScanTargetInventory
from cred_scan.orch import boundary as boundary_module
from cred_scan.orch.boundary import Boundary
from cred_scan.orch.locking import BoundaryBusyError, boundary_lock
from cred_scan.scan.models import (
    Credential,
    CredentialOccurrence,
    CredentialsDocument,
    JudgmentResult,
    TitusReport,
)


def make_boundary(tmp_path, monkeypatch, *, publication_pending=False):
    reference = ArtifactoryRepository(id="artifactory:primary:repo", name="repo")
    inventory = ScanTargetInventory(
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
        boundary=reference,
        publication_pending=publication_pending,
    )
    path = tmp_path / quote(reference.id, safe="")
    path.mkdir()
    (path / "inventory.json").write_text(inventory.model_dump_json())
    reader = Mock(aclose=AsyncMock())
    backend = Mock(content_reader=Mock(return_value=reader))
    scanner = Mock(scan=AsyncMock(), export_report=AsyncMock())
    monkeypatch.setattr(boundary_module, "DspyFindingJudge", Mock())
    monkeypatch.setattr(
        boundary_module, "TitusCliScanner", Mock(return_value=scanner)
    )
    deduplicate = AsyncMock(
        return_value=CredentialsDocument(
            boundary_id=reference.id,
            report_generated_at="new",
        )
    )
    monkeypatch.setattr(
        boundary_module,
        "deduplicate_report",
        deduplicate,
    )
    return Boundary(backend, path), scanner, reader, deduplicate


def test_command_loads_state_only_after_acquiring_ownership(tmp_path, monkeypatch):
    boundary, _, reader, _ = make_boundary(tmp_path, monkeypatch)
    credential = Credential(
        credential_id="saved",
        credential="value",
        occurrences=(CredentialOccurrence(locator="source"),),
        judgment=JudgmentResult(verdict="VALID"),
    )
    saved = CredentialsDocument(
        boundary_id=boundary.boundary_id,
        report_generated_at="saved",
        credentials={credential.credential_id: credential},
    )
    boundary.paths.credentials.write_text(saved.model_dump_json())

    assert asyncio.run(boundary.judge()) == 0
    current = CredentialsDocument.model_validate_json(
        boundary.paths.credentials.read_text()
    )
    assert current == saved
    reader.aclose.assert_awaited_once()


def test_busy_boundary_rejects_entire_competing_command(tmp_path, monkeypatch):
    boundary, _, reader, _ = make_boundary(tmp_path, monkeypatch)

    with boundary_lock(boundary.paths.operation_lock):
        with pytest.raises(BoundaryBusyError, match="boundary busy"):
            asyncio.run(boundary.judge())

    boundary.backend.content_reader.assert_not_called()
    reader.aclose.assert_not_awaited()


def test_surviving_child_retains_boundary_ownership(tmp_path):
    path = tmp_path / "boundary" / ".operation.lock"
    with boundary_lock(path) as descriptor:
        child = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(0.2)"],
            pass_fds=(descriptor,),
        )

    try:
        with pytest.raises(BoundaryBusyError):
            with boundary_lock(path):
                pass
    finally:
        child.wait(timeout=2)

    with boundary_lock(path):
        pass


def test_pending_publication_exports_without_scanning(tmp_path, monkeypatch):
    boundary, scanner, _, _ = make_boundary(
        tmp_path, monkeypatch, publication_pending=True
    )
    boundary.paths.datastore.write_bytes(b"existing datastore")
    old = CredentialsDocument(
        boundary_id=boundary.boundary_id,
        report_generated_at="old",
    )
    boundary.paths.credentials.write_text(old.model_dump_json())
    boundary.paths.report.write_text(
        TitusReport(
            boundary_id=boundary.boundary_id,
            generated_at="old",
        ).model_dump_json()
    )
    scanner.export_report.return_value = TitusReport(
        boundary_id=boundary.boundary_id,
        generated_at="new",
    )

    assert asyncio.run(boundary.scan())
    scanner.scan.assert_not_awaited()
    scanner.export_report.assert_awaited_once_with(boundary.paths.datastore)
    current = ScanTargetInventory.model_validate_json(
        boundary.paths.inventory.read_text()
    )
    assert not current.publication_pending


@pytest.mark.parametrize("failure", ["export", "conversion", "credentials"])
def test_interrupted_publication_remains_pending(
    tmp_path, monkeypatch, failure
):
    boundary, scanner, _, deduplicate = make_boundary(
        tmp_path, monkeypatch, publication_pending=True
    )
    boundary.paths.datastore.write_bytes(b"existing datastore")
    boundary.paths.credentials.write_text(
        CredentialsDocument(
            boundary_id=boundary.boundary_id,
            report_generated_at="old",
        ).model_dump_json()
    )
    scanner.export_report.return_value = TitusReport(
        boundary_id=boundary.boundary_id,
        generated_at="new",
    )
    if failure == "export":
        scanner.export_report.side_effect = RuntimeError("export failed")
    elif failure == "conversion":
        deduplicate.side_effect = RuntimeError("conversion failed")
    else:
        original_write = boundary._write

        def fail_new_credentials(path, document, model_type):
            if (
                path == boundary.paths.credentials
                and document.report_generated_at == "new"
            ):
                raise OSError("credential checkpoint failed")
            original_write(path, document, model_type)

        monkeypatch.setattr(boundary, "_write", fail_new_credentials)

    with pytest.raises((RuntimeError, OSError)):
        asyncio.run(boundary.scan())

    current = ScanTargetInventory.model_validate_json(
        boundary.paths.inventory.read_text()
    )
    assert current.publication_pending
    scanner.scan.assert_not_awaited()
