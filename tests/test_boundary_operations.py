import asyncio
from datetime import UTC, datetime
from unittest.mock import AsyncMock, Mock
from urllib.parse import quote

import pytest

from cred_scan.backend.adapters.artifactory.models import ArtifactoryRepository
from cred_scan.backend.models import BoundaryRecord, ScanTargetInventory
from cred_scan.orch import boundary as boundary_module
from cred_scan.orch.boundary import Boundary
from cred_scan.orch.locking import BoundaryBusyError, boundary_lock
from cred_scan.scan.models import CredentialsDocument, TitusReport


def persisted_boundary(tmp_path, *, publication_pending: bool = False):
    reference = ArtifactoryRepository(
        id="artifactory:artifactory_docker:repository",
        name="repository",
    )
    path = tmp_path / quote(reference.id, safe="")
    path.mkdir()
    path.joinpath("boundary.json").write_text(
        BoundaryRecord(
            backend_id="artifactory_docker",
            boundary=reference,
        ).model_dump_json()
    )
    path.joinpath("scantargets.json").write_text(
        ScanTargetInventory(
            generated_at=datetime(2026, 1, 1, tzinfo=UTC),
            boundary=reference,
            publication_pending=publication_pending,
        ).model_dump_json()
    )
    backend = Mock()
    backend.name = "artifactory_docker"
    backend.content_reader.return_value = Mock(aclose=AsyncMock())
    return Boundary(backend, path)


def test_busy_boundary_rejects_operation_before_starting_services(tmp_path) -> None:
    boundary = persisted_boundary(tmp_path)

    with boundary_lock(boundary.paths.operation_lock):
        with pytest.raises(BoundaryBusyError):
            asyncio.run(boundary.judge())

    boundary.backend.content_reader.assert_not_called()


def test_pending_publication_exports_without_rescanning(tmp_path, monkeypatch) -> None:
    boundary = persisted_boundary(tmp_path, publication_pending=True)
    scanner = Mock(scan=AsyncMock())
    scanner.export_report = AsyncMock(
        return_value=TitusReport(
            boundary_id=boundary.boundary_id,
            generated_at="2026-01-01T00:00:00+00:00",
        )
    )
    monkeypatch.setattr(
        boundary_module,
        "TitusCliScanner",
        Mock(return_value=scanner),
    )
    monkeypatch.setattr(boundary_module, "DspyFindingJudge", Mock())
    monkeypatch.setattr(boundary_module, "EvidenceExtractor", Mock())
    deduplicate = AsyncMock(
        return_value=CredentialsDocument(
            boundary_id=boundary.boundary_id,
            report_generated_at="2026-01-01T00:00:00+00:00",
        )
    )
    monkeypatch.setattr(boundary_module, "deduplicate_report", deduplicate)

    assert asyncio.run(boundary.scan()) is True

    scanner.scan.assert_not_awaited()
    scanner.export_report.assert_awaited_once_with(boundary.paths.datastore)
    saved = ScanTargetInventory.model_validate_json(
        boundary.paths.scan_targets.read_text()
    )
    assert saved.publication_pending is False
    assert boundary.paths.report.is_file()
    assert boundary.paths.credentials.is_file()
    boundary.backend.content_reader.return_value.aclose.assert_awaited_once()

