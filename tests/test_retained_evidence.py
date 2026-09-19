"""Extraction checks retained files even when no new extraction is pending."""

import asyncio
from datetime import UTC, datetime
from unittest.mock import AsyncMock, Mock
from urllib.parse import quote

import pytest

from cred_scan.backend.adapters.artifactory.models import ArtifactoryRepository
from cred_scan.backend.models import ScanBoundaryInventory
from cred_scan.extract.evidence import evidence_path
from cred_scan.extract.models import ExtractionResult
from cred_scan.orch import boundary as boundary_module
from cred_scan.orch.boundary import Boundary
from cred_scan.scan.models import Credential, CredentialOccurrence, CredentialsDocument


@pytest.mark.parametrize("file_state", ["present", "missing", "directory"])
@pytest.mark.parametrize("verdict", ["VALID", "UNKNOWN", "INVALID"])
def test_retained_file_check_preserves_history(
    tmp_path, monkeypatch, caplog, file_state, verdict
):
    repository = ArtifactoryRepository(id="artifactory:primary:repo", name="repo")
    boundary_dir = tmp_path / quote(repository.id, safe="")
    boundary_dir.mkdir()
    inventory = ScanBoundaryInventory(
        generated_at=datetime.now(UTC), boundary=repository,
    )
    (boundary_dir / "inventory.json").write_text(inventory.model_dump_json())
    destination = evidence_path(boundary_dir, "credential", "app.env")
    if file_state == "present":
        destination.parent.mkdir(parents=True)
        destination.write_bytes(b"different contents from original evidence")
    elif file_state == "directory":
        destination.mkdir(parents=True)
    credential = Credential(
        credential_id="credential",
        occurrences=(CredentialOccurrence(locator="synthetic-location"),),
        judgment={"verdict": verdict},
        extraction=ExtractionResult(
            status="RETAINED", output_path="evidence/credential/app.env",
            size=1, sha256="old-digest",
        ),
    )
    document = CredentialsDocument(
        boundary_id=repository.id, report_generated_at="now",
        credentials={credential.credential_id: credential},
    )
    document_path = boundary_dir / "credentials.json"
    document_path.write_text(document.model_dump_json())
    before = document_path.read_bytes()
    reader = Mock(aclose=AsyncMock())
    reader.resolve_location = AsyncMock()
    reader.read = AsyncMock()
    backend = Mock()
    backend.content_reader.return_value = reader
    monkeypatch.setattr(boundary_module, "DspyFindingJudge", Mock())
    monkeypatch.setattr(boundary_module, "TitusCliScanner", Mock())
    boundary = Boundary(backend, boundary_dir)
    boundary.extractor.extract = AsyncMock()

    def forbid_read(*args, **kwargs):
        raise AssertionError("retained evidence must not be read")

    try:
        with monkeypatch.context() as patch:
            patch.setattr(type(destination), "read_bytes", forbid_read)
            assert boundary.needs_extract()
            assert asyncio.run(boundary.extract()) == 0
        assert document_path.read_bytes() == before
        assert boundary.credentials == document
        reader.resolve_location.assert_not_awaited()
        reader.read.assert_not_awaited()
        boundary.extractor.extract.assert_not_awaited()
        if file_state == "present":
            assert "retained evidence missing" not in caplog.text
            assert destination.read_bytes() == b"different contents from original evidence"
        else:
            assert "retained evidence missing" in caplog.text
            assert repository.id in caplog.text
            assert "evidence/credential/app.env" in caplog.text
            assert not destination.is_file()
    finally:
        asyncio.run(boundary.aclose())
