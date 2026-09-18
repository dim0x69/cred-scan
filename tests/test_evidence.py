import asyncio
import hashlib
import pytest

from cred_scan.judge.evidence import evidence_matches, evidence_path, retain_first_evidence
from cred_scan.scan.models import ExtractionResult, JudgmentResult


@pytest.mark.parametrize(
    "filename", ["", ".", "..", "../app.env", "/app.env", "dir/app.env", "dir\\app.env"]
)
def test_evidence_rejects_non_plain_filename(tmp_path, filename):
    with pytest.raises(ValueError, match="plain safe filename"):
        evidence_path(tmp_path, "credential/id", filename)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "damage", ["none", "missing", "size", "hash", "path", "symlink"]
)
def test_evidence_integrity_checks_do_not_modify_artifacts_or_metadata(
    tmp_path, damage
):
    boundary = tmp_path / "boundary"
    destination = evidence_path(boundary, "credential/id", "app:prod.env")
    destination.parent.mkdir(parents=True)
    content = b"retained evidence"
    destination.write_bytes(content)
    metadata = ExtractionResult(
        status="RETAINED",
        output_path=destination.relative_to(boundary).as_posix(),
        size=len(content),
        sha256=hashlib.sha256(content).hexdigest(),
    )
    outside = tmp_path / "outside.env"
    outside.write_bytes(content)
    if damage == "missing":
        destination.unlink()
    elif damage == "size":
        metadata.size = len(content) + 1
    elif damage == "hash":
        metadata.sha256 = "0" * 64
    elif damage == "path":
        metadata.output_path = "../outside.env"
    elif damage == "symlink":
        destination.unlink()
        destination.symlink_to(outside)
    before = metadata.model_dump(mode="json")
    assert evidence_matches(boundary, "credential/id", metadata) == (damage == "none")
    assert metadata.model_dump(mode="json") == before
    assert outside.read_bytes() == content
    if damage == "missing":
        assert not destination.exists()
    else:
        assert destination.read_bytes() == content
    assert destination.is_symlink() == (damage == "symlink")


def test_new_filename_does_not_delete_old_evidence(tmp_path, credential):
    credential = credential.model_copy(
        update={"judgment": JudgmentResult(verdict="VALID")}
    )
    location = credential.occurrences[0].locations[0]
    old = evidence_path(tmp_path, credential.credential_id, location.filename)
    old.parent.mkdir(parents=True)
    old.write_bytes(b"historical artifact")
    renamed = location.model_copy(update={"filename": "renamed.env"})
    destination = evidence_path(tmp_path, credential.credential_id, renamed.filename)
    result, size, sha256 = asyncio.run(
        retain_first_evidence(credential, renamed, b"new evidence", destination)
    )
    assert result == destination
    assert size == len(b"new evidence")
    assert sha256 == hashlib.sha256(b"new evidence").hexdigest()
    assert old.read_bytes() == b"historical artifact"
    assert destination.read_bytes() == b"new evidence"


def test_non_valid_credential_cannot_trigger_evidence_extraction(tmp_path, credential):
    with pytest.raises(ValueError, match="VALID"):
        asyncio.run(
            retain_first_evidence(
                credential,
                credential.occurrences[0].locations[0],
                b"unused",
                tmp_path / "unused",
            )
        )
    assert list(tmp_path.iterdir()) == []
