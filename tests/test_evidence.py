import asyncio
import hashlib
import pytest

from cred_scan.extract.evidence import (
    EvidenceConflictError,
    evidence_exists,
    evidence_path,
    retain_first_evidence,
)
from cred_scan.extract.models import ExtractionResult


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
def test_evidence_existence_checks_do_not_read_or_modify_artifacts(
    tmp_path, damage, monkeypatch
):
    boundary = tmp_path / "boundary"
    destination = evidence_path(boundary, "credential/id", "app:prod.env")
    destination.parent.mkdir(parents=True)
    content = b"retained evidence"
    destination.write_bytes(content)
    metadata = ExtractionResult(
        status="retained",
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
    with monkeypatch.context() as patch:

        def forbid_read(*args, **kwargs):
            raise AssertionError("existence check must not read evidence bytes")

        patch.setattr(type(destination), "read_bytes", forbid_read)
        assert evidence_exists(boundary, "credential/id", metadata) == (
            damage in {"none", "size", "hash"}
        )
    assert metadata.model_dump(mode="json") == before
    assert outside.read_bytes() == content
    if damage == "missing":
        assert not destination.exists()
    else:
        assert destination.read_bytes() == content
    assert destination.is_symlink() == (damage == "symlink")


def test_new_filename_does_not_delete_old_evidence(tmp_path):
    credential_id = "synthetic-credential"
    old = evidence_path(tmp_path, credential_id, "app.env")
    old.parent.mkdir(parents=True)
    old.write_bytes(b"historical artifact")
    destination = evidence_path(tmp_path, credential_id, "renamed.env")
    result, size, sha256 = asyncio.run(
        retain_first_evidence(b"new evidence", destination)
    )
    assert result == destination
    assert size == len(b"new evidence")
    assert sha256 == hashlib.sha256(b"new evidence").hexdigest()
    assert old.read_bytes() == b"historical artifact"
    assert destination.read_bytes() == b"new evidence"


@pytest.mark.parametrize("matching", [False, True])
def test_orphaned_evidence_is_adopted_only_if_identical_never_overwritten(
    tmp_path, matching
):
    destination = evidence_path(tmp_path, "credential", "app.env")
    destination.parent.mkdir(parents=True)
    original = b"same" if matching else b"different"
    destination.write_bytes(original)
    inode = destination.stat().st_ino
    if matching:
        _, size, digest = asyncio.run(retain_first_evidence(b"same", destination))
        assert size == 4 and digest == hashlib.sha256(b"same").hexdigest()
    else:
        with pytest.raises(EvidenceConflictError):
            asyncio.run(retain_first_evidence(b"same", destination))
    assert destination.read_bytes() == original
    assert destination.stat().st_ino == inode
    assert not list(destination.parent.glob(".*.tmp"))
