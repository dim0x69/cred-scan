"""Safe destinations and integrity checks for first-occurrence evidence."""

from __future__ import annotations

import asyncio
import hashlib
import os
from pathlib import Path, PurePosixPath
from urllib.parse import quote

import aiofiles

from cred_scan.orch.fsync import fsync_directory
from cred_scan.backend.proto import ContentReader
from cred_scan.scan.models import Credential, ExtractionResult


class EvidenceConflictError(RuntimeError):
    """An uncheckpointed artifact differs from the immutable first occurrence."""


def evidence_path(boundary_dir: Path, credential_id: str, filename: str) -> Path:
    """Resolve a plain source filename inside its encoded credential directory."""
    if (
        not filename
        or filename in {".", ".."}
        or any(separator in filename for separator in ("/", "\\"))
        or PurePosixPath(filename).name != filename
    ):
        raise ValueError("evidence filename must be a plain safe filename")
    return boundary_dir / "evidence" / quote(credential_id, safe="._-") / filename


def evidence_matches(
    boundary_dir: Path, credential_id: str, extraction: ExtractionResult
) -> bool:
    """Verify retained path, size and hash without changing any bytes or metadata."""
    if extraction.output_path is None:
        return False
    credential_dir = boundary_dir / "evidence" / quote(credential_id, safe="._-")
    candidate = (boundary_dir / extraction.output_path).resolve()
    if candidate.parent != credential_dir.resolve() or not candidate.is_file():
        return False
    content = candidate.read_bytes()
    return (
        len(content) == extraction.size
        and hashlib.sha256(content).hexdigest() == extraction.sha256
    )


async def retain_first_evidence(
    content: bytes,
    destination: Path,
) -> tuple[Path, int, str]:
    """Create evidence without overwriting history; adopt matching orphaned bytes.

    RETAINED credentials never call this function. An existing destination here
    is the crash window between writing bytes and checkpointing their metadata.
    """
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.tmp")
    try:
        async with aiofiles.open(temporary, mode="wb") as stream:
            await stream.write(content)
            await stream.flush()
            await asyncio.to_thread(os.fsync, stream.fileno())
        try:
            # Atomic create-if-absent, never replacement of historical evidence.
            os.link(temporary, destination)
        except FileExistsError:
            if destination.is_symlink() or destination.read_bytes() != content:
                raise EvidenceConflictError(
                    f"existing evidence differs: {destination}"
                ) from None
        fsync_directory(destination.parent)
    finally:
        temporary.unlink(missing_ok=True)
    return destination, len(content), hashlib.sha256(content).hexdigest()


class EvidenceExtractor:
    """Retain first-occurrence evidence for one boundary."""

    def __init__(self, boundary_dir: Path) -> None:
        self.boundary_dir = boundary_dir

    async def extract(
        self, credential: Credential, reader: ContentReader
    ) -> ExtractionResult:
        location = await reader.resolve_location(credential.occurrences[0].locator)
        content = await reader.read(location)
        destination = evidence_path(
            self.boundary_dir, credential.credential_id, content.filename
        )
        _, size, sha256 = await retain_first_evidence(content.content, destination)
        return ExtractionResult(
            status="RETAINED",
            output_path=destination.relative_to(self.boundary_dir).as_posix(),
            size=size,
            sha256=sha256,
        )
