"""Safe destinations and integrity checks for first-occurrence evidence."""

from __future__ import annotations

import hashlib
from pathlib import Path, PurePosixPath
from urllib.parse import quote

import aiofiles

from cred_scan.backend.proto import ContentReader
from cred_scan.scan.models import Credential, CredentialLocation, ExtractionResult


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
    if extraction.status != "RETAINED" or extraction.output_path is None:
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
    credential: Credential,
    location: CredentialLocation,
    tools: ContentReader,
    destination: Path,
) -> tuple[Path, int, str]:
    """Retain the first resolved occurrence for a VALID credential."""
    if credential.judgment.verdict != "VALID":
        raise ValueError("evidence retention requires a VALID judgment")
    # Only invoked without retained evidence; never deletes an earlier artifact.
    result = await tools.extract_file(location.provenance, destination)
    async with aiofiles.open(destination, mode="rb") as stream:
        content = await stream.read()
    # credentials.json is the sole index; bytes remain outside the document.
    return result, len(content), hashlib.sha256(content).hexdigest()
