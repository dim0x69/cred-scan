"""Safe destinations and integrity checks for first-occurrence evidence."""

from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path, PurePosixPath
from urllib.parse import quote

import aiofiles

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
    credential: Credential,
    location: CredentialLocation,
    content: bytes,
    destination: Path,
) -> tuple[Path, int, str]:
    """Write the first resolved occurrence for a VALID credential.

    Content retrieval belongs to the caller-owned read session. This helper owns
    only evidence bytes, atomic replacement, and the resulting integrity data.
    """
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.tmp")
    try:
        async with aiofiles.open(temporary, mode="wb") as stream:
            await stream.write(content)
            await stream.flush()
        await asyncio.to_thread(temporary.replace, destination)
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
    return destination, len(content), hashlib.sha256(content).hexdigest()
