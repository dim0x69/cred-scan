"""Occurrence paths are readable without historical inventory targets."""

import asyncio
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import AsyncMock, Mock

import pytest

from cred_scan.backend.adapters.artifactory.docker import (
    ArtifactoryDockerReader,
    LayerEvidenceError,
)
from cred_scan.backend.adapters.artifactory.models import ArtifactoryRepository


PROVENANCE = (
    "docker://registry/docker-local/team/api@sha256:old-manifest/"
    "sha256:old-layer:etc/app.env"
)


@contextmanager
def scratch() -> Iterator[Path]:
    with TemporaryDirectory() as directory:
        yield Path(directory)


def make_reader() -> ArtifactoryDockerReader:
    backend = Mock()
    boundary = ArtifactoryRepository(
        id="artifactory:primary:docker-local", name="docker-local"
    )
    return ArtifactoryDockerReader(backend, boundary, scratch_dir=scratch)


def test_reader_resolves_and_reads_old_occurrence_without_targets() -> None:
    reader = make_reader()
    reader._find_file = AsyncMock(return_value=b"SECRET=historical\n")

    location = asyncio.run(reader.resolve_location(PROVENANCE))
    content = asyncio.run(reader.read(location))

    assert location.locator == PROVENANCE
    assert location.source_path == "etc/app.env"
    assert location.filename == "app.env"
    assert content.content == b"SECRET=historical\n"
    reader._find_file.assert_awaited_once()
    asyncio.run(reader.aclose())


def test_reader_rejects_an_occurrence_from_another_boundary() -> None:
    reader = make_reader()
    foreign = PROVENANCE.replace("docker-local", "other-repository")

    with pytest.raises(LayerEvidenceError, match="repository boundary"):
        asyncio.run(reader.resolve_location(foreign))
    asyncio.run(reader.aclose())
