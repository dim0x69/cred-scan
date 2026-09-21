"""Occurrence paths are readable without historical inventory targets."""

import asyncio
import io
import tarfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import AsyncMock, Mock

import pytest

from cred_scan.backend.adapters.artifactory.docker import (
    ArtifactoryDockerReader,
    DockerLayerProvenance,
)


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
    return ArtifactoryDockerReader(backend, scratch_dir=scratch)


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


@pytest.mark.parametrize("resolved", [False, True])
def test_reader_reads_paths_from_multiple_repositories(resolved: bool) -> None:
    reader = make_reader()
    reader._find_file = AsyncMock(side_effect=[b"first", b"second"])

    async def read_repositories() -> None:
        try:
            for repository, expected in [("docker-local", b"first"), ("other-repository", b"second")]:
                path = PROVENANCE.replace("docker-local", repository)
                location = await reader.resolve_location(path) if resolved else path
                content = await reader.read(location)
                assert content.content == expected
                assert reader._find_file.call_args.args[0].repository == repository
        finally:
            await reader.aclose()

    asyncio.run(read_repositories())


def test_archive_lookup_returns_only_file_bytes(tmp_path) -> None:
    archive_path = tmp_path / "layer.tar"
    with tarfile.open(archive_path, "w") as archive:
        content = b"SECRET"
        member = tarfile.TarInfo("etc/app.env")
        member.size = len(content)
        archive.addfile(member, io.BytesIO(content))
    provenance = DockerLayerProvenance(
        raw_path="synthetic",
        registry="registry.example",
        repository="repository",
        image="team/api",
        manifest="sha256:manifest",
        layer="sha256:layer",
        path="etc/app.env",
    )
    reader = object.__new__(ArtifactoryDockerReader)

    result = reader._find_file_in_archive(archive_path, provenance)

    assert result == b"SECRET"
    assert not isinstance(result, tuple)
