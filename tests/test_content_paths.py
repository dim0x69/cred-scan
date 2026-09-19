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
