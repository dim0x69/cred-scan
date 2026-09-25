"""Content reads retrieve bytes independently, without a read-session cache."""

import asyncio
from contextlib import contextmanager
from unittest.mock import AsyncMock, Mock

import pytest

from cred_scan.backend.adapters.artifactory.docker import (
    ArtifactoryDockerReader,
)


LOCATOR = "docker://registry/repo/image@sha256:manifest/sha256:layer:etc/app.env"


@pytest.fixture
def reader(tmp_path):
    @contextmanager
    def scratch():
        yield tmp_path

    return ArtifactoryDockerReader(Mock(), scratch_dir=scratch)


@pytest.mark.parametrize("resolved", [False, True])
def test_repeated_reads_fetch_content_each_time(reader, resolved):
    reader._find_file = AsyncMock(side_effect=[b"first read", b"second read"])

    async def exercise():
        try:
            location = await reader.resolve_location(LOCATOR) if resolved else LOCATOR
            assert (await reader.read(location)).content == b"first read"
            assert (await reader.read(location)).content == b"second read"
            assert reader._find_file.await_count == 2
        finally:
            await reader.aclose()

    asyncio.run(exercise())


def test_resolving_again_does_not_reuse_mutated_location(reader):
    async def exercise():
        try:
            first = await reader.resolve_location(LOCATOR)
            first.source_path = "changed"
            second = await reader.resolve_location(LOCATOR)
            assert second.source_path == "etc/app.env"
            assert second is not first
        finally:
            await reader.aclose()

    asyncio.run(exercise())
