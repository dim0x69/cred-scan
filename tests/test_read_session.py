import asyncio
from unittest.mock import create_autospec

import pytest

from cred_scan.backend.models import ContentLocation, ContentRead
from cred_scan.backend.proto import ContentReader
from cred_scan.orch.runtime import ReadSession


def _location(locator: str) -> ContentLocation:
    return ContentLocation(
        target_id="target",
        locator=locator,
        source_path="etc/app.env",
        filename="app.env",
    )


@pytest.mark.parametrize("content", [b"", b"text", b"\xff\x00binary"])
def test_read_session_reuses_exact_locators_and_clears_on_close(credential, content):
    reader = create_autospec(ContentReader, instance=True)
    reader.resolve_location.side_effect = lambda locator: _location(locator)
    reader.read.return_value = ContentRead(
        content=content, source_path="etc/app.env", filename="app.env"
    )
    session = ReadSession(reader)
    locator = credential.occurrences[0].locator

    async def exercise():
        assert (await session.read(locator)).content == content
        assert (await session.read(locator)).content == content
        reader.read.assert_awaited_once_with(_location(locator))
        await session.aclose()
        await session.aclose()
        assert not session._cache
        reader.aclose.assert_awaited_once()
        with pytest.raises(RuntimeError, match="closed"):
            await session.read(locator)

    asyncio.run(exercise())


def test_cache_does_not_bypass_validation_of_changed_locator(credential):
    reader = create_autospec(ContentReader, instance=True)
    reader.resolve_location.side_effect = lambda locator: _location(locator)

    async def read(requested):
        if requested.locator != credential.occurrences[0].locator:
            raise ValueError("locator does not match source")
        return ContentRead(
            content=b"content", source_path="etc/app.env", filename="app.env"
        )

    reader.read.side_effect = read
    session = ReadSession(reader)
    locator = credential.occurrences[0].locator

    async def exercise():
        try:
            assert (await session.read(locator)).content == b"content"
            with pytest.raises(ValueError, match="does not match"):
                await session.read("different")
            assert reader.read.await_count == 2
            assert (await session.read(locator)).content == b"content"
            assert reader.read.await_count == 2
        finally:
            await session.aclose()

    asyncio.run(exercise())


def test_read_session_does_not_cache_failures(credential):
    reader = create_autospec(ContentReader, instance=True)
    locator = credential.occurrences[0].locator
    reader.resolve_location.side_effect = lambda value: _location(value)
    reader.read.side_effect = [
        OSError("temporary failure"),
        ContentRead(
            content=b"retried", source_path="etc/app.env", filename="app.env"
        ),
    ]
    session = ReadSession(reader)

    async def exercise():
        try:
            with pytest.raises(OSError, match="temporary failure"):
                await session.read(locator)
            assert (await session.read(locator)).content == b"retried"
            assert (await session.read(locator)).content == b"retried"
            assert reader.read.await_count == 2
        finally:
            await session.aclose()

    asyncio.run(exercise())
