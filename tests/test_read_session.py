import asyncio
from unittest.mock import create_autospec

import pytest

from cred_scan.backend.proto import ContentReader
from cred_scan.orch.runtime import ReadSession


@pytest.mark.parametrize("content", [b"", b"text", b"\xff\x00binary"])
def test_read_session_reuses_exact_locations_and_clears_on_close(credential, content):
    reader = create_autospec(ContentReader, instance=True)
    reader.read.return_value = content
    session = ReadSession(reader)
    location = credential.occurrences[0].locations[0]

    async def exercise():
        assert await session.read(location) == content
        assert await session.read(location.model_copy()) == content
        reader.read.assert_awaited_once_with(location)
        await session.aclose()
        await session.aclose()
        assert not session._cache
        reader.aclose.assert_awaited_once()
        with pytest.raises(RuntimeError, match="closed"):
            await session.read(location)

    asyncio.run(exercise())


@pytest.mark.parametrize("field", ["target_id", "locator", "source_path", "filename"])
def test_cache_does_not_bypass_validation_of_changed_location(credential, field):
    reader = create_autospec(ContentReader, instance=True)
    location = credential.occurrences[0].locations[0]

    async def read(requested):
        if requested != location:
            raise ValueError("location does not match locator")
        return b"content"

    reader.read.side_effect = read
    session = ReadSession(reader)

    async def exercise():
        try:
            assert await session.read(location) == b"content"
            changed = location.model_copy(update={field: "different"})
            with pytest.raises(ValueError, match="does not match"):
                await session.read(changed)
            assert reader.read.await_count == 2
            assert await session.read(location) == b"content"
            assert reader.read.await_count == 2
        finally:
            await session.aclose()

    asyncio.run(exercise())


def test_read_session_does_not_cache_failures(credential):
    reader = create_autospec(ContentReader, instance=True)
    reader.read.side_effect = [OSError("temporary failure"), b"retried"]
    session = ReadSession(reader)
    location = credential.occurrences[0].locations[0]

    async def exercise():
        try:
            with pytest.raises(OSError, match="temporary failure"):
                await session.read(location)
            assert await session.read(location) == b"retried"
            assert await session.read(location) == b"retried"
            assert reader.read.await_count == 2
        finally:
            await session.aclose()

    asyncio.run(exercise())
