"""Judge-facing protocols."""

from __future__ import annotations

from typing import Protocol

from backend.proto import ContentReader
from scan.models import Credential, JudgmentResult


class FatalJudgeError(RuntimeError):
    """The configured language-model judge cannot continue this run."""


class FindingJudge(Protocol):
    """Judge credentials using the caller-owned content reader.

    Implementations must keep all work that uses ``content`` within the
    returned awaitable and propagate cancellation. The caller awaits directly
    and closes the reader afterward. Content adapters, not the whole judgment,
    must settle any non-cancellable worker that still uses reader scratch.
    """

    async def judge(
        self, credential: Credential, content: ContentReader
    ) -> JudgmentResult: ...
