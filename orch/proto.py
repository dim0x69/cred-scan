"""Configuration loading protocol."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from orch.models import AppConfig


class ConfigLoader(Protocol):
    async def load(self, path: Path) -> AppConfig: ...
