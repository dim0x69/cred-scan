"""Schema-only foundations shared by backend-specific and aggregate models."""

from __future__ import annotations

import hashlib
from typing import Literal

from pydantic import BaseModel


class BackendConfig(BaseModel):
    """Serializable backend identity used by persisted report inventories."""

    name: str


class ScanBoundary(BaseModel):
    """Provider-qualified report boundary owning inventory and scan artifacts."""

    id: str
    name: str


class ScanScope(BaseModel):
    """A logical scan scope snapshot with computed identity and lifecycle."""

    lifecycle: Literal["active", "stale"] = "active"

    @property
    def id(self) -> str:
        raise NotImplementedError

    @property
    def pin_id(self) -> str:
        raise NotImplementedError


def _pin_hash(parts: tuple[str, ...]) -> str:
    payload = "\x00".join(parts).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:24]
