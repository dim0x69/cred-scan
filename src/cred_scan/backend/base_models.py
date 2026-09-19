"""Schema-only foundations shared by backend-specific and aggregate models."""

from __future__ import annotations

import hashlib

from pydantic import BaseModel


class ScanBoundary(BaseModel):
    """Provider-qualified report boundary owning inventory and scan artifacts."""

    id: str
    name: str


class ScanScope(BaseModel):
    """A logical scan scope snapshot with computed identity."""

    @property
    def id(self) -> str:
        raise NotImplementedError

    @property
    def version_id(self) -> str:
        raise NotImplementedError


def _version_hash(parts: tuple[str, ...]) -> str:
    payload = "\x00".join(parts).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:24]
