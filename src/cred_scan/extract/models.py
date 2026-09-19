"""Persisted evidence extraction results."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ExtractionResult(BaseModel):
    """Evidence metadata; evidence bytes live outside credentials.json."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["RETAINED", "ERROR"]
    output_path: str | None = None
    size: int | None = Field(default=None, ge=0)
    sha256: str | None = None
    error: str | None = None
