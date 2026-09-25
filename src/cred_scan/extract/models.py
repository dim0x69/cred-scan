"""Persisted evidence extraction results."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ExtractionResult(BaseModel):
    """Evidence metadata; evidence bytes live outside credentials.json."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["pending", "skipped", "retained", "failed"] = "pending"
    output_path: str | None = None
    size: int | None = Field(default=None, ge=0)
    sha256: str | None = None
    error: str | None = None
    reason: str | None = None

    @model_validator(mode="after")
    def validate_result(self) -> "ExtractionResult":
        metadata = (self.output_path, self.size, self.sha256)
        if self.status == "retained":
            if not self.output_path or self.size is None or not self.sha256:
                raise ValueError("retained extraction requires path, size, and hash")
        elif any(value is not None for value in metadata):
            raise ValueError("only retained extraction has evidence metadata")
        if self.status == "failed" and not self.error:
            raise ValueError("failed extraction requires an error")
        if self.status == "skipped" and not self.reason:
            raise ValueError("skipped extraction requires a reason")
        return self
