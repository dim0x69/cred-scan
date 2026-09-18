"""Titus reports, backend credential occurrences, and lifecycle results."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ExclusionFiles(BaseModel):
    paths: Path
    credentials: Path


class ExclusionPolicy(BaseModel):
    """Patterns loaded for one scan; contents are not persisted or hashed."""

    path_file: Path
    path_patterns: tuple[str, ...] = ()
    credential_patterns: tuple[str, ...] = ()


class CredentialOccurrence(BaseModel):
    """One backend locator where the credential appeared."""

    locator: str = Field(min_length=1)


class JudgmentResult(BaseModel):
    verdict: Literal["PENDING", "VALID", "INVALID", "UNKNOWN", "ERROR"] = "PENDING"
    reasoning: str = ""


class ExtractionResult(BaseModel):
    """Evidence metadata; evidence bytes live outside credentials.json."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["RETAINED", "ERROR"]
    output_path: str | None = None
    size: int | None = Field(default=None, ge=0)
    sha256: str | None = None
    error: str | None = None


class Credential(BaseModel):
    """One deduplicated credential and its complete lifecycle state."""

    credential_id: str
    credential: str | None = Field(default=None, repr=False)
    occurrences: tuple[CredentialOccurrence, ...] = Field(min_length=1)
    judgment: JudgmentResult = Field(default_factory=JudgmentResult)
    extraction: ExtractionResult | None = None

    @property
    def paths(self) -> tuple[str, ...]:
        """Backend locators retained for source-aware content access."""
        return tuple(occurrence.locator for occurrence in self.occurrences)


class TitusReport(BaseModel):
    """The complete final Titus export for one report boundary."""

    schema_version: Literal[2] = 2
    boundary_id: str
    generated_at: str
    incomplete: bool = False
    errors: tuple[str, ...] = ()
    findings: tuple[dict[str, Any], ...] = ()


class CredentialsDocument(BaseModel):
    """The append-only ID-indexed credentials document for one boundary."""

    schema_version: Literal[8] = 8
    boundary_id: str
    report_generated_at: str
    incomplete: bool = False
    credentials: dict[str, Credential] = Field(default_factory=dict)
    errors: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_index(self) -> "CredentialsDocument":
        mismatched = [
            credential_id
            for credential_id, credential in self.credentials.items()
            if credential_id != credential.credential_id
        ]
        if mismatched:
            raise ValueError(
                "credential index keys do not match credential_id: "
                + ", ".join(mismatched)
            )
        return self
