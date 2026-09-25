"""Titus reports, backend credential occurrences, and lifecycle results."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from cred_scan.extract.models import ExtractionResult


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
    model_config = ConfigDict(extra="forbid")

    status: Literal["pending", "completed", "failed"] = "pending"
    verdict: Literal["valid", "invalid", "unknown"] | None = None
    reasoning: str = ""
    error: str | None = None

    @model_validator(mode="after")
    def validate_result(self) -> "JudgmentResult":
        if self.status == "completed":
            if self.verdict is None or self.error is not None:
                raise ValueError("completed judgment requires a verdict and no error")
        elif self.verdict is not None:
            raise ValueError("only completed judgments have a verdict")
        if self.status == "failed" and not self.error:
            raise ValueError("failed judgment requires an error")
        return self


class Credential(BaseModel):
    """One deduplicated credential and its complete lifecycle state."""

    credential_id: str
    credential: str | None = Field(default=None, repr=False)
    occurrences: tuple[CredentialOccurrence, ...] = Field(min_length=1)
    judgment: JudgmentResult = Field(default_factory=JudgmentResult)
    extraction: ExtractionResult = Field(default_factory=ExtractionResult)

    @property
    def paths(self) -> tuple[str, ...]:
        """Backend locators retained for source-aware content access."""
        return tuple(occurrence.locator for occurrence in self.occurrences)


class TitusReport(BaseModel):
    """The complete final Titus export for one report boundary."""

    schema_version: Literal[3] = 3
    boundary_id: str
    generated_at: str
    errors: tuple[str, ...] = ()
    findings: tuple[dict[str, Any], ...] = ()


class CredentialsDocument(BaseModel):
    """The append-only ID-indexed credentials document for one boundary."""

    schema_version: Literal[9] = 9
    boundary_id: str
    report_generated_at: str
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
