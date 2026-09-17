"""Titus reports, resolved credential provenance, and lifecycle results."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator


class ExclusionFiles(BaseModel):
    paths: Path
    credentials: Path


class ExclusionPolicy(BaseModel):
    """Patterns loaded for one scan; contents are not persisted or hashed."""

    path_file: Path
    path_patterns: tuple[str, ...] = ()
    credential_patterns: tuple[str, ...] = ()


class CredentialLocation(BaseModel):
    """One Titus path after source-specific backend resolution."""

    provenance: str
    source_path: str
    filename: str


class CredentialOccurrence(BaseModel):
    """Occurrences grouped by one pinned, source-neutral scan target."""

    target_id: str = Field(min_length=1)
    locations: tuple[CredentialLocation, ...] = Field(min_length=1)
    finding_ids: tuple[str, ...] = ()


class JudgmentResult(BaseModel):
    verdict: Literal["PENDING", "VALID", "INVALID", "UNKNOWN", "ERROR"] = "PENDING"
    reasoning: str = ""


class ExtractionResult(BaseModel):
    """Evidence metadata; evidence bytes live outside credentials.json."""

    status: Literal["RETAINED", "ERROR"]
    source_fingerprint: str
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
        """Raw Titus paths retained for the source-aware content reader."""
        return tuple(
            location.provenance
            for occurrence in self.occurrences
            for location in occurrence.locations
        )

    @property
    def source_paths(self) -> tuple[str, ...]:
        return tuple(
            location.source_path
            for occurrence in self.occurrences
            for location in occurrence.locations
        )

    @model_validator(mode="after")
    def require_paths(self) -> "Credential":
        if not self.paths:
            raise ValueError("credential requires at least one occurrence path")
        return self


def credential_source_fingerprint(credential: Credential) -> str:
    payload = [
        {
            "target_id": occurrence.target_id,
            "locations": tuple(
                {
                    "provenance": location.provenance,
                    "source_path": location.source_path,
                }
                for location in occurrence.locations
            ),
        }
        for occurrence in credential.occurrences
    ]
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


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

    schema_version: Literal[4] = 4
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
