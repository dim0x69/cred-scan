"""Pure append and lifecycle transitions for a boundary's credential checkpoint."""

from cred_scan.scan.models import (
    CredentialOccurrence,
    CredentialsDocument,
    ExtractionResult,
    JudgmentResult,
)


def merge_scan(
    previous: CredentialsDocument | None, discovered: CredentialsDocument
) -> CredentialsDocument:
    """Append observations in first-seen order without erasing historical state."""
    if previous is not None and previous.boundary_id != discovered.boundary_id:
        raise ValueError("cannot merge credentials from another boundary")
    updated = dict(previous.credentials) if previous is not None else {}
    for credential_id, candidate in discovered.credentials.items():
        old = updated.get(credential_id)
        if old is None:
            updated[credential_id] = candidate.model_copy(
                update={"occurrences": _merge_occurrences((), candidate.occurrences)}
            )
            continue
        updated[credential_id] = old.model_copy(
            update={
                "credential": old.credential or candidate.credential,
                "occurrences": _merge_occurrences(
                    old.occurrences, candidate.occurrences
                ),
                "judgment": (
                    old.judgment
                    if old.judgment.verdict != "PENDING"
                    else candidate.judgment
                ),
                "extraction": old.extraction or candidate.extraction,
            }
        )
    return discovered.model_copy(update={"credentials": updated})


def _merge_occurrences(
    existing: tuple[CredentialOccurrence, ...],
    discovered: tuple[CredentialOccurrence, ...],
) -> tuple[CredentialOccurrence, ...]:
    merged: dict[str, CredentialOccurrence] = {}
    # Fold every historical entry first, including several for the same target.
    for occurrence in (*existing, *discovered):
        prior = merged.get(occurrence.target_id)
        locations = list(prior.locations) if prior is not None else []
        for location in occurrence.locations:
            if location not in locations:
                locations.append(location)
        finding_ids = list(prior.finding_ids) if prior is not None else []
        for finding_id in occurrence.finding_ids:
            if finding_id not in finding_ids:
                finding_ids.append(finding_id)
        merged[occurrence.target_id] = occurrence.model_copy(
            update={"locations": tuple(locations), "finding_ids": tuple(finding_ids)}
        )
    return tuple(merged.values())


def with_judgment(
    document: CredentialsDocument, credential_id: str, judgment: JudgmentResult
) -> CredentialsDocument:
    """Update one known credential, preserving any historical extraction metadata."""
    credential = document.credentials.get(credential_id)
    if credential is None:
        raise ValueError(f"cannot update inactive credential: {credential_id}")
    return document.model_copy(
        update={
            "credentials": {
                **document.credentials,
                credential_id: credential.model_copy(update={"judgment": judgment}),
            }
        }
    )


def with_extraction(
    document: CredentialsDocument, credential_id: str, extraction: ExtractionResult
) -> CredentialsDocument:
    """Record an extraction outcome only for a known VALID credential."""
    credential = document.credentials.get(credential_id)
    if credential is None:
        raise ValueError(f"cannot extract inactive credential: {credential_id}")
    if credential.judgment.verdict != "VALID":
        raise ValueError("evidence extraction requires a VALID judgment")
    return document.model_copy(
        update={
            "credentials": {
                **document.credentials,
                credential_id: credential.model_copy(update={"extraction": extraction}),
            }
        }
    )
