"""In-memory append/merge policy for a boundary's credentials."""

from cred_scan.scan.models import CredentialOccurrence, CredentialsDocument


def merge_scan(
    previous: CredentialsDocument | None, discovered: CredentialsDocument
) -> CredentialsDocument:
    """Merge scan findings into the boundary's credential history in place.

    Match credentials by ID, adding new credentials and retaining historical
    credentials absent from this scan. Deduplicate occurrence locators in
    first-seen order, preserving the first occurrence used for evidence.
    For existing credentials, fill an empty value, replace only a PENDING
    judgment, and adopt extraction metadata only when none exists.

    Replace the report timestamp, incomplete flag, and errors with those from
    discovered. Return the mutated previous document, or mutate and return
    discovered when previous is None. New credentials are adopted by reference,
    and their occurrences may be normalized in place; inputs are not copied.

    Raise ValueError before mutation if the documents belong to different
    boundaries. This function performs no I/O; Boundary checkpoints the result.
    """
    if previous is not None and previous.boundary_id != discovered.boundary_id:
        raise ValueError("cannot merge credentials from another boundary")
    document = previous if previous is not None else discovered
    for credential_id, candidate in discovered.credentials.items():
        old = document.credentials.get(credential_id)
        if old is None or old is candidate:
            candidate.occurrences = _merge_occurrences((), candidate.occurrences)
            document.credentials[credential_id] = candidate
            continue
        old.credential = old.credential or candidate.credential
        old.occurrences = _merge_occurrences(old.occurrences, candidate.occurrences)
        if old.judgment.verdict == "PENDING":
            old.judgment = candidate.judgment
        old.extraction = old.extraction or candidate.extraction
    document.report_generated_at = discovered.report_generated_at
    document.incomplete = discovered.incomplete
    document.errors = discovered.errors
    return document


def _merge_occurrences(
    existing: tuple[CredentialOccurrence, ...],
    discovered: tuple[CredentialOccurrence, ...],
) -> tuple[CredentialOccurrence, ...]:
    merged: dict[str, CredentialOccurrence] = {}
    for occurrence in (*existing, *discovered):
        merged.setdefault(occurrence.locator, occurrence)
    return tuple(merged.values())
