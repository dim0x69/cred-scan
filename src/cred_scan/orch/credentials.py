"""In-memory append/merge policy for a boundary's credentials."""

from cred_scan.scan.models import CredentialOccurrence, CredentialsDocument


def merge_scan(
    previous: CredentialsDocument | None, discovered: CredentialsDocument
) -> CredentialsDocument:
    """Merge scan findings into the boundary's credential history in place.

    Match credentials by ID, adding new credentials and retaining historical
    credentials absent from this scan. Deduplicate occurrence locators in
    first-seen order, preserving the first occurrence used for evidence.
    For existing credentials, fill an empty value and preserve both stage results.

    Replace the report timestamp and errors with those from
    discovered. Return the mutated previous document, or mutate and return
    discovered when previous is None. New credentials are adopted by reference,
    and their occurrences may be normalized in place; inputs are not copied.

    The caller supplies documents for the same boundary. This function performs
    no I/O; Boundary checkpoints the result.
    """
    document = previous if previous is not None else discovered
    for credential_id, candidate in discovered.credentials.items():
        old = document.credentials.get(credential_id)
        if old is None or old is candidate:
            candidate.occurrences = _merge_occurrences((), candidate.occurrences)
            document.credentials[credential_id] = candidate
            continue
        old.credential = old.credential or candidate.credential
        old.occurrences = _merge_occurrences(old.occurrences, candidate.occurrences)
    document.report_generated_at = discovered.report_generated_at
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
