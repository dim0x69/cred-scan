"""Credential publication merge is pure; lifecycle persistence is tested separately."""

import pytest
from pydantic import ValidationError

from cred_scan.orch.credentials import merge_scan
from cred_scan.scan.exclusions import match_credential_exclusion
from cred_scan.scan.models import (
    CredentialsDocument,
    ExclusionPolicy,
    ExtractionResult,
    JudgmentResult,
)


def document_for(inventory, credential, **metadata):
    return CredentialsDocument(
        boundary_id=inventory.boundary.id,
        report_generated_at="now",
        credentials={credential.credential_id: credential},
        **metadata,
    )


def retained_document(inventory, credential):
    document = merge_scan(None, document_for(inventory, credential))
    saved = document.credentials[credential.credential_id]
    saved.judgment = JudgmentResult(verdict="VALID")
    saved.extraction = ExtractionResult(
        status="RETAINED",
        output_path="evidence/credential/app.env",
        size=17,
        sha256="a" * 64,
    )
    return document


def test_credential_exclusion_matches_without_persisted_ledger():
    assert match_credential_exclusion(
        ExclusionPolicy(path_file="paths.list", credential_patterns=("SECRET",)),
        "SECRET_VALUE",
    ) == ("SECRET",)


def test_credential_lifecycle_is_nested(repository_inventory, credential):
    document = merge_scan(None, document_for(repository_inventory, credential))
    saved = document.credentials[credential.credential_id]
    saved.judgment = JudgmentResult(verdict="VALID")
    assert saved.judgment.verdict == "VALID"
    assert saved.extraction is None
    saved.extraction = ExtractionResult(
        status="RETAINED",
        output_path="evidence/credential/app.env",
        size=17,
        sha256="a" * 64,
    )
    assert saved.extraction is not None


def test_credentials_document_rejects_mismatched_index(
    repository_inventory, credential
):
    with pytest.raises(ValidationError, match="credential index keys"):
        CredentialsDocument(
            boundary_id=repository_inventory.boundary.id,
            report_generated_at="now",
            credentials={"wrong": credential},
        )


@pytest.mark.parametrize("verdict", ["PENDING", "ERROR", "INVALID", "UNKNOWN"])
def test_non_valid_judgment_retains_historical_evidence(
    repository_inventory, credential, verdict
):
    document = retained_document(repository_inventory, credential)
    original = document.model_dump(mode="json")
    document.credentials[credential.credential_id].judgment = JudgmentResult(
        verdict=verdict
    )
    assert (
        document.credentials[credential.credential_id].extraction
        == retained_document(repository_inventory, credential)
        .credentials[credential.credential_id]
        .extraction
    )
    assert document.model_dump(mode="json") != original


def test_absent_history_and_new_occurrence_preserve_first_evidence(
    repository_inventory, credential
):
    document = retained_document(repository_inventory, credential)
    old = document.credentials[credential.credential_id]
    empty = CredentialsDocument(
        boundary_id=document.boundary_id, report_generated_at="new"
    )
    published = merge_scan(document, empty)
    assert published.credentials == document.credentials
    assert published.report_generated_at == "new"
    occurrence = credential.occurrences[0]
    new_occurrence = occurrence.model_copy(
        update={"locator": occurrence.locator.replace("app.env", "renamed.env")}
    )
    candidate = credential.model_copy(update={"occurrences": (new_occurrence,)})
    published = merge_scan(published, document_for(repository_inventory, candidate))
    saved = published.credentials[credential.credential_id]
    assert saved.extraction == old.extraction
    assert saved.occurrences == (occurrence, new_occurrence)


@pytest.mark.parametrize("stored_split", [False, True])
def test_append_unions_every_historical_occurrence_without_changing_first_evidence(
    repository_inventory, credential, stored_split
):
    first = credential.occurrences[0]
    second = first.model_copy(
        update={"locator": first.locator.replace("app.env", "b.env")}
    )
    history = credential.model_copy(update={"occurrences": (first, second)})
    original = retained_document(repository_inventory, history)
    retained = original.credentials[credential.credential_id].extraction
    if stored_split:
        # Current schema permits split entries; every one must be folded.
        original.credentials[credential.credential_id].occurrences = (first, second)
    before = original.model_dump(mode="json")
    candidate = history.model_copy(
        update={
            "occurrences": (second,),
            "judgment": JudgmentResult(verdict="PENDING"),
            "extraction": None,
        }
    )
    partial = document_for(
        repository_inventory, candidate, incomplete=True, errors=("partial",)
    )
    published = merge_scan(original, partial)
    saved = published.credentials[credential.credential_id]
    assert len(saved.occurrences) == 2
    assert saved.occurrences == (first, second)
    assert saved.judgment.verdict == "VALID"
    assert saved.extraction == retained
    assert published.incomplete and published.errors == ("partial",)
    assert original.model_dump(mode="json") == before
    assert merge_scan(published, partial) == published
    reversed_report = partial.model_copy(
        update={
            "credentials": {
                candidate.credential_id: candidate.model_copy(
                    update={"occurrences": (second, first, second)}
                )
            }
        }
    )
    assert merge_scan(published, reversed_report) == published


def test_append_normalizes_duplicate_occurrences_on_first_write(
    repository_inventory, credential
):
    occurrence = credential.occurrences[0]
    candidate = credential.model_copy(update={"occurrences": (occurrence, occurrence)})
    document = document_for(repository_inventory, candidate)
    before = document.model_dump(mode="json")
    published = merge_scan(None, document)
    saved = published.credentials[credential.credential_id]
    assert len(saved.occurrences) == 1
    assert saved.occurrences == (occurrence,)
    assert merge_scan(published, document) == published
    assert document.model_dump(mode="json") == before


def test_append_adds_new_pin_and_credential_without_losing_absent_history(
    repository_inventory, credential
):
    document = retained_document(repository_inventory, credential)
    old = document.credentials[credential.credential_id]
    new_occurrence = credential.occurrences[0].model_copy(
        update={
            "locator": credential.occurrences[0].locator.replace("manifest", "second")
        }
    )
    candidate = credential.model_copy(update={"occurrences": (new_occurrence,)})
    published = merge_scan(document, document_for(repository_inventory, candidate))
    saved = published.credentials[credential.credential_id]
    assert saved.occurrences == old.occurrences + (new_occurrence,)
    assert saved.extraction == old.extraction
    assert saved.judgment == old.judgment
    other = candidate.model_copy(update={"credential_id": "another-credential"})
    published = merge_scan(published, document_for(repository_inventory, other))
    assert published.credentials[credential.credential_id] == saved
    assert published.credentials[other.credential_id] == other
    assert list(published.credentials) == [
        credential.credential_id,
        other.credential_id,
    ]


def test_merge_rejects_another_boundary(repository_inventory, credential):
    document = document_for(repository_inventory, credential)
    with pytest.raises(ValueError, match="another boundary"):
        merge_scan(document, document.model_copy(update={"boundary_id": "other"}))


def test_pending_judgment_and_missing_value_accept_candidate_state(
    repository_inventory, credential
):
    previous = document_for(
        repository_inventory, credential.model_copy(update={"credential": None})
    )
    candidate = credential.model_copy(
        update={"judgment": JudgmentResult(verdict="ERROR")}
    )
    published = merge_scan(previous, document_for(repository_inventory, candidate))
    assert published.credentials[credential.credential_id].judgment.verdict == "ERROR"
    assert (
        published.credentials[credential.credential_id].credential
        == credential.credential
    )


@pytest.mark.parametrize("status", ["RETAINED", "ERROR"])
def test_extraction_metadata_has_no_source_fingerprint(status):
    extraction = ExtractionResult(status=status)
    payload = extraction.model_dump(mode="json")
    assert set(payload) == {"status", "output_path", "size", "sha256", "error"}
    assert (
        "source_fingerprint" not in ExtractionResult.model_json_schema()["properties"]
    )
    assert ExtractionResult.model_validate(payload) == extraction
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        ExtractionResult.model_validate({**payload, "source_fingerprint": "obsolete"})
