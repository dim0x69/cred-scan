from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from cred_scan.backend.adapters.artifactory.models import (
    ArtifactoryRepository,
    DockerImageScanScope,
)
from cred_scan.backend.inventory import merge_inventory
from cred_scan.backend.models import (
    ScanTarget,
    ScanTargetInventory,
    target_id_for,
)


def scope(digest: str, *, tags: tuple[str, ...] = ()) -> DockerImageScanScope:
    return DockerImageScanScope(
        image="registry/repository/team/api",
        digest=digest,
        root_digest=digest,
        platform="linux/amd64",
        tags=tags,
        manifest_timestamp=datetime(2026, 1, 1, tzinfo=UTC),
    )


def inventory(*targets: ScanTarget) -> ScanTargetInventory:
    return ScanTargetInventory(
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
        boundary=ArtifactoryRepository(
            id="artifactory:artifactory_docker:repository",
            name="repository",
        ),
        targets=targets,
    )


def test_merge_reuses_result_for_same_immutable_target() -> None:
    previous_scope = scope("sha256:manifest", tags=("old",))
    current = inventory(
        ScanTarget(id=target_id_for(previous_scope), scope=previous_scope)
    )
    current.targets[0].result.status = "scanned"
    refreshed_scope = scope("sha256:manifest", tags=("latest",))
    discovered = inventory(
        ScanTarget(id=target_id_for(refreshed_scope), scope=refreshed_scope)
    )

    merged = merge_inventory(current, discovered)

    assert merged is discovered
    assert merged.targets[0].result is current.targets[0].result
    assert merged.targets[0].scope.tags == ("latest",)


def test_inventory_selects_only_one_version_per_scope() -> None:
    first = scope("sha256:first")
    second = scope("sha256:second")

    with pytest.raises(ValidationError, match="one scan target per scope"):
        inventory(
            ScanTarget(id=target_id_for(first), scope=first),
            ScanTarget(id=target_id_for(second), scope=second),
        )


def test_target_does_not_repeat_document_ownership() -> None:
    selected = scope("sha256:manifest")
    payload = inventory(
        ScanTarget(id=target_id_for(selected), scope=selected)
    ).model_dump(mode="json")

    assert set(payload["targets"][0]) == {"id", "scope", "result"}
