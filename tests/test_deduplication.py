import asyncio
from datetime import UTC, datetime, timezone
from unittest.mock import AsyncMock

from cred_scan.backend.models import (
    ArtifactoryRepository,
    BackendConfig,
    DockerImageScanScope,
    ContentLocation,
    ScanTargetInventory,
    ScanTarget,
    target_id_for,
)
from cred_scan.scan.credentials import credential_identity, deduplicate_report
from cred_scan.scan.models import ExclusionPolicy, TitusReport


def _resolved(target_id: str, raw_path: str, source_path: str, filename: str):
    return ContentLocation(
        target_id=target_id,
        locator=raw_path,
        source_path=source_path,
        filename=filename,
    )


def target() -> tuple[ScanTargetInventory, ScanTarget]:
    repository = ArtifactoryRepository(
        id="artifactory:primary:docker-local", name="docker-local"
    )
    scope = DockerImageScanScope(
        image="registry/docker-local/team/api",
        digest="sha256:image",
        root_digest="sha256:root",
        platform="linux/amd64",
        manifest_timestamp=datetime.now(timezone.utc),
    )
    scan_target = ScanTarget(
        id=target_id_for(scope),
        backend_id="primary",
        boundary=repository,
        scope=scope,
    )
    return ScanTargetInventory(
        generated_at=datetime.now(UTC),
        backend=BackendConfig(name="primary"),
        boundary=repository,
        targets=(scan_target,),
    ), scan_target


def test_rule_specific_groups_merge_same_value() -> None:
    first = {"RuleID": "np.generic.3", "Groups": ["dXNlcg==", "c2VjcmV0"]}
    second = {"RuleID": "np.generic.8", "Groups": ["bGRhcA==", "dXNlcg==", "c2VjcmV0"]}
    assert credential_identity(first)[0] == credential_identity(second)[0]
    assert credential_identity(first)[1] == "secret"


def test_dedup_uses_backend_resolved_locations_and_path_exclusions() -> None:
    repository, scan_target = target()
    raw_path = "docker://registry/docker-local/team/api@sha256:image/sha256:layer:etc/app:prod.env"
    raw = [
        {
            "ID": "finding-1",
            "RuleID": "np.github.1",
            "Groups": ["c2VjcmV0"],
            "Matches": [
                {"RuleName": "GitHub token", "file_path": raw_path},
                {
                    "RuleName": "GitHub token",
                    "file_path": "docker://registry/docker-local/team/api@sha256:image/sha256:layer:site-packages/pkg.py",
                },
            ],
        }
    ]
    policy = ExclusionPolicy(
        path_file="path-exclusions.list", path_patterns=("site-packages/",)
    )
    resolver = AsyncMock()
    resolver.resolve_location.side_effect = [
        _resolved(scan_target.id, raw_path, "etc/app:prod.env", "app:prod.env"),
        _resolved(
            scan_target.id,
            raw[0]["Matches"][1]["file_path"],
            "site-packages/pkg.py",
            "pkg.py",
        ),
    ]
    report = TitusReport(
        boundary_id=repository.boundary.id,
        generated_at="2026-01-01T00:00:00+00:00",
        findings=tuple(raw),
    )
    document = asyncio.run(deduplicate_report(report, repository, policy, resolver))
    credential = next(iter(document.credentials.values()))
    assert credential.paths == (raw_path,)
    assert credential.occurrences[0].locator == raw_path


def test_dedup_omits_credential_when_all_locations_are_excluded() -> None:
    repository, scan_target = target()
    raw_path = (
        "docker://registry/docker-local/team/api@sha256:image/"
        "sha256:layer:vendor/secret.env"
    )
    report = TitusReport(
        boundary_id=repository.boundary.id,
        generated_at="2026-01-01T00:00:00+00:00",
        findings=(
            {
                "ID": "finding-1",
                "RuleID": "np.github.1",
                "Groups": ["c2VjcmV0"],
                "Matches": [{"file_path": raw_path}],
            },
        ),
    )
    resolver = AsyncMock()
    resolver.resolve_location.return_value = _resolved(
        scan_target.id, raw_path, "vendor/secret.env", "secret.env"
    )
    policy = ExclusionPolicy(
        path_file="path-exclusions.list", path_patterns=("vendor/",)
    )

    document = asyncio.run(deduplicate_report(report, repository, policy, resolver))

    assert document.credentials == {}


def test_dedup_can_exclude_every_credential_and_return_empty_document() -> None:
    repository, scan_target = target()
    paths = (
        "docker://registry/docker-local/team/api@sha256:image/"
        "sha256:layer:vendor/secret.env",
        "docker://registry/docker-local/team/api@sha256:image/"
        "sha256:layer:vendor/token.env",
    )
    report = TitusReport(
        boundary_id=repository.boundary.id,
        generated_at="2026-01-01T00:00:00+00:00",
        findings=tuple(
            {
                "ID": f"finding-{index}",
                "RuleID": "np.github.1",
                "Groups": [value],
                "Matches": [{"file_path": path}],
            }
            for index, (value, path) in enumerate(
                zip(("c2VjcmV0", "dG9rZW4="), paths, strict=True), 1
            )
        ),
    )
    resolver = AsyncMock()
    resolver.resolve_location.side_effect = [
        _resolved(
            scan_target.id,
            path,
            path.rsplit("sha256:layer:", 1)[-1],
            path.rsplit("/", 1)[-1],
        )
        for path in paths
    ]
    policy = ExclusionPolicy(
        path_file="path-exclusions.list", path_patterns=("vendor/",)
    )

    document = asyncio.run(deduplicate_report(report, repository, policy, resolver))

    assert document.credentials == {}


def test_unavailable_locations_remain_raw_and_produce_diagnostics():
    inventory, scan_target = target()
    report = TitusReport(
        boundary_id=inventory.boundary.id,
        generated_at="now",
        findings=(
            {
                "ID": "partly-available",
                "RuleID": "np.github.1",
                "Groups": ["c2VjcmV0"],
                "Matches": [{"file_path": "missing"}, {"file_path": "available"}],
            },
            {
                "ID": "unavailable-only",
                "RuleID": "np.github.1",
                "Groups": ["b3RoZXI="],
                "Matches": [{"file_path": "ambiguous"}],
            },
        ),
    )
    original = report.model_dump_json()
    resolver = AsyncMock()
    resolver.resolve_location.side_effect = [
        ValueError("unknown retained target"),
        _resolved(scan_target.id, "available", "etc/app.env", "app.env"),
        ValueError("ambiguous retained target"),
    ]
    document = asyncio.run(
        deduplicate_report(
            report, inventory, ExclusionPolicy(path_file="paths.list"), resolver
        )
    )
    assert report.model_dump_json() == original
    assert document.incomplete
    assert len(document.credentials) == 1
    credential = next(iter(document.credentials.values()))
    assert credential.paths == ("available",)
    occurrence = credential.occurrences[0]
    assert occurrence.locator == "available"
    assert len(document.errors) == 2
    assert "partly-available" in document.errors[0]
    assert "unavailable-only" in document.errors[1]
    assert all("location unavailable" in error for error in document.errors)
    assert resolver.resolve_location.await_count == 3
