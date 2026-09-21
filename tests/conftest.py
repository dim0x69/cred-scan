from datetime import UTC, datetime
from pathlib import Path

import pytest

from cred_scan.backend.models import (
    ArtifactoryBackendConfig,
    ArtifactoryRepository,
    BackendConfig,
    DockerImageScanScope,
    ScanTargetInventory,
    ScanTarget,
    target_id_for,
)
from cred_scan.orch.models import AppConfig, TitusConfig, WorkspaceConfig
from cred_scan.scan.models import Credential, CredentialOccurrence, ExclusionFiles


@pytest.fixture(autouse=True)
def isolate_credentials(monkeypatch) -> None:
    monkeypatch.delenv("ARTIFACTORY_ACCESS_TOKEN", raising=False)
    monkeypatch.delenv("AZURE_OPENAI_API_KEY", raising=False)


@pytest.fixture
def repository_inventory() -> ScanTargetInventory:
    repository = ArtifactoryRepository(
        id="artifactory:primary:docker-local", name="docker-local"
    )
    scope = DockerImageScanScope(
        image="registry/docker-local/team/api",
        digest="sha256:manifest",
        root_digest="sha256:root",
        platform="linux/amd64",
        manifest_timestamp=datetime(2026, 1, 1, tzinfo=UTC),
    )
    target = ScanTarget(
        id=target_id_for(scope),
        backend_id="primary",
        boundary=repository,
        scope=scope,
    )
    return ScanTargetInventory(
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
        backend=BackendConfig(name="primary"),
        boundary=repository,
        targets=(target,),
    )


@pytest.fixture
def credential(repository_inventory: ScanTargetInventory) -> Credential:
    locator = (
        "docker://registry/docker-local/team/api@sha256:manifest/"
        "sha256:layer:etc/app.env"
    )
    return Credential(
        credential_id="synthetic-credential",
        credential="SYNTHETIC_VALUE",
        occurrences=(CredentialOccurrence(locator=locator),),
    )


@pytest.fixture
def app_config(tmp_path: Path) -> AppConfig:
    return AppConfig(
        workspace=WorkspaceConfig.model_validate({"workspace-dir": tmp_path}),
        titus=TitusConfig(executable="unused-titus"),
        exclusions=ExclusionFiles(
            paths=tmp_path / "paths.list", credentials=tmp_path / "values.list"
        ),
        backend=ArtifactoryBackendConfig(
            name="primary", base_url="https://example.invalid/artifactory"
        ),
    )
