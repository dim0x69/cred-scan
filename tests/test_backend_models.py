"""Model ownership and import-order checks run without loading live services."""

import subprocess
import sys

import pytest

from cred_scan.backend import base_models, models
from cred_scan.backend.adapters.artifactory import models as artifactory_models
from cred_scan.backend.adapters.artifactory import package as package_models
from cred_scan.backend.adapters import ghes as ghes_models


@pytest.mark.parametrize(
    "entry",
    [
        "cred_scan.backend.base_models",
        "cred_scan.backend.adapters.artifactory.models",
        "cred_scan.backend.adapters.artifactory.package",
        "cred_scan.backend.adapters.ghes",
        "cred_scan.backend.models",
        "cred_scan.backend.proto",
        "cred_scan.orch.configuration",
        "cred_scan.orch.execution",
        "cred_scan.common.proto",
        "cred_scan.common.workspace",
    ],
)
def test_schema_imports_are_acyclic_and_do_not_load_adapter_implementations(entry):
    # Each entry must work in a fresh interpreter, not just after pytest imported
    # the aggregate models in conftest. Package initializers must remain inert.
    code = """
import importlib
import importlib.abc
import sys

blocked = {
    'cred_scan.backend.adapters.artifactory.common',
    'cred_scan.backend.adapters.artifactory.docker',
    'cred_scan.orch.runtime', 'cred_scan.orch.inventory',
    'cred_scan.orch.workspace', 'cred_scan.orch.boundary',
    'cred_scan.scan.titus', 'cred_scan.judge.dspy_adapter',
}
class RejectRuntime(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname in blocked:
            raise AssertionError(f'schema import loaded runtime module: {fullname}')
sys.meta_path.insert(0, RejectRuntime())
importlib.import_module(sys.argv[1])
if sys.argv[1] == 'cred_scan.orch.configuration':
    assert 'cred_scan.orch.execution' not in sys.modules
from cred_scan.backend.models import ScanBoundaryInventory, DockerImageScanScope
from cred_scan.backend.adapters.artifactory.models import DockerImageScanScope as OwnedDockerImageScanScope
from cred_scan.orch.models import AppConfig
assert DockerImageScanScope is OwnedDockerImageScanScope
ScanBoundaryInventory.model_json_schema()
AppConfig.model_json_schema()
from cred_scan.orch.execution import BoundaryExecution
BoundaryExecution.model_json_schema()
assert not blocked.intersection(sys.modules)
"""
    subprocess.run([sys.executable, "-B", "-c", code, entry], check=True, timeout=10)


def test_aggregate_exports_the_defining_models_without_copies():
    for name in ("BackendConfig", "ScanBoundary", "ScanScope"):
        value = getattr(models, name)
        assert value is getattr(base_models, name)
        assert value.__module__ == "cred_scan.backend.base_models"
    for name in (
        "ArtifactoryBackendConfig",
        "ArtifactoryRepository",
        "DockerImageScanScope",
    ):
        value = getattr(models, name)
        assert value is getattr(artifactory_models, name)
        assert value.__module__ == "cred_scan.backend.adapters.artifactory.models"
    for name in ("PackageScanScope",):
        value = getattr(models, name)
        assert value is getattr(package_models, name)
        assert value.__module__ == "cred_scan.backend.adapters.artifactory.package"
    for name in ("GitOrganization", "GitRepositoryScanScope"):
        value = getattr(models, name)
        assert value is getattr(ghes_models, name)
        assert value.__module__ == "cred_scan.backend.adapters.ghes"


def test_inventory_roundtrip_uses_provider_models_and_retains_pinned_identity(
    repository_inventory,
):
    payload = repository_inventory.model_dump(mode="json")
    restored = models.ScanBoundaryInventory.model_validate(payload)
    assert restored.model_dump(mode="json") == payload
    assert type(restored.boundary) is artifactory_models.ArtifactoryRepository
    scope = restored.targets[0].scope
    assert type(scope) is artifactory_models.DockerImageScanScope
    assert isinstance(scope, base_models.ScanScope)
    assert restored.targets[0].id == models.target_id_for(scope)
    assert payload["schema_version"] == 8
    assert payload["boundary"]["kind"] == "artifactory"
    assert payload["targets"][0]["scope"]["kind"] == "docker"
