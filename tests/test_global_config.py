"""Services consume the resolved configuration and share exclusions per run."""

import asyncio
from unittest.mock import AsyncMock, Mock

import pytest

from cred_scan.orch import global_config
from cred_scan.orch.models import AppConfig, TitusConfig, WorkspaceConfig
from cred_scan.orch.runtime import LocalRuntime
from cred_scan.orch.workspace import Workspace, load_configured_backend
from cred_scan.judge.dspy_adapter import DspyFindingJudge
from cred_scan.backend.models import ContentLocation
from cred_scan.scan.credentials import deduplicate_report
from cred_scan.scan import titus
from cred_scan.scan.models import ExclusionFiles, TitusReport
from cred_scan.scan.titus import TitusCliScanner


@pytest.fixture
def resolved_config(tmp_path, monkeypatch):
    monkeypatch.setattr(global_config, "CONFIG", None)
    monkeypatch.setattr(global_config, "_EXCLUSIONS", None)
    paths = tmp_path / "paths.list"
    credentials = tmp_path / "credentials.list"
    paths.write_text("*.lock\n")
    credentials.write_text("synthetic\n")
    return AppConfig(
        workspace=WorkspaceConfig(workspace_dir=tmp_path / "workspace"),
        titus=TitusConfig(executable="synthetic-titus"),
        exclusions=ExclusionFiles(paths=paths, credentials=credentials),
        backends=({"name": "artifactory_docker", "base_url": "https://example.invalid"},),
        artifactory_access_token="synthetic-token",
        azure_openai_api_key="synthetic-judge-token",
        judge={"base_url": "https://example.invalid/azure"},
    )


def test_configuration_must_be_installed_before_use(resolved_config):
    with pytest.raises(RuntimeError, match="has not been loaded"):
        global_config.get_config()


def test_exclusions_load_lazily_once_and_reload_for_next_run(resolved_config):
    LocalRuntime(resolved_config)
    resolved_config.exclusions.paths.write_text("*.env\n")
    first = global_config.get_exclusions()
    assert first.path_patterns == ("*.env",)
    resolved_config.exclusions.paths.write_text("*.txt\n")
    assert global_config.get_exclusions() is first
    assert first.path_patterns == ("*.env",)

    LocalRuntime(resolved_config)
    second = global_config.get_exclusions()
    assert second is not first
    assert second.path_patterns == ("*.txt",)


def test_services_read_global_settings_and_secrets(resolved_config):
    LocalRuntime(resolved_config)
    workspace = Workspace(
        load_configured_backend("artifactory_docker"),
        resolved_config.workspace.workspace_dir / "artifactory_docker",
        create=True,
    )
    try:
        assert workspace.workspace_dir == resolved_config.workspace.workspace_dir
        assert workspace.backend.session.headers["Authorization"] == (
            "Bearer synthetic-token"
        )
        judge = DspyFindingJudge()
        assert judge.model == resolved_config.judge.model
        assert judge._configuration()[0] == "synthetic-judge-token"
        scanner = TitusCliScanner(Mock(), workspace.backend)
        assert scanner.config is resolved_config.titus
        assert scanner.environment["ARTIFACTORY_API_KEY"] == "synthetic-token"
    finally:
        asyncio.run(workspace.close())


def test_deduplicator_loads_exclusions_without_policy_argument(resolved_config):
    LocalRuntime(resolved_config)
    inventory = Mock(errors=())
    inventory.boundary.id = "repository"
    resolver = Mock()
    resolver.resolve_location = AsyncMock(
        side_effect=lambda path: ContentLocation(
            locator=path, source_path=path, filename=path
        )
    )
    report = TitusReport(
        boundary_id="repository",
        generated_at="now",
        findings=(
            {"RuleID": "np.github.1", "Groups": ["c2VjcmV0"],
             "Matches": [{"file_path": "app.env"}, {"file_path": "app.lock"}]},
            {"RuleID": "np.github.1", "Groups": ["c3ludGhldGlj"],
             "Matches": [{"file_path": "excluded.env"}]},
        ),
    )
    document = asyncio.run(deduplicate_report(report, inventory, resolver))
    assert len(document.credentials) == 1
    credential = next(iter(document.credentials.values()))
    assert credential.credential == "secret"
    assert tuple(item.locator for item in credential.occurrences) == ("app.env",)


def test_titus_loads_exclusions_without_policy_argument(
    resolved_config, tmp_path, monkeypatch
):
    LocalRuntime(resolved_config)
    backend = Mock()
    backend.titus_scan_arguments.return_value = ("--docker", "synthetic-image")
    scanner = TitusCliScanner(Mock(), backend)
    spawn = AsyncMock(side_effect=OSError("synthetic spawn failure"))
    monkeypatch.setattr(titus, "_spawn", spawn)
    asyncio.run(scanner.scan(Mock(), tmp_path, tmp_path / "titus.ds"))
    command = spawn.call_args.args
    assert command[command.index("--ignore") + 1] == str(
        resolved_config.exclusions.paths
    )
