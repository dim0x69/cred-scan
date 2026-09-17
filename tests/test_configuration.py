import asyncio
import os
from pathlib import Path

import pytest

from cred_scan.orch.configuration import YamlConfigLoader


def test_configuration_resolves_backend_and_exclusion_paths(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yml"
    config_path.write_text(
        """
workspace:
  workspace-dir: workspace
  results-dir: workspace/results
titus:
  executable: titus
exclusions:
  paths: path-exclusions.list
  credentials: cred-value-exclusions.list
backends:
  - name: primary
    kind: artifactory
    base_url: https://example/artifactory
    platform: linux/amd64
""",
        encoding="utf-8",
    )
    config = asyncio.run(YamlConfigLoader().load(config_path))
    assert config.backends[0].name == "primary"
    assert config.workspace.workspace_dir == (tmp_path / "workspace").resolve()
    assert config.workspace.results_dir == (tmp_path / "workspace/results").resolve()
    assert config.exclusions.paths == (tmp_path / "path-exclusions.list").resolve()
    assert config.artifactory_api_key is None


def test_configuration_uses_process_credentials_before_dotenv_without_mutation(
    tmp_path: Path, monkeypatch
) -> None:
    config_path = tmp_path / "config.yml"
    config_path.write_text(
        """
workspace:
  workspace-dir: workspace
  results-dir: workspace/results
titus:
  executable: titus
exclusions:
  paths: path-exclusions.list
  credentials: cred-value-exclusions.list
backends:
  - name: primary
    kind: artifactory
    base_url: https://example/artifactory
""",
        encoding="utf-8",
    )
    (tmp_path / ".env").write_text(
        "ARTIFACTORY_API_KEY=from-dotenv\nAZURE_OPENAI_API_KEY=judge-dotenv\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ARTIFACTORY_API_KEY", "from-process")
    monkeypatch.delenv("AZURE_OPENAI_API_KEY", raising=False)
    before = dict(os.environ)

    config = asyncio.run(YamlConfigLoader().load(config_path))

    assert config.artifactory_api_key is not None
    assert config.azure_openai_api_key is not None
    assert config.artifactory_api_key == "from-process"
    assert config.azure_openai_api_key == "judge-dotenv"
    assert config.titus.executable == str((tmp_path / "titus").resolve())
    assert dict(os.environ) == before


@pytest.mark.parametrize("absolute_workspace", [False, True])
@pytest.mark.parametrize("override", [None, "other-results", "/tmp/cred-scan-results"])
def test_results_root_default_and_override_are_config_relative(
    tmp_path: Path, monkeypatch, absolute_workspace: bool, override: str | None
) -> None:
    config_dir = tmp_path / "settings"
    config_dir.mkdir()
    workspace = tmp_path / "custom-workspace" if absolute_workspace else Path("custom")
    results_setting = f"  results-dir: {override}\n" if override is not None else ""
    config_path = config_dir / "config.yml"
    config_path.write_text(
        f"workspace:\n  workspace-dir: {workspace}\n{results_setting}"
        "titus:\n  executable: ./titus\n"
        "exclusions:\n  paths: paths.list\n  credentials: values.list\n"
        "backends: []\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    config = asyncio.run(YamlConfigLoader().load(config_path))

    expected_workspace = (config_dir / workspace).resolve()
    expected_results = (
        (config_dir / override).resolve()
        if override is not None
        else expected_workspace
    )
    assert config.workspace.workspace_dir == expected_workspace
    assert config.workspace.results_dir == expected_results
