from unittest.mock import AsyncMock, Mock

import pytest
from typer.testing import CliRunner

import cli
from orch.models import AppConfig


@pytest.mark.parametrize(
    "arguments",
    [
        ["--help"],
        ["inventory", "--help"],
        ["scan", "--help"],
        ["judge", "--help"],
        ["extract", "--help"],
        ["run", "--help"],
    ],
)
def test_help_does_not_load_configuration_or_start_runtime(
    monkeypatch, arguments
) -> None:
    loader = Mock(side_effect=AssertionError("help must not load configuration"))
    runtime = Mock(side_effect=AssertionError("help must not start runtime"))
    monkeypatch.setattr(cli, "YamlConfigLoader", loader)
    monkeypatch.setattr(cli, "LocalRuntime", runtime)

    result = CliRunner().invoke(cli.app, arguments)

    assert result.exit_code == 0
    loader.assert_not_called()
    runtime.assert_not_called()


def test_missing_config_is_rejected(tmp_path) -> None:
    result = CliRunner().invoke(
        cli.app, ["inventory", "--config", str(tmp_path / "missing.yml")]
    )

    assert result.exit_code != 0
    assert "config file not found" in result.output


def test_inventory_command_displays_returned_count(
    monkeypatch, app_config: AppConfig
) -> None:
    loader = Mock(load=AsyncMock(return_value=app_config))
    runtime = Mock(inventory=AsyncMock(return_value=2))
    monkeypatch.setattr(cli, "YamlConfigLoader", Mock(return_value=loader))
    runtime_constructor = Mock(return_value=runtime)
    monkeypatch.setattr(cli, "LocalRuntime", runtime_constructor)

    result = CliRunner().invoke(cli.app, ["inventory"])

    assert result.exit_code == 0
    assert "wrote inventory with 2 report boundary(ies)" in result.output
    runtime_constructor.assert_called_once_with(app_config)
    runtime.inventory.assert_awaited_once()


def test_judge_command_displays_returned_count(
    monkeypatch, app_config: AppConfig
) -> None:
    loader = Mock(load=AsyncMock(return_value=app_config))
    runtime = Mock(judge=AsyncMock(return_value=3))
    monkeypatch.setattr(cli, "YamlConfigLoader", Mock(return_value=loader))
    runtime_constructor = Mock(return_value=runtime)
    monkeypatch.setattr(cli, "LocalRuntime", runtime_constructor)

    result = CliRunner().invoke(cli.app, ["judge"])

    assert result.exit_code == 0
    assert "judged 3 credential(s)" in result.output
    runtime_constructor.assert_called_once_with(app_config)
    runtime.judge.assert_awaited_once()


def test_scan_command_displays_returned_count(
    monkeypatch, app_config: AppConfig
) -> None:
    loader = Mock(load=AsyncMock(return_value=app_config))
    runtime = Mock(scan=AsyncMock(return_value=2))
    monkeypatch.setattr(cli, "YamlConfigLoader", Mock(return_value=loader))
    runtime_constructor = Mock(return_value=runtime)
    monkeypatch.setattr(cli, "LocalRuntime", runtime_constructor)

    result = CliRunner().invoke(cli.app, ["scan"])

    assert result.exit_code == 0
    assert "scanned 2 report boundary(ies)" in result.output
    runtime_constructor.assert_called_once_with(app_config)
    runtime.scan.assert_awaited_once()


def test_extract_command_displays_returned_count(
    monkeypatch, app_config: AppConfig
) -> None:
    loader = Mock(load=AsyncMock(return_value=app_config))
    runtime = Mock(extract=AsyncMock(return_value=4))
    monkeypatch.setattr(cli, "YamlConfigLoader", Mock(return_value=loader))
    runtime_constructor = Mock(return_value=runtime)
    monkeypatch.setattr(cli, "LocalRuntime", runtime_constructor)

    result = CliRunner().invoke(cli.app, ["extract"])

    assert result.exit_code == 0
    assert "extracted 4 credential(s)" in result.output
    runtime_constructor.assert_called_once_with(app_config)
    runtime.extract.assert_awaited_once()


def test_run_command_displays_returned_count(
    monkeypatch, app_config: AppConfig
) -> None:
    loader = Mock(load=AsyncMock(return_value=app_config))
    runtime = Mock(run=AsyncMock(return_value=2))
    monkeypatch.setattr(cli, "YamlConfigLoader", Mock(return_value=loader))
    runtime_constructor = Mock(return_value=runtime)
    monkeypatch.setattr(cli, "LocalRuntime", runtime_constructor)

    result = CliRunner().invoke(cli.app, ["run"])

    assert result.exit_code == 0
    assert "completed 2 report boundary(ies)" in result.output
    runtime_constructor.assert_called_once_with(app_config)
    runtime.run.assert_awaited_once()
