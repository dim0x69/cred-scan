"""Thin local CLI for one-boundary operations."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Annotated

import typer

from cred_scan.orch.configuration import YamlConfigLoader
from cred_scan.orch.runtime import LocalRuntime

LOGGER = logging.getLogger(__name__)

app = typer.Typer(
    help="Backend-agnostic credential scanner; each command operates on one boundary.",
    add_completion=False,
    no_args_is_help=True,
)


def _configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )


def _existing_config(config: Path) -> Path:
    path = config.expanduser().resolve()
    if not path.is_file():
        raise typer.BadParameter(
            f"config file not found: {path}", param_hint="--config"
        )
    return path


def _run_command(
    command: str,
    boundary_id: str | None,
    config: Path,
    message: str,
    operation: str,
) -> None:
    async def run() -> None:
        loaded = await YamlConfigLoader().load(config)
        result = await getattr(LocalRuntime(loaded), operation)(boundary_id)
        if result is None:
            typer.echo(message.format(boundary_id=boundary_id))
        else:
            typer.echo(message.format(boundary_id=boundary_id, count=result))

    config = _existing_config(config)
    _configure_logging()
    LOGGER.info(
        "starting command=%s boundary=%s config=%s",
        command,
        boundary_id or "<next>",
        config,
    )
    try:
        asyncio.run(run())
    except Exception:
        LOGGER.error(
            "command failed command=%s boundary=%s config=%s",
            command,
            boundary_id or "<next>",
            config,
        )
        raise typer.Exit(1)


@app.command()
def inventory(
    boundary_id: Annotated[str, typer.Argument(help="Report boundary identifier.")],
    config: Annotated[
        Path, typer.Option("--config", "-c", help="Central configuration file.")
    ] = Path("config.yml"),
) -> None:
    """Refresh the inventory for one report boundary."""
    _run_command(
        "inventory",
        boundary_id,
        config,
        "refreshed inventory for {boundary_id}",
        "inventory",
    )


@app.command()
def scan(
    boundary_id: Annotated[
        str | None,
        typer.Argument(help="Boundary identifier; omit to select the next boundary."),
    ] = None,
    config: Annotated[
        Path, typer.Option("--config", "-c", help="Central configuration file.")
    ] = Path("config.yml"),
) -> None:
    """Scan pending targets for one report boundary."""
    _run_command(
        "scan",
        boundary_id,
        config,
        "scanned {count} boundary(ies)",
        "scan",
    )


@app.command()
def judge(
    boundary_id: Annotated[
        str | None,
        typer.Argument(help="Boundary identifier; omit to select the next boundary."),
    ] = None,
    config: Annotated[
        Path, typer.Option("--config", "-c", help="Central configuration file.")
    ] = Path("config.yml"),
) -> None:
    """Judge saved PENDING or ERROR credentials for one boundary."""
    _run_command(
        "judge",
        boundary_id,
        config,
        "judged {count} credential(s)",
        "judge",
    )


@app.command()
def extract(
    boundary_id: Annotated[
        str | None,
        typer.Argument(help="Boundary identifier; omit to select the next boundary."),
    ] = None,
    config: Annotated[
        Path, typer.Option("--config", "-c", help="Central configuration file.")
    ] = Path("config.yml"),
) -> None:
    """Extract evidence for VALID credentials in one boundary."""
    _run_command(
        "extract",
        boundary_id,
        config,
        "extracted {count} credential(s)",
        "extract",
    )


if __name__ == "__main__":
    app()
