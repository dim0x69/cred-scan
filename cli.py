"""Thin local CLI for manual inventory and append-only boundary scans."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Annotated

import typer

from orch.configuration import YamlConfigLoader
from orch.runtime import LocalRuntime

LOGGER = logging.getLogger(__name__)

app = typer.Typer(
    help="Backend-agnostic credential scanner; inventory is manual and scan is append-only.",
    add_completion=False,
    no_args_is_help=True,
)


def _configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )


def _existing_config(config: Path) -> Path:
    path = config.expanduser().resolve()
    if not path.is_file():
        raise typer.BadParameter(
            f"config file not found: {path}", param_hint="--config"
        )
    return path


@app.command()
def inventory(
    config: Annotated[
        Path, typer.Option("--config", "-c", help="Central configuration file.")
    ] = Path("config.yml"),
) -> None:
    """Manually discover sources, update pins, and mark stale boundaries."""

    async def run() -> None:
        loaded = await YamlConfigLoader().load(config)
        completed = await LocalRuntime(loaded).inventory()
        typer.echo(f"wrote inventory with {completed} report boundary(ies)")

    config = _existing_config(config)
    _configure_logging()
    try:
        asyncio.run(run())
    except Exception as error:
        typer.echo(f"error: {error}", err=True)
        raise typer.Exit(1) from error


@app.command()
def judge(
    config: Annotated[
        Path, typer.Option("--config", "-c", help="Central configuration file.")
    ] = Path("config.yml"),
) -> None:
    """Judge persisted PENDING and ERROR credentials without scanning."""

    async def run() -> None:
        loaded = await YamlConfigLoader().load(config)
        completed = await LocalRuntime(loaded).judge()
        typer.echo(f"judged {completed} credential(s)")

    config = _existing_config(config)
    _configure_logging()
    try:
        asyncio.run(run())
    except Exception as error:
        typer.echo(f"error: {error}", err=True)
        raise typer.Exit(1) from error


@app.command()
def scan(
    config: Annotated[
        Path, typer.Option("--config", "-c", help="Central configuration file.")
    ] = Path("config.yml"),
) -> None:
    """Scan persisted targets, judge findings, and retain evidence."""

    async def run() -> None:
        loaded = await YamlConfigLoader().load(config)
        completed = await LocalRuntime(loaded).scan()
        typer.echo(f"scanned {completed} report boundary(ies)")

    config = _existing_config(config)
    _configure_logging()
    try:
        asyncio.run(run())
    except Exception as error:
        typer.echo(f"error: {error}", err=True)
        raise typer.Exit(1) from error


@app.command()
def extract(
    config: Annotated[
        Path, typer.Option("--config", "-c", help="Central configuration file.")
    ] = Path("config.yml"),
) -> None:
    """Extract first-occurrence evidence for persisted VALID credentials."""

    async def run() -> None:
        loaded = await YamlConfigLoader().load(config)
        completed = await LocalRuntime(loaded).extract()
        typer.echo(f"extracted {completed} credential(s)")

    config = _existing_config(config)
    _configure_logging()
    try:
        asyncio.run(run())
    except Exception as error:
        typer.echo(f"error: {error}", err=True)
        raise typer.Exit(1) from error


@app.command()
def run(
    config: Annotated[
        Path, typer.Option("--config", "-c", help="Central configuration file.")
    ] = Path("config.yml"),
) -> None:
    """Compatibility alias for the complete scan workflow."""

    async def execute() -> None:
        loaded = await YamlConfigLoader().load(config)
        completed = await LocalRuntime(loaded).run()
        typer.echo(f"completed {completed} report boundary(ies)")

    config = _existing_config(config)
    _configure_logging()
    try:
        asyncio.run(execute())
    except Exception as error:
        typer.echo(f"error: {error}", err=True)
        raise typer.Exit(1) from error


if __name__ == "__main__":
    app()
