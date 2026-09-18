"""Thin local CLI for manual inventory and append-only boundary scans."""

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
    help="Backend-agnostic credential scanner; inventory is manual and scan is append-only.",
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
    LOGGER.info("starting command=inventory config=%s", config)
    try:
        asyncio.run(run())
    except Exception:
        LOGGER.error("command failed command=inventory config=%s", config)
        raise typer.Exit(1)


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
    LOGGER.info("starting command=judge config=%s", config)
    try:
        asyncio.run(run())
    except Exception:
        LOGGER.error("command failed command=judge config=%s", config)
        raise typer.Exit(1)


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
    LOGGER.info("starting command=scan config=%s", config)
    try:
        asyncio.run(run())
    except Exception:
        LOGGER.error("command failed command=scan config=%s", config)
        raise typer.Exit(1)


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
    LOGGER.info("starting command=extract config=%s", config)
    try:
        asyncio.run(run())
    except Exception:
        LOGGER.error("command failed command=extract config=%s", config)
        raise typer.Exit(1)


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
    LOGGER.info("starting command=run config=%s", config)
    try:
        asyncio.run(execute())
    except Exception:
        LOGGER.error("command failed command=run config=%s", config)
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
