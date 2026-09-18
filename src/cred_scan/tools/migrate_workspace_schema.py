"""Offline inventory 7 -> 8 upgrade.

The tool only validates and upgrades inventory documents. Runtime commands use
inventory, report, and credential checkpoints directly; no execution checkpoint
or scheduler state is required.
"""

import argparse
import json
import os
from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from pathlib import Path
from typing import Any, TypeVar
from urllib.parse import quote, unquote

from pydantic import BaseModel

from cred_scan.backend.models import ScanBoundaryInventory
from cred_scan.common.fsync import fsync_directory
from cred_scan.scan.models import CredentialsDocument, TitusReport

DocumentT = TypeVar("DocumentT", bound=BaseModel)


@contextmanager
def _boundary_lock(path: Path) -> Iterator[None]:
    """Own one boundary using the same sentinel convention as Boundary."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        stream.write("locked\n")

    try:
        yield
    finally:
        path.unlink(missing_ok=True)


class _WorkspaceStorage:
    """Minimal path/storage facade for the offline tool; creates no services."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def boundary(self, boundary_id: str) -> Path:
        return self.root / quote(boundary_id, safe="")

    @property
    def boundaries(self) -> Iterator[Path]:
        for inventory_path in sorted(
            self.root.glob("*/inventory.json"),
            key=lambda path: unquote(path.parent.name),
        ):
            boundary_path = self.boundary(unquote(inventory_path.parent.name))
            if boundary_path / "inventory.json" != inventory_path:
                raise ValueError(
                    f"noncanonical boundary directory: {inventory_path.parent}"
                )
            yield boundary_path

    def lock(self, boundary_path: Path) -> AbstractContextManager[None]:
        return _boundary_lock(boundary_path / ".operation.lock")

    def read(
        self,
        path: Path,
        model_type: type[DocumentT],
    ) -> DocumentT | None:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        return model_type.model_validate(payload)

    def write(
        self,
        path: Path,
        document: DocumentT,
        model_type: type[DocumentT],
    ) -> None:
        validated = model_type.model_validate(
            document.model_dump(mode="json")
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        try:
            with temporary.open("w", encoding="utf-8") as stream:
                json.dump(
                    validated.model_dump(mode="json"),
                    stream,
                    indent=2,
                    sort_keys=True,
                )
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            temporary.replace(path)
            fsync_directory(path.parent)
        finally:
            temporary.unlink(missing_ok=True)


def _payload(path: Path, versions: set[int]) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("schema_version") not in versions:
        raise ValueError(
            f"{path}: expected schema version in {sorted(versions)}"
        )
    return value


def _validate(
    path: Path,
    model: type[DocumentT],
    payload: dict[str, Any],
) -> DocumentT:
    try:
        return model.model_validate(payload)
    except ValueError:
        raise ValueError(f"{path}: invalid {model.__name__}") from None


def _optional(
    path: Path,
    version: int,
    model: type[DocumentT],
) -> DocumentT | None:
    if not path.exists():
        return None
    return _validate(path, model, _payload(path, {version}))


def migrate_workspace(workspace_dir: Path, *, apply: bool = False) -> int:
    """Preflight each boundary under its own lock; dry-run by default."""
    if not workspace_dir.is_dir():
        raise ValueError(
            f"{workspace_dir}: workspace directory does not exist"
        )

    store = _WorkspaceStorage(workspace_dir)
    pending: list[tuple[Path, ScanBoundaryInventory]] = []

    for boundary_path in store.boundaries:
        inventory_path = boundary_path / "inventory.json"
        with store.lock(boundary_path):
            original = _payload(inventory_path, {7, 8})
            inventory = _validate(
                inventory_path,
                ScanBoundaryInventory,
                {**original, "schema_version": 8},
            )
            if boundary_path.name != quote(inventory.boundary.id, safe=""):
                raise ValueError(
                    f"{inventory_path}: boundary directory does not match inventory"
                )
            _optional(boundary_path / "report.json", 2, TitusReport)
            _optional(
                boundary_path / "credentials.json",
                8,
                CredentialsDocument,
            )
            if original["schema_version"] == 7:
                pending.append((boundary_path, inventory))

    if apply:
        for boundary_path, inventory in pending:
            with store.lock(boundary_path):
                store.write(
                    boundary_path / "inventory.json",
                    inventory,
                    ScanBoundaryInventory,
                )

    return len(pending)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workspace_dir", type=Path)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--apply", action="store_true")
    mode.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    count = migrate_workspace(args.workspace_dir, apply=args.apply)
    action = "upgraded" if args.apply else "would upgrade"
    print(f"{action} {count} boundary(ies)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
