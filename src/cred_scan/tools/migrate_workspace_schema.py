"""Offline workspace migration to boundary records and scantargets.json.

Credentials, reports, cumulative Titus datastores, and evidence are untouched.
Original inventory.json files are backed up before replacement.
"""

import argparse
import json
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any, TypeVar
from urllib.parse import quote, unquote

from pydantic import BaseModel

from cred_scan.backend.models import BoundaryRecord, ScanTargetInventory
from cred_scan.orch.fsync import fsync_directory
from cred_scan.orch.locking import boundary_lock
from cred_scan.scan.models import CredentialsDocument, TitusReport

DocumentT = TypeVar("DocumentT", bound=BaseModel)


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
    backend_payload = json.loads(
        (workspace_dir / "backend.json").read_text(encoding="utf-8")
    )
    if not isinstance(backend_payload, dict):
        raise ValueError(f"{workspace_dir / 'backend.json'}: invalid backend marker")
    backend_id = backend_payload.get("name")
    if not isinstance(backend_id, str) or not backend_id:
        raise ValueError(f"{workspace_dir / 'backend.json'}: invalid backend name")
    pending: list[
        tuple[Path, bytes, int, ScanTargetInventory, BoundaryRecord]
    ] = []

    for boundary_path in store.boundaries:
        inventory_path = boundary_path / "inventory.json"
        with boundary_lock(boundary_path / ".operation.lock"):
            for destination in (
                boundary_path / "boundary.json",
                boundary_path / "scantargets.json",
            ):
                if destination.exists():
                    raise ValueError(f"migration destination already exists: {destination}")
            original_bytes = inventory_path.read_bytes()
            original = _payload(inventory_path, {8, 9, 10})
            original_version = original["schema_version"]
            payload = dict(original)
            if original["schema_version"] == 8:
                targets = []
                for target in original["targets"]:
                    if target.get("lifecycle", "current") != "current":
                        continue
                    if target["scope"].get("lifecycle", "active") != "active":
                        continue
                    target = dict(target)
                    target.pop("lifecycle", None)
                    scope = dict(target["scope"])
                    scope.pop("lifecycle", None)
                    scope.pop("pin_id", None)
                    target["scope"] = scope
                    targets.append(target)
                payload["targets"] = targets
            if original_version in {8, 9}:
                payload["publication_pending"] = (
                    boundary_path / "titus.ds"
                ).exists()
            payload["schema_version"] = 11
            payload.pop("lifecycle", None)
            payload.pop("stale_reason", None)
            inventory = _validate(inventory_path, ScanTargetInventory, payload)
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
            record = BoundaryRecord(
                backend_id=backend_id,
                boundary=inventory.boundary,
            )
            pending.append(
                (
                    boundary_path,
                    original_bytes,
                    original_version,
                    inventory,
                    record,
                )
            )

    if apply:
        for (
            boundary_path,
            original_bytes,
            original_version,
            inventory,
            record,
        ) in pending:
            with boundary_lock(boundary_path / ".operation.lock"):
                if (boundary_path / "inventory.json").read_bytes() != original_bytes:
                    raise ValueError(f"inventory changed during migration: {boundary_path}")
                backup = (
                    workspace_dir
                    / f".inventory-v{original_version}-backup"
                    / boundary_path.name
                    / "inventory.json"
                )
                backup.parent.mkdir(parents=True, exist_ok=True)
                with backup.open("xb") as stream:
                    stream.write(original_bytes)
                    stream.flush()
                    os.fsync(stream.fileno())
                fsync_directory(backup.parent)
                store.write(
                    boundary_path / "scantargets.json",
                    inventory,
                    ScanTargetInventory,
                )
                store.write(
                    boundary_path / "boundary.json",
                    record,
                    BoundaryRecord,
                )
                (boundary_path / "inventory.json").unlink()
                fsync_directory(boundary_path)

    return len(pending)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workspace_dir", type=Path)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--apply", action="store_true")
    mode.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    count = migrate_workspace(args.workspace_dir, apply=args.apply)
    action = "migrated" if args.apply else "would migrate"
    print(f"{action} {count} boundary(ies)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
