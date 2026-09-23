"""Offline migration to backend-scoped boundary records and scantargets.json.

Credentials, reports, cumulative Titus datastores, and evidence are preserved.
Original inventory.json files are backed up before replacement.
"""

import argparse
import json
import os
import shutil
from collections.abc import Iterator
from pathlib import Path
from typing import Any, TypeVar
from urllib.parse import quote, unquote

from pydantic import BaseModel

from cred_scan.backend.models import (
    BackendWorkspaceRecord,
    BoundaryRecord,
    ScanTargetInventory,
)
from cred_scan.orch.fsync import fsync_directory
from cred_scan.orch.json_io import write_json_atomic
from cred_scan.orch.locking import boundary_lock
from cred_scan.scan.models import CredentialsDocument, TitusReport

DocumentT = TypeVar("DocumentT", bound=BaseModel)


class _WorkspaceStorage:
    """Minimal path/storage facade for the offline tool; creates no services."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def boundary(self, boundary_id: str) -> Path:
        return self.root / quote(boundary_id, safe="")

    def migrated_boundary(self, backend_name: str, boundary_id: str) -> Path:
        return (
            self.root
            / quote(backend_name, safe="")
            / "boundaries"
            / quote(boundary_id, safe="")
        )

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

    def write(
        self,
        path: Path,
        document: DocumentT,
        model_type: type[DocumentT],
    ) -> None:
        validated = model_type.model_validate(
            document.model_dump(mode="json")
        )
        write_json_atomic(path, validated.model_dump(mode="json"))


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


def _rename_boundary_id(value: str, source_backend: str, target_backend: str) -> str:
    source = f"artifactory:{source_backend}:"
    target = f"artifactory:{target_backend}:"
    return target + value.removeprefix(source) if value.startswith(source) else value


def _migrate_report(
    path: Path,
    source_backend: str,
    target_backend: str,
) -> TitusReport | None:
    if not path.exists():
        return None
    payload = _payload(path, {2})
    payload["boundary_id"] = _rename_boundary_id(
        payload["boundary_id"], source_backend, target_backend
    )
    return _validate(path, TitusReport, payload)


def _migrate_credentials(
    path: Path,
    source_backend: str,
    target_backend: str,
) -> CredentialsDocument | None:
    if not path.exists():
        return None
    payload = _payload(path, {7, 8})
    payload["boundary_id"] = _rename_boundary_id(
        payload["boundary_id"], source_backend, target_backend
    )
    if payload["schema_version"] == 7:
        for credential in payload["credentials"].values():
            locations = []
            for occurrence in credential["occurrences"]:
                locations.extend(
                    {"locator": location["locator"]}
                    for location in occurrence["locations"]
                )
            credential["occurrences"] = locations
        payload["schema_version"] = 8
    return _validate(path, CredentialsDocument, payload)


def migrate_workspace(workspace_dir: Path, *, apply: bool = False) -> int:
    """Migrate the legacy flat workspace; dry-run by default."""
    if not workspace_dir.is_dir():
        raise ValueError(
            f"{workspace_dir}: workspace directory does not exist"
        )

    marker = workspace_dir / "backend.json"
    store = _WorkspaceStorage(workspace_dir)
    if marker.exists():
        backend_payload = json.loads(marker.read_text(encoding="utf-8"))
        if not isinstance(backend_payload, dict):
            raise ValueError(f"{marker}: invalid backend marker")
        source_backend = backend_payload.get("name")
        if not isinstance(source_backend, str) or not source_backend:
            raise ValueError(f"{marker}: invalid backend name")
        target_backend = source_backend
    else:
        # The existing single workspace predates the backend marker. Infer its
        # source identity from the legacy inventory documents. This is a
        # one-workspace migration, not a general compatibility mechanism.
        legacy_paths = tuple(workspace_dir.glob("*/inventory.json"))
        if not legacy_paths and tuple(workspace_dir.glob("*/backend.json")):
            return 0
        if not legacy_paths:
            raise ValueError(f"missing legacy backend marker: {marker}")
        source_names = {
            json.loads(path.read_text(encoding="utf-8"))["backend"]["name"]
            for path in legacy_paths
        }
        if len(source_names) != 1:
            raise ValueError("legacy workspace contains multiple backend identities")
        source_backend = source_names.pop()
        target_backend = (
            "artifactory_docker"
            if source_backend == "artifactory-primary"
            else source_backend
        )
    pending: list[
        tuple[
            Path,
            Path,
            bytes,
            int,
            ScanTargetInventory,
            BoundaryRecord,
            TitusReport | None,
            CredentialsDocument | None,
        ]
    ] = []

    for boundary_path in store.boundaries:
        inventory_path = boundary_path / "inventory.json"
        source_boundary_id = unquote(boundary_path.name)
        target_boundary_id = _rename_boundary_id(
            source_boundary_id,
            source_backend,
            target_backend,
        )
        destination = store.migrated_boundary(
            target_backend,
            target_boundary_id,
        )
        if destination.exists():
            raise ValueError(f"migration destination already exists: {destination}")
        with boundary_lock(boundary_path / ".operation.lock"):
            original_bytes = inventory_path.read_bytes()
            original = _payload(inventory_path, {7, 8, 9, 10})
            original_version = original["schema_version"]
            payload = dict(original)
            if original["schema_version"] in {7, 8}:
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
            if original_version in {7, 8, 9}:
                payload["publication_pending"] = (
                    boundary_path / "titus.ds"
                ).exists()
            if boundary_path.name != quote(source_boundary_id, safe=""):
                raise ValueError(
                    f"{inventory_path}: boundary directory does not match inventory"
                )
            payload["schema_version"] = 11
            payload.pop("lifecycle", None)
            payload.pop("stale_reason", None)
            boundary_payload = dict(payload["boundary"])
            boundary_payload["id"] = target_boundary_id
            payload["boundary"] = boundary_payload
            inventory = _validate(inventory_path, ScanTargetInventory, payload)
            report = _migrate_report(
                boundary_path / "report.json",
                source_backend,
                target_backend,
            )
            credentials = _migrate_credentials(
                boundary_path / "credentials.json",
                source_backend,
                target_backend,
            )
            record = BoundaryRecord(
                backend_id=target_backend,
                boundary=inventory.boundary,
            )
            pending.append(
                (
                    boundary_path,
                    destination,
                    original_bytes,
                    original_version,
                    inventory,
                    record,
                    report,
                    credentials,
                )
            )

    if apply:
        backend_dir = workspace_dir / quote(target_backend, safe="")
        backend_dir.mkdir(parents=True, exist_ok=True)
        for (
            boundary_path,
            destination,
            original_bytes,
            original_version,
            inventory,
            record,
            report,
            credentials,
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
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(boundary_path), str(destination))
                store.write(
                    destination / "scantargets.json",
                    inventory,
                    ScanTargetInventory,
                )
                store.write(
                    destination / "boundary.json",
                    record,
                    BoundaryRecord,
                )
                if report is not None:
                    store.write(destination / "report.json", report, TitusReport)
                if credentials is not None:
                    store.write(
                        destination / "credentials.json",
                        credentials,
                        CredentialsDocument,
                    )
                (destination / "inventory.json").unlink()
                fsync_directory(destination)

        store.write(
            backend_dir / "backend.json",
            BackendWorkspaceRecord(name=target_backend),
            BackendWorkspaceRecord,
        )
        if marker.exists():
            marker.unlink()
        fsync_directory(workspace_dir)

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
