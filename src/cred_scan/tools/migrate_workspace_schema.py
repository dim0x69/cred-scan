"""Offline migration from credentials schema 5, 6, or 7 to schema 8.

Legacy target-grouped locations are flattened into backend occurrences and
obsolete extraction source fingerprints are removed. Evidence integrity data is
kept.

The runtime intentionally rejects old credential documents. This operator-only
utility preflights every boundary and writes only with ``--apply``.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from cred_scan.backend.adapters.artifactory.docker import LayerEvidenceError, parse_provenance
from cred_scan.backend.adapters.artifactory.models import DockerImageScanScope
from cred_scan.backend.models import ScanBoundaryInventory
from cred_scan.scan.models import CredentialsDocument, TitusReport

OLD_CREDENTIALS_SCHEMAS = (5, 6, 7)
CURRENT_CREDENTIALS_SCHEMA = 8


def _read_object(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"{path}: invalid JSON") from error
    if not isinstance(payload, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return payload


def _validate(model: type[Any], payload: dict[str, Any], path: Path) -> Any:
    try:
        return model.model_validate(payload)
    except ValidationError as error:
        raise ValueError(f"{path}: invalid {model.__name__}") from error


def _migrate_credentials(
    path: Path,
    original: dict[str, Any],
) -> dict[str, Any]:
    version = original.get("schema_version")
    if version not in (*OLD_CREDENTIALS_SCHEMAS, CURRENT_CREDENTIALS_SCHEMA):
        raise ValueError(
            f"{path}: expected credentials schema 5, 6, 7, or "
            f"{CURRENT_CREDENTIALS_SCHEMA}, found {version!r}"
        )
    payload = copy.deepcopy(original)
    payload["schema_version"] = CURRENT_CREDENTIALS_SCHEMA
    for credential in payload.get("credentials", {}).values():
        if not isinstance(credential, dict):
            raise ValueError(f"{path}: credential must be an object")
        extraction = credential.get("extraction")
        if version in OLD_CREDENTIALS_SCHEMAS and isinstance(extraction, dict):
            extraction.pop("source_fingerprint", None)
        if version == CURRENT_CREDENTIALS_SCHEMA:
            continue
        flattened: list[dict[str, str]] = []
        for occurrence in credential.get("occurrences", ()):
            if not isinstance(occurrence, dict):
                raise ValueError(f"{path}: occurrence must be an object")
            for location in occurrence.get("locations", ()):
                if not isinstance(location, dict):
                    raise ValueError(f"{path}: location must be an object")
                if version == 5:
                    provenance = location.get("provenance")
                    if not isinstance(provenance, dict):
                        raise ValueError(
                            f"{path}: typed provenance is required for schema 5"
                        )
                    locator = provenance.get("raw_path")
                else:
                    locator = location.get("locator")
                if not isinstance(locator, str) or not locator:
                    raise ValueError(f"{path}: occurrence has no locator")
                flattened.append({"locator": locator})
        credential["occurrences"] = flattened

    document = _validate(CredentialsDocument, payload, path)
    return document.model_dump(mode="json")


def _validate_report_targets(
    report: TitusReport, inventory: ScanBoundaryInventory, path: Path
) -> None:
    targets = inventory.targets
    for finding in report.findings:
        matches = finding.get("Matches", [])
        if not isinstance(matches, list):
            continue
        for match in matches:
            raw_path = match.get("file_path") if isinstance(match, dict) else None
            if not isinstance(raw_path, str):
                continue
            try:
                provenance = parse_provenance(raw_path)
            except LayerEvidenceError:
                continue
            image = f"{provenance.registry}/{provenance.repository}/{provenance.image}"
            candidates = [
                target
                for target in targets
                if isinstance(target.scope, DockerImageScanScope)
                and target.scope.image == image
                and target.scope.digest == provenance.manifest
            ]
            if len(candidates) != 1:
                raise ValueError(
                    f"{path}: report locator does not identify exactly one retained "
                    f"target: {raw_path}"
                )


def _preflight_boundary(inventory_path: Path) -> tuple[Path, dict[str, Any]]:
    boundary_dir = inventory_path.parent
    inventory = _validate(
        ScanBoundaryInventory, _read_object(inventory_path), inventory_path
    )
    report_path = boundary_dir / "report.json"
    credentials_path = boundary_dir / "credentials.json"
    if not report_path.exists():
        # Inventory is published before scanning creates any result documents.
        # Do not let a new boundary block migration of already-scanned ones.
        if not any(
            path.exists()
            for path in (
                credentials_path,
                boundary_dir / "titus.ds",
                boundary_dir / "evidence",
            )
        ):
            return credentials_path, {}
        raise ValueError(f"{report_path}: missing report for existing scan results")
    report = _validate(TitusReport, _read_object(report_path), report_path)
    if report.boundary_id != inventory.boundary.id:
        raise ValueError(f"{report_path}: report boundary does not match inventory")
    _validate_report_targets(report, inventory, report_path)
    if not credentials_path.exists():
        return credentials_path, {}
    original = _read_object(credentials_path)
    if original.get("boundary_id") != inventory.boundary.id:
        raise ValueError(f"{credentials_path}: boundary does not match inventory")
    return credentials_path, _migrate_credentials(credentials_path, original)


def _write_json_atomically(path: Path, payload: dict[str, Any]) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("w", encoding="utf-8") as stream:
            json.dump(payload, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def migrate_workspace(workspace_dir: Path, *, apply: bool = False) -> int:
    """Preflight all boundaries and optionally migrate credentials documents."""
    if not workspace_dir.is_dir():
        raise ValueError(f"{workspace_dir}: workspace directory does not exist")
    pending: list[tuple[Path, dict[str, Any]]] = []
    for inventory_path in sorted(workspace_dir.rglob("inventory.json")):
        credentials_path, payload = _preflight_boundary(inventory_path)
        if payload:
            original = _read_object(credentials_path)
            if original.get("schema_version") in OLD_CREDENTIALS_SCHEMAS:
                pending.append((credentials_path, payload))
    if apply:
        for path, payload in pending:
            _write_json_atomically(path, payload)
    return len(pending)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Migrate credential locations with the scanner stopped."
    )
    parser.add_argument("workspace_dir", type=Path)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    count = migrate_workspace(args.workspace_dir, apply=args.apply)
    action = "would migrate" if not args.apply else "migrated"
    print(f"{action} {count} credential document(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
