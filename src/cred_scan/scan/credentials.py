"""Titus report conversion and source-neutral credential deduplication."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import UTC, datetime
from typing import Any
from urllib.parse import unquote, urlsplit

from pathspec import PathSpec

from cred_scan.backend.models import ScanBoundaryInventory
from cred_scan.backend.proto import ContentReader
from cred_scan.scan.exclusions import match_credential_exclusion
from cred_scan.scan.models import Credential, CredentialsDocument, ExclusionPolicy, TitusReport

IDENTITY_GROUPS: dict[str, int] = {
    "kingfisher.credentials.1": 1,
    "kingfisher.curl.1": 1,
    "np.generic.3": 1,
    "np.generic.8": 2,
    "np.mongodb.1": 1,
    "np.netrc.1": 2,
    "np.odbc.1": 1,
}
NON_CREDENTIAL_RULES = frozenset({"kingfisher.coveralls.1"})


def decode_json_bytes(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    try:
        return base64.b64decode(value, validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return value


def decoded_groups(finding: dict[str, Any]) -> list[Any]:
    groups = finding.get("Groups", [])
    return [decode_json_bytes(group) for group in groups] if isinstance(groups, list) else []


def _canonical_identity_bytes(value: str) -> bytes:
    normalized = value.strip()
    if normalized.startswith("openssh-key-v1"):
        return b"binary:" + normalized.encode()
    if "BEGIN " in normalized:
        body = re.sub(r"-----BEGIN [^-]+-----|-----END [^-]+-----", "", normalized)
        normalized = "".join(body.split())
        try:
            return b"binary:" + base64.b64decode(normalized, validate=True)
        except (ValueError, UnicodeDecodeError):
            return f"text:{normalized}".encode()
    try:
        decoded = base64.b64decode("".join(normalized.split()), validate=True)
    except (ValueError, UnicodeDecodeError):
        return f"text:{normalized}".encode()
    if decoded.startswith(b"openssh-key-v1"):
        return b"binary:" + decoded
    return f"text:{normalized}".encode()


def _hash_identity(value: str) -> str:
    return hashlib.sha256(_canonical_identity_bytes(value)).hexdigest()


def credential_identity(finding: dict[str, Any]) -> tuple[str, str | None]:
    rule_id = str(finding.get("RuleID", "unknown"))
    groups = decoded_groups(finding)
    index = IDENTITY_GROUPS.get(rule_id)
    if index is not None and index < len(groups):
        value = groups[index]
        if isinstance(value, str) and value:
            return _hash_identity(value), value
    matches = finding.get("Matches", [])
    if isinstance(matches, list):
        for match in matches:
            named = match.get("NamedGroups") if isinstance(match, dict) else None
            if not isinstance(named, dict):
                continue
            for name in ("secret", "token", "password", "api_key", "key", "credential"):
                value = decode_json_bytes(named.get(name))
                if isinstance(value, str) and value:
                    return _hash_identity(value), value
    if rule_id == "kingfisher.uri.1" and groups and isinstance(groups[0], str):
        try:
            password = urlsplit(groups[0]).password
        except ValueError:
            password = None
        if password:
            return _hash_identity(unquote(password)), unquote(password)
    if len(groups) == 1 and isinstance(groups[0], str) and groups[0]:
        return _hash_identity(groups[0]), groups[0]
    finding_id = finding.get("ID")
    if finding_id:
        return str(finding_id), None
    fallback = json.dumps(
        {"RuleID": rule_id, "Groups": finding.get("Groups", [])},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(fallback.encode()).hexdigest(), None


def _path_spec(policy: ExclusionPolicy) -> PathSpec:
    return PathSpec.from_lines("gitwildmatch", policy.path_patterns)


def report_from_export(
    raw_report: list[dict[str, Any]],
    inventory: ScanBoundaryInventory,
    *,
    incomplete: bool = False,
    errors: tuple[str, ...] = (),
) -> TitusReport:
    return TitusReport(
        boundary_id=inventory.boundary.id,
        generated_at=datetime.now(UTC).isoformat(),
        incomplete=incomplete,
        errors=tuple(errors) + inventory.errors,
        findings=tuple(item for item in raw_report if isinstance(item, dict)),
    )


async def deduplicate_report(
    report: TitusReport,
    inventory: ScanBoundaryInventory,
    policy: ExclusionPolicy,
    resolver: ContentReader,
) -> CredentialsDocument:
    """Resolve all raw locations before producing persisted credentials."""
    if report.boundary_id != inventory.boundary.id:
        raise ValueError(f"report boundary is not in inventory: {report.boundary_id}")
    spec = _path_spec(policy)
    conversion_errors: list[str] = []
    grouped: dict[str, dict[str, Any]] = {}
    for finding in report.findings:
        rule_id = str(finding.get("RuleID", "unknown"))
        if rule_id in NON_CREDENTIAL_RULES:
            continue
        credential_id, value = credential_identity(finding)
        item = grouped.setdefault(
            credential_id,
            {
                "credential_id": credential_id,
                "credential": value,
                "occurrences": [],
            },
        )
        if item["credential"] is None and value is not None:
            item["credential"] = value
        matches = finding.get("Matches", [])
        matches = matches if isinstance(matches, list) else []
        for match in matches:
            if not isinstance(match, dict) or not match.get("file_path"):
                continue
            raw_path = str(match["file_path"])
            try:
                resolved = await resolver.resolve_location(raw_path)
            except Exception as error:
                finding_id = str(finding.get("ID", "<unknown>"))
                conversion_errors.append(
                    f"finding {finding_id} location unavailable: "
                    f"{type(error).__name__}: {error}"
                )
                continue
            if spec.match_file(resolved.source_path):
                continue
            if not any(
                occurrence["locator"] == resolved.locator
                for occurrence in item["occurrences"]
            ):
                item["occurrences"].append({"locator": resolved.locator})

    active: dict[str, Credential] = {}
    for credential_id, raw in grouped.items():
        # A group can have no surviving locations when path exclusions
        # remove every resolved occurrence. It is not an active candidate,
        # and must not be passed to Credential, whose occurrence invariant
        # intentionally remains strict.
        if not raw["occurrences"]:
            continue
        credential = Credential.model_validate(raw)
        if match_credential_exclusion(policy, credential.credential or "") is None:
            active[credential_id] = credential
    return CredentialsDocument(
        boundary_id=inventory.boundary.id,
        report_generated_at=report.generated_at,
        incomplete=report.incomplete or bool(conversion_errors),
        credentials=active,
        errors=tuple(report.errors) + inventory.errors + tuple(conversion_errors),
    )
