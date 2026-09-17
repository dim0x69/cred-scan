# Data interfaces

All persisted values use Pydantic v2 models. A report boundary is one backend
and one provider grouping. Its documents never combine findings from another
boundary.

## Model ownership and imports

- [`backend/base_models.py`](../backend/base_models.py) defines the schema-only
  `BackendConfig`, `ScanBoundary`, `ScanScope`, and shared pin-hash helper.
- [`backend/adapters/artifactory/models.py`](../backend/adapters/artifactory/models.py)
  defines `ArtifactoryBackendConfig` (name, kind, base URL, platform),
  `ArtifactoryRepository`, and `DockerImageScanScope`. Docker is bound to Artifactory in this
  harness; these schemas remain distinct configuration/boundary/scope levels.
- [`backend/models.py`](../backend/models.py) is the aggregate schema entry point:
  it re-exports those exact classes and defines Git/package scopes, typed unions,
  targets, inventories, and content-transfer models. Provider schemas import only
  the shared bases, never the aggregate module, avoiding circular imports.

Model ownership is reflected in module locations, and concrete scope class names
state the logical source explicitly: `DockerImageScanScope`,
`GitRepositoryScanScope`, and `PackageScanScope`. Fields, discriminator values
(`docker`, `git`, `package`), computed identity, and inheritance are unchanged.
Generated JSON Schema titles and definition references use the new class names;
persisted JSON does not store Python class names. Inventory 7, report 2,
credentials 4, and the central configuration shape remain unchanged. No aliases
for the old class names, legacy persisted fields, or runtime migration are added.

## Boundary, scope, and target identity

```text
ScanBoundary                         Artifactory repository / Git organization
└── ScanScope.id                      Docker image / Git repository / package
    └── ScanTarget.id                 immutable manifest / commit / artifact
```

[`ScanBoundary`](../backend/base_models.py) is the `id`/`name` base for
[`ArtifactoryRepository`](../backend/adapters/artifactory/models.py) and
`GitOrganization`. `ScanBoundaryRef` in [`backend.models`](../backend/models.py)
is their union.
It identifies the report grouping, not an individual image or Git repository.
Boundary lifecycle lives on `ScanBoundaryInventory`, not this identity model.

`ScanScope` replaces the former `Source` base for `DockerImageScanScope`,
`GitRepositoryScanScope`, and `PackageScanScope`; `ScanScopeRef` is their union. These typed scope snapshots expose:

```python
scope.kind: str
scope.id: str          # computed stable logical identity
scope.pin_id: str      # computed immutable pin identity
scope.lifecycle: Literal["active", "stale"]
```

The logical scope ID excludes version fields. The pin ID includes the fields
that identify exact scanned bytes. Supplied computed `scope.id`/`scope.pin_id`
values are regenerated from canonical fields. Docker `id` is the image identity
and `pin_id` hashes the child manifest digest alone. The parent index and platform
label describe selection, not different scanned bytes; they remain snapshot
metadata. Git/package adapters remain future work.

`ScanTarget` explicitly keeps the two levels separate:

```python
class ScanTarget(BaseModel):
    id: str
    backend_id: str
    boundary: ScanBoundaryRef
    scope: ScanScopeRef
    lifecycle: Literal["current", "superseded"]
    result: ScanTargetResult
```

Every target ID must equal `target_id_for(scope)` (`scope.id@scope.pin_id`).
Construction and persistence reject mismatches. Naming changes do not alter
these ID values. A new scope pin appends a target; rediscovery of a superseded
pin reuses its ID and result. Occurrence `target_id` resolves to one retained
immutable target, never merely to the current logical scope.

`ScanBoundaryInventory.boundary` identifies the owner of all its targets. Its
`lifecycle: Literal["active", "stale"]` and `stale_reason: str | None` describe
the whole boundary. Each target's `scope.lifecycle` describes its logical scope;
`target.lifecycle` and `target.result.status` remain separate. The inventory
stores a flat target collection and groups scopes by `target.scope.id`.

Stale boundaries/scopes remain reportable but are not scanned. Successful
discovery synchronizes scope lifecycle across retained pin snapshots. Errors
preserve lifecycle, results, and stale reasons without promoting new pins.

## Titus report

`TitusReport` is the latest cumulative export from the boundary Titus
 datastore:

```python
class TitusReport(BaseModel):
    boundary_id: str
    generated_at: str
    incomplete: bool = False
    errors: tuple[str, ...] = ()
    findings: tuple[dict[str, Any], ...] = ()
```

The selected adjusted Titus build must retain old source occurrences when new
pins are scanned into the same datastore. If finding IDs are only unique within
an export, credential references must qualify them with target or scan
identity.

## Credential occurrence

```python
class CredentialLocation(BaseModel):
    provenance: str
    source_path: str
    filename: str

class CredentialOccurrence(BaseModel):
    target_id: str
    locations: tuple[CredentialLocation, ...]
    finding_ids: tuple[str, ...]
```

The target ID identifies the exact source pin. Locations retain raw Titus
provenance and the resolved path accepted by the backend reader. Occurrences
from repeated scans are merged idempotently by target, location, and finding
identity. Both persisted and newly converted documents may contain several
occurrences for one target. Append publication folds every entry into one
target group, unions locations/finding IDs in first-seen order, and preserves
the original first location even if later reports omit or reorder it.

## Credential lifecycle

```python
class Credential(BaseModel):
    credential_id: str
    credential: str | None
    occurrences: tuple[CredentialOccurrence, ...]
    judgment: JudgmentResult
    extraction: ExtractionResult | None
```

`CredentialsDocument.boundary_id` identifies the enclosing report boundary.
It does not identify a logical scan scope; each occurrence reaches that scope
through its immutable target reference.

Pure transformations in `orch/credentials.py` own append and lifecycle policy;
orchestration persists their results through validated workspace I/O. The document
schemas do not encode a second publication/lifecycle state machine. Runtime
`ReportBoundary` holds inventory, workspace/paths, and backend only; scanners and
judgers are operation arguments. There is no persisted or in-memory scan-completion
flag added to these models. The scheduler's successful-publication handoff defines
when normal judgment may start; recovery consumes an existing credential document.

Scanning publication is append-only:

- new credential IDs are added;
- new occurrences and finding references are appended;
- repeated observations are deduplicated;
- existing credentials are not removed when absent from a later report;
- existing judgment and evidence metadata are preserved.

Judgment remains separate from future user acceptance/mitigation. A later
mitigation feature may alter the active user view, but scan publication does not
perform that removal.

Evidence metadata remains in `credentials.json`; evidence bytes live under the
boundary evidence directory. `judge.evidence` owns safe destinations and integrity
checks; no evidence workspace object or separate index is persisted. Scan-time historical cleanup is disabled. The
initial policy retains first-occurrence evidence while all source occurrences
are retained in the credential document. Its extraction fingerprint records the
source set at extraction time; appending observations does not rewrite it.
`RETAINED` metadata is not proof that bytes still exist: reuse verifies the
stored path, size, and SHA-256. Missing or mismatched evidence raises an integrity
failure while retaining the expected metadata and any existing artifact.

## Content reader locators

`ContentReader.list_files(directory)` returns backend-owned locators that can be
passed unchanged to `read_file()`. A Docker locator retains the exact manifest
and layer identity. Git and package adapters provide equivalent immutable
locators.

`read_file()` returns complete exact file bytes. `extract_file()` writes those
bytes unchanged to evidence. Callers do not reconstruct provenance from a
relative path. Reader operations propagate cancellation after joining any blocking
archive worker still accessing temporary bytes. The caller closes the reader only
after that operation has unwound; no detached parser may outlive reader scratch.

## Workspace path value

[`BoundaryPaths`](../common/models.py) is a frozen, nonpersisted Pydantic value
with `boundary_id: str` and `boundary_dir: Path`. Its read-only properties are
`inventory`, `report`, `credentials`, `datastore`, and `scratch_parent`. They derive
`inventory.json`, `report.json`, `credentials.json`, `titus.ds`, and `scratch` under
the same boundary directory; constructing paths creates no files or directories.
Only `Workspace.boundary(id)` encodes the unchanged boundary ID with
`quote(id, safe="")`. Evidence destinations are owned by `judge.evidence`.
There are no nested document/evidence handles or serialized workspace path models.
Inventory/report/credential fields, versions, and JSON schemas are unchanged by
this persistence simplification.

## Persistence and stale state

`inventory.json` persists current and superseded target pins, scope lifecycle,
and boundary lifecycle. `report.json` persists cumulative raw Titus findings.
`credentials.json` persists append-only normalized observations and judgment.
Stale boundaries and scopes retain all three documents and evidence so an
overview can label historical observations correctly.

Inventory and scan are mutually exclusive workspace operations. File writes are
atomic, and operation ownership is protected by a workspace-level nonblocking
lock. Current document versions and field changes are:

| Document | Version | Renamed fields |
|---|---|---|
| Inventory | **7** | inventory `scope` → `boundary`; target `scope` → `boundary`, `source` → `scope` |
| Titus report | **2** | `scope_id` → `boundary_id` |
| Credentials | **4** | `scope_id` → `boundary_id` |

Old field names are not runtime aliases. Older versions are rejected; a schema
number alone cannot upgrade their payloads. This refactor leaves `workspace/`
untouched. A separately authorized offline migration from inventory 6/report
1/credentials 3 can rename these keys and versions without changing boundary
IDs, target IDs, occurrence references, or extraction fingerprints. Report
wrapper JSON changes, but raw findings and evidence bytes must not change.

The earlier schema-5 workspace additionally requires the previously documented
child-manifest ID correction, same-child alias reconciliation, and corresponding
occurrence/fingerprint updates. Preserve originals and history; do not discard
artifacts. No runtime migration or legacy-ID fallback is provided. The historical
schema-2→3 credential utility still emits its old format, not this upgrade.
