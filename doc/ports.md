# Ports

## Backend construction and model ownership

[`BackendAdapter`](../src/cred_scan/backend/proto.py) remains the runtime contract used by
orchestration, scanning, and readers. `ArtifactoryBackend` implements it directly,
stores the supplied `ArtifactoryBackendConfig`, and returns its current `config.name`
from `name`. `ArtifactoryDockerBackend` extends that transport with Docker behavior;
there is no additional config/name-only runtime superclass.

`cred_scan.orch.models` and `cred_scan.orch.inventory` import `ArtifactoryBackendConfig` from
[`artifactory/models.py`](../src/cred_scan/backend/adapters/artifactory/models.py). Shared port
signatures still use the exact classes and unions exported by `cred_scan.backend.models`.
The concrete scope classes are `DockerImageScanScope`, `GitRepositoryScanScope`,
and `PackageScanScope`; `ScanScopeRef` remains their union, so `ScanTarget.scope`
and reader/scanner port signatures keep the same shape.
The provider model module imports schema-only shared bases, not adapter code.
Import runtime classes/errors from
`cred_scan.backend.adapters.artifactory.common` or
`cred_scan.backend.adapters.artifactory.docker`, not the package initializer;
that initializer stays free of implementation imports.

`ArtifactoryError` remains in `artifactory.common`, including HTTP wrapping,
configuration/response validation, and reader translation into `LayerEvidenceError`.
Removing or reclassifying these exceptions is deferred; this refactor does not
alter diagnostics, response closure, or judgment fatal-error classification.

## Inventory boundaries, scopes, and pins

`BackendAdapter.inventory() -> list[ScanBoundaryInventory]` returns the latest
backend discovery result. Each error-free boundary result is authoritative for
that boundary's logical scan scopes and pin selection. Omitted boundaries are marked stale
only when the backend discovery succeeds and none of its returned boundaries
has errors. An exception does not establish absence.

`ScanBoundaryRef` identifies the Artifactory repository or Git organization
owning the report. Each typed `ScanScopeRef` (Docker/Git/package snapshot) provides:

```python
scope.kind
scope.id       # computed logical identity
scope.pin_id   # computed immutable-version identity
scope.lifecycle
```

The inventory carries `boundary: ScanBoundaryRef`; each target carries both
`boundary: ScanBoundaryRef` and `scope: ScanScopeRef`. These are distinct levels,
not alternate representations of the same source.

The backend owns scan-scope identity and pin selection. Docker chooses its selected
manifest/platform, Git chooses its selected commit, and package adapters choose
an exact artifact. Shared inventory code does not inspect source-specific
fields.

The inventory merger:

- looks up pins across all retained targets, including superseded ones, and
  preserves the existing target ID and execution result on rediscovery;
- adds a new current/pending target when a scope receives a new pin;
- marks the previous target superseded without deleting it;
- adds new logical scope IDs;
- marks omitted scopes stale only after authoritative discovery;
- marks omitted boundaries stale only after authoritative discovery;
- retains targets, reports, credentials, and evidence for stale data;
- preserves every previous target, lifecycle state, current selection, and stale
  reason after failed/partial boundary discovery, recording errors but making no
  pin promotions (an initial failed boundary has no promoted targets).

The backend provides canonical `ScanTarget.id == target_id_for(scope)` values.
Construction and persistence reject mismatches. If discovery includes several
pins for a scope, their order is backend-owned: the last pin is current and
all distinct earlier pins are retained. Repeating discovery does not duplicate
IDs or reset results. Docker pin IDs use the child manifest digest actually
passed to Titus; a parent-index-only change retains the same target.

Worker completion remains stricter than inventory refresh. A claimed target must
complete with the same immutable source pin it was given. Inventory and scan
cannot overlap because the runtime holds one workspace operation lock.

## Titus scanning

```python
class CredentialScanner(Protocol):
    async def scan(
        self,
        target: ScanTarget,
        work_dir: Path,
        datastore: Path,
        exclusions: ExclusionPolicy,
    ) -> ScanTarget: ...

    async def export_report(self, datastore: Path) -> TitusReport: ...
```

All target pins for one boundary use the same persistent `datastore` path.
Titus is invoked incrementally. The final export is materialized as cumulative
`report.json`. The adjusted Titus build must be verified to retain old source
occurrences and export old plus new findings from this datastore.

Scanning skips stale boundaries, stale scopes, and superseded targets. A
failed or incomplete scan does not remove previously published documents or
evidence. `TitusCliScanner.export_report` converts raw Titus JSON and returns the
typed `TitusReport` required by the port; orchestration does not accept a second
raw-export representation or repeat that conversion.

## Content locations

`BackendAdapter.content_reader(boundary: ScanBoundaryRef,
targets: tuple[ScanTarget, ...])` creates a reader bound to one report boundary
and a nonempty set of its retained pins, including superseded targets. The
boundary parameter must not be a logical `ScanScope`.

```python
ContentReader.resolve_location(
    raw_path: str,
    *,
    target_id: str | None = None,
) -> ContentLocation

ContentReader.read(location: ContentLocation) -> bytes
ContentReader.aclose() -> None
```

The resolver returns a source-neutral location whose target ID belongs to a
retained immutable target in the current boundary. Historical report locations
may therefore resolve to superseded targets as well as current targets. The
opaque locator is interpreted only by the backend. Docker distinguishes layer
files from manifest/config metadata internally; Git and package adapters provide
equivalent backend-owned locator strings.

`read()` returns complete exact bytes. It does not write evidence or expose text
encoding. A Python content session caches bytes only for one credential's
judgment and immediate evidence extraction, keyed by all location fields. It
clears the cache and closes the reader on exit, including failed or cancelled
judgment. There is no cross-credential or cross-run cache. Evidence helpers own
writing and hashing. The LLM
judge uses session-local location IDs which orchestration resolves to these
source-neutral values before invoking the reader.

`FindingJudge.judge(credential, content)` is awaited directly and must propagate
cancellation and keep all reader use within its awaitable. Ordinary judgment/reader
creation failures become credential ERROR results; `FatalJudgeError` aborts the run.
The owner closes the reader afterward. Docker readers settle blocking archive
parsers locally before deleting their input/scratch; this protection is not a shield
around an entire judgment. Repeated cancellation still cannot release a parser's
input while it is in use.

## Credential publication

[`src/cred_scan/orch/credentials.py`](../src/cred_scan/orch/credentials.py) exposes pure transformations:

```python
merge_scan(previous: CredentialsDocument | None, discovered: CredentialsDocument) -> CredentialsDocument
with_judgment(document: CredentialsDocument, credential_id: str, judgment: JudgmentResult) -> CredentialsDocument
with_extraction(document: CredentialsDocument, credential_id: str, extraction: ExtractionResult) -> CredentialsDocument
```

`ReportBoundary` reads the latest checkpoint, applies the transformation, and
writes the result before advancing. Transformations do not mutate their inputs
or perform I/O. Missing lifecycle documents and unknown credential IDs fail;
merging documents from different boundaries is rejected. `merge_scan` merges
credential IDs, occurrences, and finding references idempotently. It never removes a prior credential,
occurrence, or evidence artifact. The publication folds **all** historical entries
before new entries, including multiple entries for the same target, and unions
locations/finding IDs in first-seen order. Initial publication also normalizes
repeated entries. Partial/excluded later reports cannot erase earlier paths or
change the first evidence location.

Judgment and extraction update one credential record by stable credential ID.
Judgment updates do not delete historical extraction metadata. Extraction is
allowed only for `VALID` credentials. User acceptance and mitigation are not
part of scan publication.

## Evidence

Evidence retention currently stores the first valid occurrence. Historical
first-occurrence evidence is not removed when a newer source pin is scanned or
a finding is absent from a later report. All occurrences remain in
`credentials.json` for overview generation.

Before skipping extraction for `RETAINED` metadata, the runtime calls
`cred_scan.judge.evidence.evidence_matches(boundary_dir, credential_id, extraction)`. If path, size, or hash
verification fails, scan/extract raises a visible integrity error rather than
silently claiming success or deleting/replacing historical evidence. Bytes and
expected metadata remain untouched; restore the verified artifact offline
before retrying. No automatic evidence repair is performed.

`evidence_path(boundary_dir, credential_id, filename)` resolves a plain safe filename
under the encoded credential directory. Runtime reads the location through the
short-lived content session, then passes the raw bytes to
`retain_first_evidence(credential, location, content, destination)`, which requires
VALID, writes atomically, and returns `(path, size, sha256)`. Only credentials
without retained evidence reach this extraction call. Metadata is stored
separately in `credentials.json`.

`ReportBoundary._ensure_evidence` is the one orchestration path for immediate and
recovery extraction: verify RETAINED first; otherwise borrow the live judgment
session or open/close a fresh session, read bytes, write evidence, read the latest
credentials, and checkpoint one extraction outcome. A borrowed session is not
closed by this helper. A matching artifact returns false (no new extraction);
new RETAINED returns true. Ordinary retrieval failures persist ERROR. Integrity
failures and checkpoint-write failures escape without replacing historical
metadata.

`cred_scan.common.workspace.scratch_dir(parent)` is the sole temporary-directory primitive.
The caller owns the context through target attempts or the complete content-reader
session, including immediate evidence extraction. Exit removes only its child and,
if empty, the parent; it does not guarantee cleanup after SIGKILL.

## Operation diagnostics

The Typer command surface logs command start, config path, and command
termination. Phase owners log exceptions at the failure site with context:
configuration paths, inventory paths, report boundaries, target IDs, Titus
attempts, report paths, and credential checkpoints. `TaskGroup` exceptions are
not flattened or reinterpreted by the CLI; the originating phase log retains
its traceback. Commands still return nonzero after logging and do not convert
failures into successful checkpoints.

## Persisted inventory precondition

Runtime operations require inventory **7**, report **2**, and credential **7**
models. Inventory/target `boundary` is the report owner; target `scope` is the
logical scope snapshot. Reports and credentials carry `boundary_id`.
`Workspace.boundary(boundary_id)` returns `BoundaryPaths` with that unchanged
report-boundary ID and directory encoding.

Older keys/versions are rejected with no runtime aliases or automatic migration.
The operator-only `cred_scan.tools.migrate_workspace_schema` utility performs an
authorized offline upgrade from credentials 5 or 6 to 7 after inventory/report
preflight. It converts schema-5 typed provenance to target-bearing opaque
locators and removes the unused extraction `source_fingerprint` from both old
versions. No source-fingerprint helper remains. All other extraction metadata,
observations, judgments, findings, evidence, and datastore files are preserved.
Evidence reuse still checks stored path, size, and SHA-256 before backend reads.
Inventory-only boundaries are skipped after validating inventory;
existing reports are validated even without credentials. Missing reports with
credential, datastore, or evidence artifacts fail the complete preflight before
any writes. The tool writes only with `--apply`. Missing historical targets must
be restored from authoritative inventory, prior scan state, or backup before
the new location contract is enforced.
The historical schema-2→3 credential utility still validates/writes only its old
formats; it does not upgrade to this runtime.

## Workspace persistence and operation ownership

[`WorkspaceProtocol`](../src/cred_scan/common/proto.py) is the single common persistence port:

```python
results_dir: Path
boundary(boundary_id: str) -> BoundaryPaths
inventory_boundaries() -> Iterator[BoundaryPaths]
read(path: Path, model_type: type[DocumentT]) -> DocumentT | None
write(path: Path, document: DocumentT, model_type: type[DocumentT]) -> None
operation_lock() -> AbstractContextManager[None]
```

`DocumentT` is bound to Pydantic `BaseModel`. `read` returns None only for a missing
file; malformed JSON, non-object payloads, and invalid/legacy models raise. `write`
checks the explicitly expected type and revalidates even `model_copy()` values
before replacing the file. No filename registry or domain lifecycle is implicit.
`inventory_boundaries` discovers paths containing `inventory.json`, including stale
boundaries; orchestration, not persistence, decides eligibility.

Inventory orchestration reads/merges/writes `ScanBoundaryInventory`. ReportBoundary
writes `TitusReport` before conversion and reads/transforms/writes
`CredentialsDocument` afterward. It reads the latest credential checkpoint for each
judgment/extraction update, rejects missing documents, and validates the document
boundary and occurrence target references before content access. Pydantic already
validates location-to-occurrence target consistency. Paths come from `BoundaryPaths`, never a reader's
untrusted locator. Direct read/modify/write callers must hold operation ownership;
a per-write lock alone is not a transaction across the read and transformation.

The lock is workspace-wide and nonblocking. `inventory`, `scan`, `judge`, and
`extract` acquire it for their complete operation. Individual JSON writes use
blocking directory locks plus atomic replacement. Evidence writers use replacement
under operation/boundary ownership, without an additional file-level lock.
JSON temporary files are fsynced before replacement; directory fsync and explicit
evidence fsync are not implemented, so power-loss durability is not verified.

## Boundary phase methods

`ReportBoundary(inventory, workspace, *, backend)` carries no optional scanner/judge
and no mutable completion flag. Its concrete phase methods are:

```python
async def scan(scanner: CredentialScanner, policy: ExclusionPolicy) -> CredentialsDocument: ...
async def judge(document: CredentialsDocument, judge: FindingJudge, *, extract_valid: bool = False) -> int: ...
async def extract(document: CredentialsDocument) -> int: ...
```

Callers own the boundary and operation lock. `scan` recovers interrupted targets,
snapshots eligible targets once in inventory order, and saves each claim/completion.
It never reclaims a still-retryable failure within that invocation; retries within a
target retain the existing three-attempt policy. It writes the final typed report
before converting/appending credentials and returns only after publication succeeds.

`judge` validates the document boundary and occurrence target references, attempts
PENDING/ERROR credentials, and returns attempted judgment count. With
`extract_valid=True`, it also ensures
evidence for existing VALID credentials and newly VALID judgments while their
readers are live; it does not change the returned count. `extract` validates the
same references, processes only VALID credentials, and returns newly retained
count. Both consume published documents; neither republishes scan observations.

## Runtime workflow

`LocalRuntime.inventory()` performs only manual inventory under the operation
lock. `LocalRuntime.scan()` processes persisted inventory, performs target
scans, appends the cumulative report-derived observations, judges candidates,
and extracts evidence. `LocalRuntime.run()` is only a compatibility alias for
`scan()`; it contains no separate orchestration.

`LocalRuntime.judge()` and `LocalRuntime.extract()` remain recovery/operator
paths over persisted documents and skip stale boundaries. The scan worker awaits
successful `boundary.scan(scanner, policy)` before enqueuing its document; the serial
consumer then calls `boundary.judge(document, judge, extract_valid=True)`. Failure
before handoff cannot start judgment for that boundary. Recovery calls `judge` with
its default option or `extract` directly. These paths share evidence handling, not
three booleans selecting return semantics or bypassing a phase guard.
