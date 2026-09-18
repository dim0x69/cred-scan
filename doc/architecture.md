# Architecture

For a visual overview, open the [standalone end-to-end graph](end-to-end.html#flow)
and its [storage/lifecycle map](end-to-end.html#storage).

This repository implements a manually inventoried, Titus-based credential
scanner. A report boundary is one backend and one provider grouping. Boundaries
retain historical scan data and never merge credentials across boundaries.

## Module ownership

```text
src/cred_scan/
  backend/
    backend adapters, ScanBoundary/ScanScope identity, inventory, content readers
  scan/
    Titus invocation, report conversion, deduplication, exclusions
  judge/
    judgment ports/adapters, evidence destinations and integrity checks
  orch/
    boundary lifecycle, pure credential transitions, inventory/scan coordination, configuration
  common/
    workspace paths, atomic JSON persistence, operation locking, one scratch context
  cli.py
    thin Typer command surface and operation diagnostics
```

Backend discovery does not import scan or judge. Scan does not import judge or
orchestration. Orchestration supplies the selected backend and resolves pinned
targets for content readers.

Backend schema dependencies are deliberately one-way:

```text
src/cred_scan/backend/models.py (aggregate unions, targets, inventory)
  -> src/cred_scan/backend/adapters/artifactory/models.py (endpoint, repository, Docker scope)
  -> src/cred_scan/backend/adapters/artifactory/package.py (package scope)
  -> src/cred_scan/backend/adapters/ghes.py (Git boundary and scope)
       -> src/cred_scan/backend/base_models.py (BackendConfig, ScanBoundary, ScanScope, pin hash)
  -> src/cred_scan/backend/base_models.py
```

Docker is part of the Artifactory integration in this harness. Its `DockerImageScanScope`,
`ArtifactoryRepository`, and `ArtifactoryBackendConfig` live together in that
integration's model module; `PackageScanScope` lives in the Artifactory package
module, and Git boundary/scope models live in the GHES adapter module.
`cred_scan.backend.models` imports/re-exports these exact classes for shared unions
and consumers; it does not duplicate them. The schema-only bases
import no adapters. Artifactory's package initializer imports no implementation,
so loading models or orchestration settings does not load transport/runtime code.

`ArtifactoryBackend` directly implements `BackendAdapter` and owns its config and
`name` property. The former config/name-only runtime `Backend` superclass is gone;
`proto.py` still contains contracts, not concrete adapter behavior. Transport errors
and their `ArtifactoryError`/`LayerEvidenceError` handling are unchanged.

## Manual lifecycle

The normal operator workflow is:

```text
inventory  ->  scan
```

The CLI logs command start, configuration path, and command termination. Errors
are logged with `LOGGER.exception` at the phase where they occur: configuration
loading, inventory loading, Titus target/report operations, candidate conversion,
and credential publication. Nested `asyncio.TaskGroup` failures preserve normal
cancellation and propagation; the CLI does not flatten or reinterpret them.

`inventory` is manual. It discovers logical scan scopes and immutable pins, adds
new targets, retains old targets, and marks scopes or boundaries stale when an
authoritative discovery confirms they disappeared. It does not scan or change
credential observations.

`scan` uses only the persisted inventory. It skips stale boundaries and
superseded targets, scans current pending targets, reuses the boundary Titus
datastore, exports cumulative `report.json`, appends `credentials.json`
observations, judges findings, and retains evidence.

Inventory and scan use one nonblocking workspace operation lock and cannot run
at the same time. The lock is held for the complete operation; file-level locks
still protect individual atomic writes.

## Boundary, scope, and target model

The logical structure is:

```text
ScanBoundary
├── ScanScope
│   └── ScanTarget pin(s)
└── report / credentials / evidence / Titus datastore
```

`ScanBoundary` identifies a report grouping such as an Artifactory repository
or Git organization. Its inventory holds the `active`/`stale` boundary lifecycle.
A stale boundary remains reportable but is not scanned. Runtime `ReportBoundary`
is the orchestration object for this grouping, not another identity model.

`ScanScope` identifies a logical source inside that boundary: a Docker image,
Git repository, or package coordinate. It replaces the former `Source` model;
the former boundary-level `ScanScope` is now `ScanBoundary`. Typed scope
snapshots share this interface:

```python
scope.kind
scope.id       # computed logical identity
scope.pin_id   # computed immutable-version identity
scope.lifecycle
```

`ScanBoundaryInventory.boundary` and `ScanTarget.boundary` hold the report owner.
`ScanTarget.scope` holds the typed logical scope and selected immutable pin.
Scopes are grouped from retained targets; there is no second synchronized registry.
Workspace/report/credential identifiers use `boundary_id`.

The logical ID is computed from identity fields only. Docker tags, manifest
hashes, Git commits, package digests, and timestamps do not change the logical
ID. The pin ID is computed from the exact immutable reference that determines
the scanned bytes. For Docker this is the selected child manifest digest:
Titus scans `image@digest`. Parent indexes, platform selection labels, tags,
and timestamps remain snapshot metadata; changing them without changing the
child digest must not introduce a second target with ambiguous provenance.

A `ScanTarget` identifies one immutable source pin. Its deterministic target ID
combines the logical scope ID and pin ID, and is validated against the scope
on construction and persistence. Target lifecycle (`current` or
`superseded`) is separate from execution state (`pending`, `running`,
`scanned`, `partial`, or `failed`). Superseded targets remain resolvable for
historical findings and are not scanned again.

## Inventory refresh

The shared inventory merger is backend-neutral. It groups by `target.scope.id`
and compares canonical target IDs derived from `scope.id` and `scope.pin_id`:

- same scope and a retained pin: reuse the existing target and result, even
  when that pin was superseded (A → B → A does not create a second A);
- same scope and new pin: retain the old target as superseded and add the new
  target as current/pending;
- new scope: add a current/pending target;
- scope omitted from a successful authoritative boundary discovery: mark its
  scope snapshots stale and retain its targets;
- boundary omitted from successful authoritative discovery: mark the boundary
  stale and retain all artifacts;
- discovery failure or partial discovery: preserve all prior targets, current
  selections, scope/boundary lifecycle, and stale reason; record errors without
  promoting new pins or reactivating stale data.

Successful discovery synchronizes scope lifecycle across all retained snapshots.
The backend owns selection and ordering; when discovery supplies multiple pins
for one scope, all distinct pins are retained and the last is current. Repeated
identical discovery preserves IDs and execution results.

A target pin cannot change while a worker owns it. Inventory and scan operation
locking prevents that race. Interrupted running targets are recovered before a
later scan claims them. After that recovery checkpoint, the owning worker snapshots
eligible current/active pending or retryable failed/partial pins in inventory order
and iterates them once. Each target still gets a persisted RUNNING claim, up to
three attempts in one scratch context, immutable-pin completion validation, and a
completion checkpoint. A remaining retryable failure is not reclaimed in that run.

## Persistent artifacts

Each boundary owns:

```text
<boundary>/
  inventory.json
  titus.ds/
  report.json
  credentials.json
  evidence/
  scratch/
```

`titus.ds` is one persistent Titus datastore per boundary. Every target pin in
that boundary is scanned into the same datastore with incremental mode. The
runtime then exports `report.json` from the same datastore. The adjusted Titus
build is expected to retain all source occurrences and produce cumulative
exports; this behavior requires integration verification against the selected
binary.

`report.json` is the latest cumulative raw Titus report and rule-metadata store.
`credentials.json` is an append-only normalized observation and judgment index.
A scan adds credential identities, occurrences, and finding references, but does
not remove records that are absent from a later scan. Publication folds all old
and new occurrences, including multiple old entries for one target, in that
order. Locations and finding IDs are unioned without changing the first evidence
location. Historical evidence is
also not removed by scanning. Future mitigation may change the active user view
but is separate from this scan lifecycle.

Every occurrence and every location reference the same immutable `ScanTarget.id`
and retain an opaque backend locator, source-relative path, and filename.
Pydantic enforces the location-to-occurrence relationship; report-boundary
orchestration enforces the document boundary and occurrence-target membership
against the retained inventory. Therefore old findings continue to resolve to
the image manifest/layer, Git commit, or package artifact that produced them
without exposing backend syntax to scan or judgment.

## Scan/judge/evidence lifecycle

For an active boundary:

1. Claim current pending or retryable targets one at a time.
2. Run all Titus attempts for the target using the shared boundary datastore.
3. Export the cumulative Titus report after target processing.
4. Persist `report.json`.
5. Resolve each raw Titus path against all retained target pins and construct a
   target-bearing source-neutral location.
6. Append normalized credential observations to `credentials.json`.
7. Judge pending/error credentials.
8. Retain first-occurrence evidence for valid credentials. Before reusing a
   `RETAINED` artifact, verify its path, size, and hash. Missing or corrupt evidence
   fails the operation visibly without deleting/replacing bytes or metadata;
   an operator must restore the verified artifact before retrying.

`src/cred_scan/orch/credentials.py` owns pure append/judgment/extraction transformations;
`ReportBoundary` explicitly reads, transforms, and persists credential checkpoints.
It saves recovered targets, target claims/completions, the raw report, merged
credentials, every judgment, and every extraction outcome separately. No per-attempt
or multi-document transaction state is introduced.

`ReportBoundary` holds inventory, paths/workspace, and backend. The scanner and judge
are required arguments to their phase methods, not optional services on a partially
configured boundary. `LocalRuntime` creates scanners in scan workers and shares one
judger in the serial consumer; recovery never constructs Titus. Empty/stale-only
scan runs construct neither phase service. The bounded queue and nested TaskGroups
remain: a worker enqueues only after `scan(scanner, policy)` has saved credentials.
This handoff enforces publication-before-judgment; no mutable completion flag or
caller-supplied bypass switch duplicates it.

`judge(document, judge, extract_valid=False)` returns attempted judgment count;
`extract(document)` returns newly retained evidence count. Normal scan uses
`extract_valid=True` and keeps one Python-owned byte session for one credential's
judgment and immediate extraction. The cache key includes target ID, locator,
source path, and filename, so changed metadata must be validated by the backend.
Closing the session clears all cached bytes and closes its reader; nothing is
shared across credentials or runs. Both normal and recovery paths call one
evidence operation that checks retained integrity before opening a session and
owns the single extraction checkpoint.

Cancellation propagates through native async judgment; it is not shielded for the
whole LLM call. Docker reader methods join only their blocking archive-parsing
executor work before removing the input archive and allowing reader scratch cleanup,
including repeated cancellation and parser errors. Such a worker must finish before
cleanup; it cannot be forcibly cancelled. Reader/backend closure follows cancellation
unwinding and operation ownership remains held until that cleanup completes.

A failed or incomplete scan does not remove prior reports, observations, or
evidence. Stale boundaries and superseded targets are excluded from scanning
but remain available to overview generation.

## Source neutrality and future adapters

Current runtime construction is Artifactory-Docker-specific. Git/GHES,
package, and OpenShift adapters are future capability work. They must provide
the same backend, scope, pin, source-neutral location/read, Titus, and judgment
ports without changing the source-neutral credential occurrence contract.

## Configuration and persistence

Runtime settings remain in `config.yml`; relative paths resolve against that
file. `Workspace` owns the resolved workspace root, typed `read(path, model_type)` /
`write(path, document, model_type)`, inventory-directory discovery, and operation
lock. `boundary(id)` returns an immutable, I/O-free `BoundaryPaths` value, not a
resource/document handle. `ReportBoundary` retains the root workspace and its
paths separately. Common persistence imports no feature models or domain policy.
`cred_scan.common.workspace.scratch_dir(parent)` owns one temporary child, never other live
sessions. Backend readers hold it until `aclose()`; scan holds it through every
target attempt. `cred_scan.judge.evidence` owns retained-file path/integrity helpers, not a
workspace handle, manifest, deletion, or repair service.

JSON writes validate the expected model again, fsync a same-directory temporary
file, then replace the destination under a directory lock. Pre-replacement errors
preserve the old checkpoint and clean only that write's temporary file. Directory
fsync and explicit evidence fsync are not implemented; tested process-interruption
recovery must not be confused with power-loss durability. Reports and credentials
are separate checkpoints: conversion failure can leave a newer raw report beside
older credentials for the next run.

Current schemas are inventory **7**, Titus report **2**, and credentials
**7**. They use `boundary` for the report owner, `scope` for the target's logical
source snapshot, and `boundary_id` for document/workspace identity. Credential
locations use `target_id`, opaque `locator`, `source_path`, and `filename`.
Boundary ID values, canonical target IDs, datastore paths, and evidence integrity
metadata remain stable. Extraction results contain status, output path, size,
SHA-256, and error only; the unused source-set fingerprint has been removed.

Earlier documents are rejected rather than interpreted via legacy aliases.
`cred_scan.tools.migrate_workspace_schema` is the separate operator-only
migration from credentials 5 or 6 to 7. It preflights inventory/report/credential
relationships, converts schema-5 typed provenance to target-bearing opaque
locators, and removes the unused extraction `source_fingerprint` from both old
versions before optional atomic writes with `--apply`. All other extraction
metadata and observations are preserved; no source content is fetched and no
evidence is re-extracted. Inventory-only boundaries need no report;
existing reports are still validated, and result artifacts without a report
fail preflight. Preserve raw findings, evidence bytes, and execution history. The
historical schema-2→3 utility retains its old output and does not perform this
upgrade.
