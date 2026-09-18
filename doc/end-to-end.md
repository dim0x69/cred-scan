# End-to-end flow

This document describes the manual inventory and append-only scan lifecycle.
The current live adapter is Artifactory local Docker; Git, package, and
OpenShift adapters use the same source-neutral contracts when implemented.

## 1. Manual inventory

The operator runs:

```text
cred-scan inventory
```

The backend discovers report boundaries and logical scan scopes:

```text
ScanBoundary: Artifactory repository docker-local
└── ScanScope: Docker image payments/api
    └── ScanTarget: selected child manifest M1
```

The Artifactory integration owns both the repository boundary and Docker scope
schemas. Model construction uses these imports:

```python
from cred_scan.backend.adapters.artifactory.models import ArtifactoryRepository, DockerImageScanScope
from cred_scan.backend.models import BackendConfig, ScanBoundaryInventory, ScanTarget, target_id_for
```

`cred_scan.backend.models` also exports the same provider classes for shared consumers;
there is only one definition of each model. At runtime, the Artifactory adapter
owns its config/name directly and satisfies `BackendAdapter` without a separate
runtime superclass. Model imports themselves neither construct clients nor discover
sources. Error handling is unchanged, including `ArtifactoryError` on transport or
response failures.

The example's image snapshot is a `DockerImageScanScope`. Git and package
snapshots use `GitRepositoryScanScope` and `PackageScanScope`. These concrete
names describe logical scopes with immutable pins, not report boundaries.
Their persisted `kind` values remain `docker`, `git`, and `package` respectively;
renaming Python classes requires no result migration or new schema version.

The inventory stores `boundary`; each target stores both `boundary` and `scope`.
Each typed scope computes:

```text
scope.id      stable logical identity
scope.pin_id  immutable version identity
```

For Git the boundary is the organization, the scope is a repository, and the
target is a commit. These remain distinct levels after the naming refactor.

For Docker, the scope identity represents the image while the pin identifies
the selected child manifest digest. A new parent index pointing to the same
child manifest, or a changed platform label for those same bytes, retains the
same target and result. For Git, the scope identity represents the
repository while the pin identifies the commit. Packages use an equivalent
logical coordinate and artifact pin.

Inventory behavior:

```text
same scope + same pin:
  retain existing target/result

same scope + previously unseen pin:
  retain old target as SUPERSEDED
  add new target as CURRENT/PENDING

same scope + previously superseded pin:
  reuse the historical target as CURRENT with its existing result
  mark the formerly current target SUPERSEDED

new scope:
  add CURRENT/PENDING target

scope omitted from authoritative discovery:
  mark scope STALE
  retain target/history

boundary omitted from authoritative discovery:
  mark boundary STALE
  retain all artifacts
```

A transient or partial discovery error preserves existing lifecycle, current
pins, execution results, and stale reasons. It records the error but does not
reactivate a stale boundary or promote a new pin. Inventory never invokes Titus
and never deletes credential observations or evidence.

For example, discovery A → B → A retains exactly two target IDs. If A was already
scanned, returning to A does not scan its unchanged bytes again. Repeating either
discovery is idempotent.

## 2. Persistent boundary state

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

`inventory.json` retains current/superseded pins and scope/boundary lifecycle
state in schema **7**, validating `target.id == target_id_for(target.scope)`.
`report.json` uses schema **2** and `credentials.json` schema **5**; both record
`boundary_id`, not a logical scope ID.

Older field names and schema versions are rejected at runtime. To reuse the
previous workspace, stop the scanner, back it up, and preflight the operator
migration:

```sh
uv run python -m cred_scan.tools.migrate_workspace_schema workspace --dry-run
uv run python -m cred_scan.tools.migrate_workspace_schema workspace --apply
```

The migration handles inventory 5/report 1/credentials 3/4, including the Docker
child-manifest target-ID correction, same-child alias reconciliation, occurrence
references, and extraction fingerprints. It preserves boundary IDs, raw
findings, evidence bytes, and the Titus datastore; `--apply` is required to
write. Report wrapper keys change, but raw findings and evidence bytes are
preserved.

`titus.ds` is the one persistent Titus datastore for the boundary. It survives
between manual scans and is shared by all target pins in that boundary.

The harness uses explicit paths and typed persistence (schematic caller example):

```python
paths = workspace.boundary(inventory.boundary.id)
workspace.write(paths.inventory, inventory, ScanBoundaryInventory)
previous = workspace.read(paths.credentials, CredentialsDocument)
published = merge_scan(previous, candidates)
workspace.write(paths.credentials, published, CredentialsDocument)
```

There is no workspace-owned credential merge or nested document handle.

## 3. Scan persisted inventory

The operator then runs:

```text
cred-scan scan
```

`scan` does not refresh inventory. It logs the command and config path before
starting. Each phase logs its own failure with the relevant inventory path,
report boundary, target and attempt, Titus datastore, raw report, or credential
checkpoint context before re-raising. `asyncio.TaskGroup` only propagates the
worker failure; the CLI does not flatten or reinterpret it. The command exits
nonzero and does not treat the failure as a completed scan.

It acquires the workspace operation lock and skips:

- stale boundaries;
- stale scopes;
- superseded target pins;
- current targets already successfully scanned.

The worker first recovers RUNNING targets and saves the recovery, then snapshots
eligible current/active pins once in inventory order. It claims each pending or
retryable failed/partial target once in this scan invocation. Each target receives
up to three Titus attempts using the same boundary `titus.ds` path and incremental
mode; a failure still marked retryable waits until the next manual scan rather
than being selected again in this run.
One `scratch_dir(paths.scratch_parent)` context spans every attempt; its own child
is removed after target completion, exception, or cooperative cancellation. Another
live reader's scratch is not removed, and `titus.ds` is never scratch.

A later scan-scope pin is therefore scanned as:

```text
M1 → titus.ds
M2 → same titus.ds
M3 → same titus.ds
```

The adjusted Titus build must retain all source occurrences in that datastore.
This is a required integration guarantee and must be checked against the
selected binary.

## 4. Cumulative report

After current target processing, Titus exports the boundary datastore:

```text
titus.ds → cumulative report.json
```

The report retains raw Titus findings and rule metadata for old and new target
pins. The report is materialized before credential conversion. If a cumulative
export cannot be guaranteed, an append-only report collection is required
instead of silently losing older findings.

## 5. Append credential observations

Report conversion resolves every finding location through the backend-bound
content reader. A credential occurrence contains the immutable target ID (the
following is schematic; actual IDs are constructed with `target_id_for(scope)`):

```json
{
  "target_id": "payments/api@manifest-m1",
  "locations": [
    {
      "provenance": "...manifest-m1/layer-l1/app.env",
      "source_path": "app.env",
      "filename": "app.env"
    }
  ],
  "finding_ids": ["finding-id"]
}
```

Orchestration reads the latest credentials checkpoint, calls
`cred_scan.orch.credentials.merge_scan(previous, candidates)`, and writes the merged document.
Only a successful write permits handoff to judgment. A conversion failure keeps
the newer raw report and the older credential checkpoint for retry. The worker and
serial consumer use this sequence (schematic; services are supplied per phase):

```python
# Scanner worker:
document = await boundary.scan(scanner, policy)
await queue.put((boundary, document))

# Serial judger, only after receiving that completed publication:
await boundary.judge(document, judge, extract_valid=True)
```

No separate completion flag or bypass option duplicates this ordering. A
`ReportBoundary` constructor holds only inventory, workspace/paths, and backend.

Credential publication is append-only:

```text
new credential ID:
  add credential

existing credential ID:
  preserve old observations
  append new target/path/finding observations
  deduplicate repeated observations
  preserve judgment and evidence metadata
```

A credential absent from a newer scan remains in `credentials.json`. A
credential found in two image manifests, Git commits, or package artifacts has
multiple retained occurrences.

Path exclusions continue to remove locations from the candidate produced by
that scan. They do not delete historical credential observations from the
append-only document.

For example, the first export may contain separate entries for `a.env/f1` and
`b.env/f2` under the same target. A later export containing only `b.env/f2` still
leaves both paths and both finding IDs in the stored credential, with `a.env`
first. Reordered/repeated exports do not change that first evidence location.

## 6. Judgment and evidence

The normal `scan` workflow judges `PENDING` and retryable `ERROR` credentials.
Judgment remains separate from user acceptance or mitigation.

Only `VALID` credentials are eligible for evidence extraction. The current
implementation retains the first valid occurrence's evidence. Historical
retained evidence is not deleted when a newer target is scanned or a finding is
absent from a later report. `cred_scan.judge.evidence.evidence_matches` checks the stored
artifact's path, size, and hash before reuse. If the file is missing or corrupt, scan/extract fails visibly without
replacing the artifact or its expected metadata. Restore bytes matching that
metadata before retrying; automatic repair is not part of this workflow.

Orchestration applies `with_judgment` to the latest checkpoint and writes it before
extracting, then persists `with_extraction` separately. Readers remain alive through
judgment and immediate VALID extraction. An evidence error leaves a saved VALID
judgment and retryable extraction ERROR, without requiring another LLM judgment.
Every update preserves other credentials' already-saved results, rather than
writing a stale queued document over them. The separate `judge` and `extract` commands
remain available for recovery but are not required for normal use. They call
`boundary.judge(persisted_document, judge)` or `boundary.extract(persisted_document)`.
Judgment returns attempted credentials; extraction returns newly retained artifacts.
One `_ensure_evidence` path serves both recovery and immediate extraction, borrowing
the live judgment reader when present and otherwise opening a reader only if the
retained-artifact check does not suffice.

## 7. Failure and stale paths

If discovery fails:

- existing targets, execution results, and lifecycle remain;
- scopes/boundaries are neither marked stale nor reactivated by the failure;
- partial discoveries do not supersede existing pins;
- credentials and evidence remain unchanged.

If a target scan or final report export fails:

- target failure/checkpoint state is persisted;
- previous report, credential, and evidence state is retained;
- the next manual scan recovers persisted RUNNING targets to PENDING and checkpoints
  that recovery before claiming again; completed targets remain completed;
- target claims and completions are individual checkpoints, not individual Titus
  attempts; a target's three attempts still share scratch and datastore;
- if targets already completed, the next scan can still export/publish without
  rescanning pins; a saved raw report is not rolled back after conversion failure.

If the operator cancels during an LLM wait, one cancellation propagates into the
async judgment, readers/backends close, and the workspace lock is released. A test
observes completion without issuing a second timeout-driven cancellation. If a
Docker tool is already parsing a layer on an executor thread, cancellation waits
for just that parser to finish before deleting its archive and reader scratch;
repeated cancellation cannot delete bytes still in use. The interrupted judgment
is not silently checkpointed as a successful result.

If evidence bytes are written but extraction metadata cannot be saved, the saved
judgment and older metadata remain. Those unindexed bytes are not treated as
verified retained evidence; a retry may retrieve/write that uncommitted artifact
again. Once RETAINED metadata exists, missing/corrupt evidence instead requires
visible failure without replacement. No multi-document transaction or automatic
repair is introduced. Temporary-file fsync/replace is tested; power-loss durability
of directory entries and evidence is not verified.

If a repository or organization is confirmed absent by authoritative inventory:

- the boundary is marked `STALE`;
- no Titus scan is started for it;
- inventory, Titus datastore, report, credentials, and evidence remain available
  to the overview.

If the boundary reappears in successful discovery, it becomes active again.
Previously known pins reuse their results; genuinely new pins start pending.
If discovery fails instead, the boundary stays stale and retains its error.

## 8. Overview relationship

The future overview can resolve:

```text
credential
→ occurrence
→ immutable target ID
→ target.scope.id and target.scope.kind
→ exact image/manifest/layer, commit, or package pin
→ target.boundary and inventory boundary lifecycle
→ raw Titus finding and retained evidence
```

This allows end users to accept a finding with enough context to rotate the
credential, while retaining stale-source history for later review.
