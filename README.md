# Credential scanner

Credential scanner with backend-agnostic core models and manually refreshed
source inventories. Inventory selects immutable source pins; `scan` reuses one
persistent incremental Titus datastore per boundary, retains superseded targets,
appends credential observations, judges findings, and extracts evidence.
Bounded asyncio scanner workers process independent active boundaries while one
serial judger handles completed boundaries. `scan_concurrency` counts async
worker slots, not OS threads; Titus has a separate `internal_workers` setting.

## Current scope

Current implemented scope:

- Artifactory local Docker repositories.
- Manual authoritative inventory refresh with computed source identity and
  immutable target-pin IDs.
- Retained superseded targets and stale boundaries; stale boundaries are not
  scanned but remain available for reporting.
- One persistent incremental Titus datastore per report boundary, reused across
  manual scans.
- Bounded scanner workers process independent active boundaries while one serial
  judger handles completed boundaries.
- Three total scan attempts per target.
- Boundary-wide Titus export as `report.json`; cumulative retention remains a
  required adjusted-Titus integration guarantee, not yet verified by a live scan.
- Append-only normalized `credentials.json` observations and evidence metadata.
- Current adjusted-Titus credential identity and source-neutral occurrence deduplication.
- `path-exclusions.list` passed to Titus and reapplied during deduplication.
- Old-style regex-search `cred-value-exclusions.list` before judgment.
- Native asynchronous DSPy judgment with exact repository-bound Artifactory file tools.
- `aiofiles` regular content/evidence file I/O with worker-thread tar parsing.
- First-occurrence evidence retention without scan-time historical deletion.

Not included yet: GHES/Git, package scanning, OpenShift, user acceptance and
mitigation, the former CLI workflow, human review, and training export. The
existing workspace was previously migrated offline to inventory schema 5 and
append-only credential behavior. Current schemas are inventory 7, report 2,
and credentials 4; see the upgrade warning below. `report.json` is the cumulative raw Titus and
rule-metadata store; `credentials.json` contains append-only normalized
observations, judgment, and finding references. Future source adapters must use
the generic backend, ScanScope, content reader, report, and judgment ports.

The model hierarchy is `ScanBoundary → ScanScope → ScanTarget`: an Artifactory
repository/Git organization contains logical images/Git repositories/packages,
which have immutable manifest/commit/artifact pins. `ScanTarget.boundary` is the
report owner; `ScanTarget.scope` is the typed logical-source snapshot. The former
boundary-level `ScanScope` is now `ScanBoundary`; the former `Source` is now
`ScanScope`.

Artifactory endpoint, repository, and Docker scope models live together in
[`src/cred_scan/backend/adapters/artifactory/models.py`](src/cred_scan/backend/adapters/artifactory/models.py).
The concrete logical scopes are `DockerImageScanScope`, `GitRepositoryScanScope`,
and `PackageScanScope`. Shared schema bases live in `src/cred_scan/backend/base_models.py`;
`cred_scan.backend.models` remains the aggregate model entry point. Model imports do not load adapter implementations.
See [model ownership](doc/interfaces.md#model-ownership-and-imports).

## Configuration and commands

**Existing-workspace warning:** current schemas are inventory **7**, Titus report
**2**, and credentials **4**. They distinguish report `boundary` from logical
`scope` and replace report/workspace `scope_id` with `boundary_id`. Old keys and
versions are rejected; these changes do **not** migrate `workspace/`.

The naming refactor preserves boundary IDs, canonical target IDs, evidence
fingerprints, and directory paths. Separately authorize and preflight
[the offline field mapping](doc/interfaces.md#persistence-and-stale-state)
before reusing existing results. Schema-5 inventories additionally need the
previous Docker child-manifest ID correction and alias reconciliation, including
occurrence/fingerprint updates. Preserve raw findings and evidence bytes even
though report wrapper JSON keys change. Do not merely bump schema numbers or
discard history; the older credential-schema utility does not perform this upgrade.

Relative paths in `config.yml` resolve against that file. Results default to
`<workspace-dir>`; `workspace.results-dir` is an optional override.
``pydantic-settings` loads the selected YAML file and its adjacent `.env` without
mutating the process environment. YAML owns ordinary runtime settings; process environment
credentials override adjacent `.env` credentials. The deployment supplies
credentials through the environment, and they are never placed in command
arguments. The committed `titus` launcher uses the local adjusted Titus build copied
from the old scanner repository. The binary is stored as `titus.gz` because
the Bosch GitHub Enterprise file limit is 50 MiB; the launcher extracts it to
`.titus-cache/` and executes it. The embedded binary's SHA-256 is:

```text
df2972aa86094de2ab1cc5073e967388a2ed0bf0918d8b81d4f7693d6f28b3bc
```

```sh
uv sync --locked
cred-scan --help
cred-scan inventory
cred-scan scan
cred-scan judge
cred-scan extract
cred-scan run
```

Inventory and scan are separate manual operations. Inventory updates immutable
source pins and marks omitted sources or boundaries stale. Scan never refreshes
inventory; it processes persisted current targets, reuses each boundary's
incremental Titus datastore, exports cumulative `report.json`, appends
observations to `credentials.json`, judges `PENDING` and `ERROR` credentials,
and retains first-occurrence evidence for `VALID` credentials. Stale boundaries
and superseded targets are not scanned. `judge` and `extract` remain operator
recovery commands, and `run` is a compatibility alias for the complete scan
workflow. Returning to a superseded pin reuses its target ID and result; failed
or partial discovery cannot reactivate stale data or promote new pins. Append
publication unions all historical locations/finding IDs in first-seen order,
even when several stored occurrences share a target.

Retained evidence is checked against its path, size, and hash before reuse.
Missing or corrupt evidence fails scan/extract visibly without deleting or
overwriting bytes or metadata. Restore the verified artifact before retrying.

`src/cred_scan/orch/runtime.py` contains the `ReportBoundary` lifecycle and the small
`LocalRuntime` scheduler. A `ScanBoundaryInventory` carries a serializable
`BackendConfig` name; the runtime resolves and caches the corresponding
`BackendAdapter` while constructing the boundary. The same backend is passed to the
boundary-bound Titus scanner and content-reader flow. A boundary holds inventory,
workspace paths, and backend; its `scan(scanner, policy)`,
`judge(document, judge, extract_valid=...)`, and `extract(document)` operations
receive only the phase services they need. The scheduler hands a boundary to the
judger only after successful publication, without an additional completion flag.
One evidence operation serves immediate extraction and recovery. `Workspace` exposes typed
validated JSON read/write, inventory-path discovery, and the operation lock.
It returns an immutable `BoundaryPaths` value, not nested document/resource handles.
`src/cred_scan/orch/credentials.py` owns pure append/lifecycle transformations; orchestration
persists each checkpoint explicitly. `src/cred_scan/judge/evidence.py` owns evidence destinations
and integrity checks. Target scans and backend readers share one scratch context
primitive, each owning only its temporary child. The scan runtime returns only the completed
boundary count, which the CLI prints. The judge runtime returns the count of
attempted persisted credentials, and the extract runtime returns the count of
newly extracted credentials; their CLI commands print those summaries. INFO
logging also reports inventory boundaries, scan target attempts and outcomes,
each judgment's stable credential ID and verdict, and evidence status.
Credential values are not included in operational output. The combined `run`
command emits these phase messages before its completed-boundaries summary.
The commands are local implementation entry points; the old OpenShift and
multi-stage CLI workflow is intentionally out of scope.

Cancelling a run propagates into native async judgment instead of shielding the
entire LLM operation. Docker readers settle only an already-running blocking archive
parser before removing its archive/scratch; cancellation can wait for that local
worker, not for an unresponsive LLM call. Local tests verify this ownership;
no live LLM/Titus integration guarantee is implied.

## Layout

```text
src/cred_scan/                # installable Python package
  backend/                    # backend models, adapters, inventory, readers
  common/                     # workspace persistence and shared ports
  judge/                      # judgment and evidence ports/adapters
  orch/                       # configuration and scan/judge coordination
  scan/                       # Titus, report conversion, exclusions
  tools/                      # operator/developer utilities
  cli.py                      # Typer command surface

tests/                        # package-level tests
workspace/                    # runtime-only; ignored by Git
  <encoded-boundary-id>/
    inventory.json
    titus.ds/
    report.json
    credentials.json            # append-only credentials and lifecycle state
    evidence/
      <safe-credential-id>/<filename>
    scratch/                    # removed when no scratch scope is active
```

The Titus datastore remains the detailed forensic source. The boundary passes
its stable `titus.ds` path directly to Titus for both incremental scans and the
cumulative report export; Titus owns datastore creation and opening. `report.json`
is the latest cumulative export. `credentials.json` stores append-only normalized
occurrences and judgment state separately; raw Titus findings and rule metadata
remain in `report.json`. Every credential occurrence requires a nonempty
immutable target ID. Evidence metadata in `credentials.json` is the sole index
for retained evidence. Historical credentials, occurrences, and evidence are
not removed by scanning. Output paths are relative to the report boundary and
preserve a sanitized source filename.

## Documentation

- [Architecture](doc/architecture.md)
- [Interfaces](doc/interfaces.md)
- [Ports](doc/ports.md)
- [End-to-end flow](doc/end-to-end.md)

The historical schema migration utility is an operator/developer utility and
is not invoked by the CLI or runtime harness. The earlier schema-5 target-pin
migration was executed offline as a temporary one-shot operation and is not
retained in the runtime harness. Migration to the current schemas remains a
separate task. The historical schema-2→3 utility keeps its old output contract
and does not make that output readable by the current runtime.
The existing `artifactory-cred-scan/` checkout is the behavioral reference for
Artifactory API behavior, Titus invocation, Docker-layer access, and credential
deduplication. This project uses direct `httpx` for its asynchronous
Artifactory transport; `requests` may still be present transitively through
DSPy. Its old CLI, OpenShift deployment, human-review workflow, and
training export are not copied into this implementation.
