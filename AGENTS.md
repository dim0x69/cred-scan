# Project instructions

## Design stage

This repository is an evolving credential-scanner design. Keep application
behavior as Python Protocol signatures with ellipsis bodies and static examples
until the user explicitly requests implementation. Use Pydantic v2 for data
models and uv for dependency management. Typer registration/help is allowed for
the mock CLI; command bodies must not start scans, load credentials, or call LLMs.

## Serena MCP

This project is configured for Serena through `.mcp.json`. When using Pi,
use the Serena MCP tools for Python code navigation and semantic edits: prefer
`get_symbols_overview`, `find_symbol`, `find_referencing_symbols`,
`get_diagnostics_for_file`, `replace_symbol_body`, `insert_*_symbol`, and
`rename_symbol` over line-based exploration or edits. Call Serena's
`initial_instructions` tool before starting coding work. Use Pi's built-in tools
for shell commands and non-code files when Serena does not provide an advantage.

## Module responsibilities

- `src/cred_scan/backend/`: configured instances, ScanBoundary/ScanScope identities,
  inventory, and client ports.
- `src/cred_scan/scan/`: Titus invocation, datastore export, report conversion,
  deduplication, exclusions, and pre-judgment credential documents, taking
  ScanTarget directly.
- `src/cred_scan/judge/`: judgment protocols, direct backend tools, persistence,
  and evidence.
- `src/cred_scan/orch/`: scan/judge scheduling, boundary gates, configuration,
  and coordination.
- `src/cred_scan/cli.py`: thin Typer command surface; delegates conceptually to orchestration.
- `src/cred_scan/orch/configuration.py`: central config loading implementation; schemas live in
  `src/cred_scan/orch/models.py` and the loading port lives in `src/cred_scan/orch/proto.py`.
- `src/cred_scan/common/`: cross-cutting workspace models, protocol, and implementation.

Avoid circular dependencies. Backend discovery must not import scan or judge;
scan must not import judge or orchestration. `cred_scan.orch.configuration` owns all
orchestration settings and must not import pipeline/scheduler code.
`src/cred_scan/common/` stays independent of orchestration and runtime feature behavior. Its
workspace persistence layer may import the explicitly persisted document models
used by the current workspace contract, but must not import adapters, service
implementations, or create circular feature dependencies.

## Preserve these design contracts

- `ScanBoundary` is the notification/report boundary: Artifactory repository or
  Git organization. `ScanScope` is the logical source: Docker image, Git
  repository, or package. `ScanTarget.boundary` owns the report grouping;
  `ScanTarget.scope` holds the logical scope and immutable pin. Do not collapse
  these levels or reintroduce the former `Source` model.
- One shared Titus database per report boundary; retain every source occurrence.
- One worker owns one target at a time, including all its Titus invocations.
- Shared-database parallel CLI execution is conditional on the adjusted Titus
  build's guarantees; serialized access per scope is the current design default.
- Use the user's adjusted Titus build, including native Artifactory and Docker
  file exclusions. Do not replace those capabilities with upstream assumptions.
- Version selection is backend-inventory-owned: Docker inventory chooses the
  newest manifest/platform by timestamp and Git inventory chooses the newest
  commit on `main` by commit timestamp. Do not reintroduce Docker/Git selection
  settings into central config.
- Each report boundary persists an inventory document containing fully pinned
  `ScanTarget` objects and nests one backend -> repository -> targets tree.
  Inventory is manual and exclusive with scan. Refresh retains all immutable
  pins: new pins append pending targets, returning pins reuse their results,
  and authoritative absence marks sources/boundaries stale without deletion.
  Failed/partial discovery preserves lifecycle and current pins. Docker pin
  identity uses the selected child manifest digest, not parent-index or platform
  selection metadata. Inventory schema 7 rejects noncanonical target IDs and
  uses `boundary`/`scope` fields. Report schema 2 and credential schema 4 use
  `boundary_id`; no runtime migration, old-field aliases, or legacy-ID fallback
  is allowed.
  Empty repositories without errors remain outside report boundaries.
- Scan only produces judge candidates after a final boundary-wide Titus export;
  it groups credentials per repository, applies exclusions, and preserves all
  paths and pinned target references. Judge runs only afterward. Every credential
  occurrence requires a nonempty pinned target ID; legacy checkpoints without
  one are rejected, with no migration or fallback.
- Store only extracted files containing nonexcluded findings, plus small
  provenance/result metadata. Delete scan scratch at target completion. Keep
  judge scratch through judgment and VALID-only first-occurrence evidence
  extraction, then remove it; reuse retrieved bytes before downloading again.
  Only VALID judgments trigger new evidence extraction. Append publication and
  later judgments do not delete historical evidence. Reuse checks path/size/hash;
  missing or corrupt retained evidence fails visibly without overwriting it.
- No long-lived whole-image, whole-repository, archive, or general blob cache.
  Titus's own caches must follow the same lifecycle. Additional judge context
  is retrieved temporarily from immutable references and discarded afterward.
- All runtime settings live in `config.yml`, including `workspace-dir`, Titus,
  LLM/environment settings, and the two central exclusion-file paths.
  Results default to `<workspace-dir>`; an explicit `results-dir` override is
  resolved relative to `config.yml`, like other relative paths.
- Internal APIs have no external compatibility requirement. Backends create
  repository-bound content readers directly; scan orchestration returns only
  the completed boundary count, not accumulated credential documents.
- Exclusions come from `path-exclusion.list` and `cred-value-exclusion.list`.
  Load both files once per run; keep their patterns plain and do not hash or
  version exclusion contents.

## Keep documentation synchronized

Updating `doc/` is part of every design change, not a separate follow-up task.
Before finishing a change, update the affected documents in the same task:

- `doc/architecture.md`: module ownership, dependencies, configuration, lifecycle.
- `doc/interfaces.md`: data models, relationships, identity and field contracts.
- `doc/ports.md`: protocol methods, callers, preconditions and outcomes.
- `doc/end-to-end.md`: worked example reflecting the current contracts.

When moving/renaming interfaces, update documentation links and static example
imports. When a contract changes, update both its port description and the
end-to-end example. Keep README as an entry point to the detailed documents.
Clearly distinguish a proposal, a user-provided capability, and verified behavior.
Do not describe design stubs as working implementations.

## Verification

Use the uv locked environment. For structural changes, check imports and
Pydantic schema generation. For CLI changes, check Typer help and command help.
Static example construction is allowed. Ensure protocol and mock command bodies
remain stubs. Do not add production logic merely to make a design demo runnable.
