# Boundary state plan

The workflow below records the agreed design. The status-cleanup section adds
recommendations for review and identifies confirmed decisions: explicit
extraction state, removal of the document-level `incomplete` flags, and a
`--failed` option on each source command. Other proposals are not yet agreed
invariants. This document does not implement the changes.

## Operating rules

- For a given backend, at most one instance of each source command runs at a
  time: `scan`, `judge`, and `extract`.
- Those three commands may run in parallel across different boundaries. Each
  boundary progresses through its stages sequentially and has one writer.
- Inventory runs only when no other command for the same backend is running.
  No other command starts for that backend until inventory exits. This is an
  operating rule, without a persisted backend `busy` state or a backend lock.
- Different backends are independent.
- A boundary does not automatically return to an earlier stage. Re-entry
  requires an explicit human action, coordinated so the boundary is idle.

Under this contract, boundary phase handoffs replace the need for boundary
locks. Removing the existing locks depends on implementing the handoffs first.

## Boundary phase

Persist one phase indicating which command may process the boundary:

```text
scan -> judge -> extract -> done
```

| Phase | Eligible command | Handoff |
| --- | --- | --- |
| `scan` | `scan` | Finish scan attempts, export the report, and publish credentials; advance to `judge`. |
| `judge` | `judge` | Finish the selected judgment pass and save judgment results; advance to `extract`. |
| `extract` | `extract` | Finish the selected extraction pass and save evidence metadata; advance to `done`. |
| `done` | None for normal stage processing | Remain complete until explicitly reopened. |

The boundary stays in its current phase while that command works. Separate
boundary `running` states are unnecessary under the one-instance-per-stage rule.

Availability (`available` / `absent`) remains separate from phase. Absent
boundaries do not run source operations; their accumulated results and evidence
remain retained. Existing target, judgment, and extraction states retain item
progress and errors. The boundary phase controls the stage handoff.

## Each invocation is one finite batch

1. Select the available boundaries currently in the command's phase once.
2. Load and process the selected work. Judge never processes an unfinished scan
   boundary; extract never processes an unfinished judgment boundary.
3. Save results and advance each completed boundary's phase.
4. Clean up resources and exit.

There is no polling, waiting for upstream work, or repeating the batch.
Boundaries that become ready after selection are left for a later invocation.
Different selected boundaries may run concurrently. Targets within a boundary
remain sequential, with Titus's existing internal parallelism and bounded
per-target retries. This plan does not introduce automatic retry passes.

### Explicit retries with `--failed`

Confirmed command interface:

```sh
cred-scan scan --failed
cred-scan judge --failed
cred-scan extract --failed
```

| Command | Failed work to requeue |
| --- | --- |
| `scan --failed` | Scan targets with `result.status == failed`. |
| `judge --failed` | Credentials with `judgment.status == failed`. |
| `extract --failed` | Credentials with `extraction.status == failed`. |

Proposed selection semantics: `--failed` adds failed items to the command's
normal pending work for one invocation. Select the work once, requeue the chosen
failures as `pending` while preserving diagnostics, and run the normal stage.
Failures produced during this invocation are saved for a later explicit retry;
the command does not repeat its selection or loop until everything succeeds.

The flag authorizes reopening the requested boundary phase when saved failed
work exists, including a boundary that has advanced to a later phase or `done`.
It does not bypass unfinished upstream phases: judge still needs finished scan
publication, and extract still needs a finished judgment pass. The human ensures
the affected boundaries are idle under the operating rule; no lock or backend
busy state is added. Boundaries with neither normal work nor eligible failed
items are not reopened by this flag.

Preserve successful scans, completed judgments, retained evidence, and other
stages' results. Finish the requested pass and use its normal final-write phase
handoff; do not run downstream commands automatically. Existing `--backend`
selection also applies to these invocations.

`--failed` does not select `skipped` extraction or completed `invalid`/`unknown`
judgments. Those are completed decisions, not failed attempts. Deliberately
reconsidering such decisions remains a separate interface question.

## Publish the phase as the final write

Advancing a phase hands the boundary to the next process immediately:

```text
save all stage results and required artifacts
finish any work that can still write boundary data
atomically persist the next phase
perform no further boundary-data writes from the previous stage
```

Routine checkpoints keep the current phase. The final phase publication must
follow every result write, including repeated writes of unchanged documents.
The next command reads the phase before loading the boundary's working data.

Current `Boundary.checkpoint()` writes inventory, report, then credentials.
Clearing `publication_pending` in inventory and calling that checkpoint is not
a safe handoff without locks: judge could save a result before scan rewrites its
older credentials document. The new phase publication must be a distinct final
write, not an assignment followed by another whole-boundary checkpoint.

If a run stops before advancing the phase, downstream commands remain
ineligible. A later invocation of the same stage can use saved item progress.
Advancing the phase must not erase item errors or accumulated results. Existing
scan policy still allows available findings to proceed after failed target
attempts, provided export and credential publication succeed.

## Proposed status cleanup

Use lowercase persisted values throughout, including the phase names above.
Keep distinct fields for workflow phase, backend availability, execution
results, and credential assessment. Retain concrete diagnostics without storing
redundant completeness flags. The following is the recommended target model,
subject to review except where a decision is explicitly marked confirmed.

| Field | Proposed values or meaning |
| --- | --- |
| `boundary.phase` | `scan`, `judge`, `extract`, `done`; store in `boundary.json`. |
| `boundary.availability` | Keep `available`, `absent`. |
| `target.result.status` | `pending`, `running`, `scanned`, `failed`. |
| `target.result.retryable` | Propose removing the persisted flag; explicit retry selects `failed` targets. Keep immediate retry decisions local to the scanner. |
| `credential.judgment.status` | `pending`, `completed`, `failed`. |
| `credential.judgment.verdict` | `valid`, `invalid`, `unknown`, or `null` when there is no completed assessment. |
| `credential.extraction` | Always present, with an explicit status; no `null` used to imply pending work. |
| `credential.extraction.status` | `pending`, `skipped`, `retained`, `failed`; `pending` is confirmed, and `skipped` is the proposed representation of no eligible extraction work. |
| Report `incomplete` | Remove; confirmed decision. Preserve target results and report errors. |
| Credentials `incomplete` | Remove; confirmed decision. Preserve conversion errors and credential results. |
| Inventory `publication_pending` | Remove once the phase owns publication recovery. |

### Simplify retry selection

Currently `retryable` is used operationally: `Boundary._scan_target()` stops
its bounded retry loop when the scanner marks an error non-retryable. Examples
include authorization errors, missing manifests, and unsupported target types.
A transient connection failure can instead receive another attempt. Both cases
have status `failed`, so checking that status alone does not preserve the
current immediate-retry policy.

For a later human-requested retry, `status == failed` is sufficient. The human
may have fixed credentials or another cause since the previous attempt; a saved
retry-policy flag should not control that decision.

Proposed simplification: remove `ScanTargetResult.retryable` and move the existing
bounded scan retry loop into `TitusCliScanner.scan()`. The scanner uses its
existing error classification only during that invocation, stops immediately
for known non-transient errors, and retains the current maximum of three
attempts for transient failures. It continues to mutate the boundary-owned
target and return no replacement. Boundary owns scratch and checkpoints before
and after this call; targets and Titus invocations remain sequential.

Persist target progress, outcomes, and diagnostics without the retry-policy
flag. `scan --failed` selects failed targets and requeues them as `pending`;
ordinary recovery resumes pending/interrupted targets and leaves
saved failures alone. Remove the flag from the schema, scanner mutations, and
boundary selection/logging, and drop stored values during migration. No
additional persisted failure classification is needed.

### Remove redundant completeness flags

Confirmed decision: remove `TitusReport.incomplete` and
`CredentialsDocument.incomplete`. No command uses either flag to choose work,
retry an item, or block a downstream stage. The current uses are limited to:

| Field | Where it is set | Where it is consumed |
| --- | --- | --- |
| `report.incomplete` | `Boundary._scan()` marks it true when selected targets did not all finish as `scanned`, or inventory errors are present; any existing report incompleteness is preserved. | Stored in `report.json` and propagated into credential conversion. |
| `credentials.incomplete` | `deduplicate_report()` combines report incompleteness with occurrence-resolution/conversion errors. `merge_scan()` stores the latest publication's value. | Stored in `credentials.json` and included in the scan-completion log. |

Scan problems can be identified from the saved target statuses and errors when
needed. Failed targets alone do not capture conversion problems: every target
can scan successfully while occurrence resolution fails. Keep those concrete
conversion diagnostics in `credentials.errors`, together with existing report
and target diagnostics. Intentional exclusions are not conversion failures.

If a future display needs a completeness summary, calculate it from the
available target results and relevant error records at that time. Do not add a
replacement boolean, persisted summary, or reporting helper without a concrete
consumer. Such a summary describes the available records; a later inventory
replacement must not be mistaken for a full history of past target outcomes.
Boundary phase remains the sole control for stage handoff.

During implementation, remove the two fields and their constructor arguments,
placeholder defaults, propagation through export/conversion/merge, and the
`incomplete` scan-log field. Update the affected tests and documentation. Drop
the fields from the existing workspace during migration while preserving
findings, target results, judgments, extraction metadata, and error details.
Removing these flags must not suppress error reporting or change publication
and downstream processing of available findings.

### Replace the publication flag with phase

Today `publication_pending` records unfinished report export and credential
publication. It is set before scanning, not just during export. A false value
also occurs before the first scan, so it is not a standalone completion state.

Keep the boundary in `scan` until report export, conversion, merge, and all
result writes succeed. Then publish `judge` as the final write. If publication
is interrupted, the phase remains `scan`; a later invocation must finish
publication even when all target scans are already complete. Remove the flag
from the schema, inventory merge, and runtime eligibility checks together.
Do not introduce a separate `publishing` phase.

Handle zero-target boundaries explicitly: export an existing cumulative
datastore when present; otherwise publish a valid empty result while preserving
credential history. A lack of pending targets must not strand a boundary in
`scan` or discard past findings.

If scanning stops before export, the boundary remains in `scan`. On the next
invocation, resume any pending or interrupted running targets first. Keep
already checkpointed `scanned` and `failed` results. If every target's attempts
have finished, skip scanning entirely and run export, conversion, and merge,
then advance to `judge` after the final result writes. An interrupted publication
must not automatically requeue completed failed attempts; retrying those
requires an explicit human request based on `status == failed`.

This is intended recovery behavior. The current `_target_needs_scan()` still
selects retryable failed targets on subsequent scan invocations and must change
to distinguish ordinary recovery from an explicitly requested retry.

### Remove the unused target status

The current scanner never produces `partial`; it produces `scanned` or `failed`.
Remove `partial` from the target schema and eligibility checks. Migrate any
stored `partial` result to `failed`, retaining its errors, return code,
timestamps, and accumulated findings. A failed target may still have
contributed findings to the cumulative datastore.

Keep the existing treatment of Titus warnings for this change: warning-bearing
attempts remain failed. Introducing a distinct partial-success policy would
require a separate definition and decision.

Published credentials from failed target attempts remain eligible for judgment.
Credentials are deduplicated across the boundary's cumulative findings and do
not carry a direct scan-target ID used to gate judgment. Their occurrence
locators still identify the immutable source versions and files, and one
credential may occur in several targets or scan runs.

Consequently, a target's `failed` status records the scan failure without a
separate report flag or suppression of the credentials it contributed. Once
boundary export and credential publication succeed, judgment processes the
published candidates regardless of which target attempts succeeded. Normal
exclusions and occurrence validation still apply during publication.

### Separate judgment execution from verdict

Add `judgment.status` and reserve `verdict` for an actual assessment:

- `pending`: no completed attempt; verdict is `null`.
- `completed`: verdict is `valid`, `invalid`, or `unknown`.
- `failed`: execution failed; verdict is `null`, with a separate `error` message.

Keep `reasoning` for assessment explanations and validate these combinations.
An uncertain but completed assessment is `completed` with verdict `unknown`.
The judge operation changes only judgment fields, then advances the boundary
phase after its final result checkpoint. It does not set extraction status,
decide that extraction was skipped, or reset previous extraction results.
A completed `valid` or `unknown` judgment permits evidence extraction under the
existing policy; the extract operation applies that policy when it runs.

Update the DSPy output schema and adapter normalization to lowercase values.
Treat an invalid verdict output as a failed judgment instead of silently
converting it to `unknown`, which currently enables evidence extraction.

### Clarify extraction state

Use `failed` consistently for execution failure in scanning, judgment, and
extraction. Change extraction `ERROR` to `failed` and `RETAINED` to `retained`.

Confirmed requirement: extraction has an explicit `pending` state, consistent
with judgment. Store an extraction object on every credential. Its execution
state is persisted independently and is never inferred from a missing object
or reconstructed from a verdict when loading the credential.

Proposed ownership: each stage changes its own result. Judgment produces the
assessment; extraction owns its pending, skipped, retained, and failed states.
The boundary phase coordinates their order. Extraction still consults the saved
assessment to enforce the existing `valid`/`unknown` eligibility rule. A check
of whether an operation is permitted does not replace its explicit execution
state. Eliminating that eligibility check would require changing which
credentials are allowed to produce retained evidence, which is not proposed.

Proposed complete state set:

- `pending`: the extract operation has not processed this credential. New
  credentials start here independently of judgment; boundary phase prevents
  extraction before the judgment pass finishes. Pending does not guarantee that
  evidence will be collected.
- `skipped`: the extract operation considered the credential but its saved
  judgment did not permit evidence collection; persist the reason. This is a
  proposed additional state so processed ineligible items do not stay pending.
- `retained`: evidence was saved, with its path, size, and hash.
- `failed`: an extraction attempt failed, with its error preserved.

The extract operation selects its `pending` credentials once, then processes
each selected item according to the saved judgment. It trusts the boundary
phase handoff: judgment finishes its pass before publishing `extract`. There is
no separate extraction recovery path for an unfinished judgment in this phase.

| Saved judgment | Action owned by the extract operation |
| --- | --- |
| Completed `valid` or `unknown` | Attempt first-occurrence evidence retention; save `retained` or `failed`. |
| Completed `invalid` | Save `skipped` with the reason; do not read or retain source bytes. |
| Failed judgment | Save `skipped` because no completed eligible assessment is available; do not read or retain source bytes. |

Always preserve `retained` evidence and its metadata, including during explicit
rejudgment. Scan merges must likewise preserve existing extraction objects
instead of replacing them with a new credential's default `pending` object.
Although judgments and extraction results share `credentials.json`, their
lifecycle fields have separate owners. A judgment checkpoint preserves the
saved extraction fields; an extraction checkpoint preserves the judgment.
There is no judgment-side extraction-state preparation to complete or recover.

Resume unfinished extraction `pending` items after interruption. An ordinary
extract invocation does not retry `failed` or reconsider `skipped` items.
`extract --failed` requeues selected failed extractions as `pending`, preserving
diagnostics, and reopens the boundary's `extract` phase when needed. The extract
operation then checks the saved assessment again. Rejudgment alone does not
reset extraction status, and extraction retry does not repeat judgment.
Reconsidering `skipped` extraction is outside `--failed`; its explicit interface
remains to be designed, including skips caused by a subsequently retried failed
judgment. Keep attempted-extraction counts limited to actual retention attempts;
recording `skipped` is not a source-read or retention attempt.

Validate the metadata appropriate to each extraction state; pending or skipped
items must not claim retained evidence, and skipped items carry their reason.
An existence audit that finds missing evidence must report it without changing
`retained` to `failed`, reopening the phase, or replacing evidence. During an
extract invocation, audit retained evidence in
selected `extract` boundaries and separately audit available `done` boundaries
from the invocation's snapshot. Auditing a `done` boundary is read-only.

### Separate completion from success and retries

Recommend advancing after a finite pass completes, even when individual items
have handled failures. Save each failure in the result owned by that stage.
The extract operation records `skipped` for its pending items when the saved
judgment is invalid or failed; judgment does not write that extraction outcome.
`done` means the extraction pass finished; it does not promise that every item
succeeded. Saved item statuses and concrete error records describe failures;
there are no aggregate report or credential completeness flags.

Cancellation, fatal errors, or failed result persistence leave the boundary in
its current phase. Resume pending or interrupted work from saved item progress
on a later explicit command. Saved item failures are completed attempts and
require an explicit retry request; reopening a boundary alone must not silently
repeat them. Apply the same distinction to scan, judgment, and extraction.
After a phase has advanced, item failures do not automatically reopen it.
The corresponding `--failed` command reopens the required phase while the
boundary is idle, preserving successful judgments and retained evidence.
Extraction retries must not require rejudgment.

### Migrate values and validate the transition

Apply these changes to the single existing workspace together with the phase
schema, preserving accumulated results and evidence:

| Existing value | Proposed migration |
| --- | --- |
| Judgment `PENDING` | Status `pending`, verdict `null`. |
| Judgment `VALID`, `INVALID`, `UNKNOWN` | Status `completed`, corresponding lowercase verdict; preserve reasoning. |
| Judgment `ERROR` | Status `failed`, verdict `null`; preserve the stored failure message in `error`. |
| Extraction `RETAINED`, `ERROR` | Status `retained`, `failed`; preserve metadata and error details. |
| Extraction `null` | Create explicit status `pending` independently of the judgment; only a later extract operation records its own result or skip. |
| Target `partial` | Status `failed`; preserve diagnostics and findings. |
| Target `retryable` | Drop the flag; preserve the target's status and diagnostics. |
| `publication_pending = true` | Preserve unfinished publication by assigning phase `scan` before dropping the flag. |
| Report or credentials `incomplete` | Drop the field; preserve findings, item results, and all existing error diagnostics. |

A false publication flag alone must never establish a completed scan. Inspect
the existing inventory, report, credentials, and item states when assigning
initial phases; report ambiguous cases instead of guessing that work completed.
When migration creates pending extraction items, assign a phase that allows
them to be processed: `extract` if the upstream passes are complete, otherwise
the appropriate upstream phase. Do not assign `done` while newly materialized
pending extraction remains. A saved invalid verdict does not prove that an
extraction skip was already processed.
Identify any historical results that lack metadata required by the proposed
validation before migration, without inventing metadata or replacing evidence.

Update schemas, defaults, comparisons, adapter inputs/outputs, tests, and
documentation together. Runtime should accept the new format after the offline
migration, without a permanent uppercase/lowercase compatibility layer.

Verify publication recovery with all targets scanned, final-write ordering,
judgment status/verdict validation, independent ownership of judgment and
extraction fields, explicit extraction selection and verdict-based permission,
explicit retry versus interruption recovery, read-only retained evidence
audits, and preservation of existing
results through migration. Cover publication of findings from failed scan
targets and ensure migration and scan merges preserve all extraction states.
Verify removal of completeness flags without losing conversion diagnostics or
changing stage eligibility. Verify that scanner-local bounded retries retain
the existing transient/non-transient behavior without a persisted retry flag.
Verify `--failed` selection for each command, reopening of later phases without
bypassing upstream work, preservation of successful results, and one finite
pass even when retried items fail again.

## Details to settle before implementation

- Review the proposed cleanup above, especially judgment's separate execution
  status, extraction's proposed `skipped` state and transition details,
  scanner-local bounded retries without persisted `retryable`, handled-failure
  advancement, and read-only audits of `done` boundaries.
  Explicit extraction `pending` is confirmed. The proposed separation keeps
  judgment from mutating extraction state and applies verdict eligibility
  inside the extract operation. Removing both document-level `incomplete`
  flags is also confirmed.
- Specify inventory-driven phase changes for new or changed targets, unchanged
  inventories, empty boundaries, and boundaries becoming absent or available.
- The retry interface is confirmed as `--failed` on scan, judge, and extract.
  Review the proposed additive selection semantics (pending plus failed).
  Deliberate reconsideration of completed judgments or skipped extractions is
  outside that flag and remains a separate interface decision.
- Resolve initial phases for ambiguous interrupted or partially completed
  boundaries in the existing workspace before applying migration.

## Implementation follow-up

The current implementation still uses workspace and boundary locks, has no
boundary phase field, and selects judgment/extraction work from credential
states. It does not yet implement the handoff contract above.

When implementation is requested:

1. Add the phase and approved status-schema changes, and migrate the existing
   workspace in the same task, including removal of both `incomplete` fields.
2. Select ready boundaries once and gate document loading and services by phase.
   Add `--failed` to scan, judge, and extract with the retry selection described
   above, preserving successful work.
3. Separate routine checkpoints from the final atomic phase publication and
   replace `publication_pending` with phase-based recovery.
4. Remove workspace and boundary locking and Titus lock-descriptor inheritance.
5. Verify finite selection, concurrent work on different boundaries, final-write
   ordering, interruption recovery, and explicit re-entry.
6. Synchronize the affected `AGENTS.md` invariants and `doc/end-to-end.html`,
   distinguishing the agreed design from any remaining implementation gaps.
