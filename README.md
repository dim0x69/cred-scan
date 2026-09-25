# Credential scanner

A design-stage credential scanner with backend-owned source locators,
backend-scoped workspaces, boundary-scoped Titus datastores, judgment, and evidence retention. Commands process
boundaries concurrently; each boundary scans its targets sequentially with one
Titus scanner. Titus internal parallelism is configured through `internal_workers`.

Each source command snapshots ready boundaries once and exits after that batch.
Boundary phase advances `scan → judge → extract → done` only after saving results
and cleaning up. Different stages may run simultaneously on different boundaries.

Operating rules per backend: run at most one instance of each source command,
and run inventory alone. There are no command or boundary locks.
Use `scan --failed`, `judge --failed`, or `extract --failed` to include saved
failures alongside pending work. Retrying an earlier stage requires affected
boundaries to be idle. It never bypasses unfinished upstream work.

## Documentation

The authoritative workflow and model documentation is the self-contained
[visual end-to-end guide](doc/end-to-end.html). It is the main documentation
artifact and must be kept synchronized with code changes.

## Development

```sh
uv sync --locked
uv run pytest
cred-scan --help
cred-scan inventory add
cred-scan inventory update
cred-scan scan
cred-scan judge
cred-scan extract
```

The repository remains a design-stage project. Current runtime behavior and
future capabilities are distinguished in the documentation; GHES/Git, package,
OpenShift, user acceptance, and mitigation workflows are not implemented.
