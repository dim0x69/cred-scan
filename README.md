# Credential scanner

A design-stage credential scanner with backend-owned source locators,
one-backend workspaces, boundary-scoped Titus datastores, judgment, and evidence retention.

## Documentation

The authoritative workflow and model documentation is the self-contained
[visual end-to-end guide](doc/end-to-end.html). It is the main documentation
artifact and must be kept synchronized with code changes.

## Development

```sh
uv sync --locked
uv run pytest
cred-scan --help
cred-scan inventory
cred-scan scan
cred-scan judge
cred-scan extract
```

The repository remains a design-stage project. Current runtime behavior and
future capabilities are distinguished in the documentation; GHES/Git, package,
OpenShift, user acceptance, and mitigation workflows are not implemented.
