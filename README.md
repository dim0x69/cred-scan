# Credential scanner

A design-stage credential scanner with backend-owned source locators,
boundary-scoped Titus datastores, judgment, and evidence retention.

## Documentation

The authoritative workflow and model documentation is the self-contained
[visual end-to-end guide](doc/end-to-end.html). It is the main documentation
artifact and must be kept synchronized with code changes.

Supporting documents:

- [Architecture](doc/architecture.md)
- [Interfaces](doc/interfaces.md)
- [Ports](doc/ports.md)

## Development

```sh
uv sync --locked
uv run pytest
cred-scan --help
```

The repository remains a design-stage project. Current runtime behavior and
future capabilities are distinguished in the documentation; GHES/Git, package,
OpenShift, user acceptance, and mitigation workflows are not implemented.
