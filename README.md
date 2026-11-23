# logwatch

A small, read-only log watcher for a single Linux host or container.

- **Tier 1 (no AI):** every 2 minutes, checks that declared services are up and alerts on crashes, restart loops, OOM kills, and silent logs.
- **Tier 2 (digest):** hourly, tails declared log files, redacts secrets, applies YAML rules, clusters whatever is left, and asks a tool-less LLM to classify the clusters. One digest per day; high-severity findings alert immediately.

It never restarts, blocks, or edits anything. Log text is treated as untrusted data.

## Quick start (development)

```sh
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/pytest
.venv/bin/logwatch replay fixtures/path-scan-300
```

## Layout

- `src/logwatch/` the package, one module per responsibility
- `rules/default.yaml` noise allowlist and known-bad rules
- `fixtures/` synthetic incidents replayed by the test suite
- `deploy/` OpenRC init script and install notes

Install on Alpine/OpenRC: `sh deploy/install.sh --dry-run`, then `sh deploy/install.sh` (details in `deploy/install.md`). What is unverified about the service probe: `deploy/probe-notes.md`.

Design and build plan: see `docs/README.md`.
