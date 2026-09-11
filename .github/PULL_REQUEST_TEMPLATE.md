## What and why

<!-- The problem first, then the change. Say which layer it lives in: shim, host state,
     or server (see CONTRIBUTING.md). A security fix in the server layer alone is not a fix. -->

## Effect on deployed hosts

- [ ] Shim fingerprint unchanged
- [ ] Fingerprint changes — users must run `safereach shim-update --all` (changelog says so)
- [ ] Root-owned host state changes — users must re-enrol `--hardened` (changelog says so)

## Checks

- [ ] `uv run pytest` green, `ruff check` and `ruff format --check` clean
- [ ] End-to-end suite run locally (`SAFEREACH_E2E=1 uv run pytest tests/e2e`) if this
      touches the spec, the shim, the remote scripts, or `ssh.py`
- [ ] New attack strings in `tests/conftest.py` for anything this makes reachable
- [ ] Changelog entry, if user-visible
