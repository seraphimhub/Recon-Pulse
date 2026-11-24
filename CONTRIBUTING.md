# Contributing

Thanks for helping improve ReconPulse. This project touches live systems, so
contributions are reviewed with safety and predictability first.

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[ui,dev]"
```

## Before opening a pull request

```bash
ruff format src tests
ruff check src tests
mypy src
pytest --cov=reconpulse
```

All four must pass. New behaviour needs a test that runs offline; the suite uses
a threaded mock server on `127.0.0.1` and must never reach the internet.

## Non-negotiables

- **No new network egress.** Every request goes through
  `reconpulse.core.http_client.HTTPClient`. Modules may not import `requests`,
  `httpx`, `urllib.request`, sockets, or DNS libraries to talk to a target
  directly; the few modules that need non-HTTP work (TLS handshake, DNS, TCP
  connect) validate scope and addresses first and are documented as such.
- **Read-only only.** `GET`, `HEAD`, `OPTIONS`. No exploit payloads, fuzzing,
  brute force, state-changing requests, DoS, evasion, or credential use.
- **Scope and SSRF checks stay on every path.** A change that weakens
  `core/netguard.py` or `core/scope.py` needs tests for the bypass it might open.
- **Secrets never leave the analyzer.** Masked values only; no response bodies or
  file contents in reports, logs, the UI, or the audit log.
- **No silent failures.** A refused or blocked action must be reported in the
  report `errors`/`notes`, not swallowed.

## Adding an active technique

1. Create `src/reconpulse/active/<name>.py` with a module object exposing
   `name`, `level`, `description`, `plan(ctx)`, and `run(ctx)`.
2. Return findings built with `active_finding(...)` so
   `evidence_type=active_probe` and confidence are always set.
3. Use `ctx.client` for HTTP; validate scope before any socket or DNS work.
4. Register the module in `active/__init__.py` and add its level to
   `TECHNIQUE_LEVELS` in `core/authorization.py`.
5. Document it in `docs/ACTIVE_MODE.md`, including what it sends and what it
   deliberately does not.
6. Add tests under `tests/`.

## Commits and branches

- Work on a feature branch, not `main`.
- Conventional commits: `feat(scope): ...`, `fix(core): ...`, `test: ...`,
  `docs: ...`, `refactor: ...`, `chore: ...`.
- Subject line in English, imperative mood, 72 characters or fewer.
- One logical change per commit; keep formatting-only commits separate.
- Do not add AI attribution trailers, bot co-authors, or generated-with lines.
- Never commit `authorization.yaml`, `reconpulse-output/`, audit logs, reports,
  `.env` files, or any captured evidence. See `.gitignore`.

## Review checklist

- [ ] tests pass offline, coverage stays at or above 80%
- [ ] `ruff format --check`, `ruff check`, and `mypy src` are clean
- [ ] new findings include severity, confidence, evidence type, explanation,
      remediation, and a safe verification step
- [ ] documentation updated (`README.md`, `docs/ACTIVE_MODE.md`, `CHANGELOG.md`)
- [ ] no new dependencies without justification
