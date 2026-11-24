# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[semantic versioning](https://semver.org/).

## [2.0.0] - 2026-11-24

The single-file Streamlit prototype is now a packaged tool with a CLI, a library
API, and a thin UI. Behaviour is passive by default and every network path is
scope-checked.

### Added

- `reconpulse` CLI with `scan`, `techniques`, `auth-example`, and `verify-audit`
  subcommands, multi-target runs, `--resume`, and five export formats.
- Guarded HTTP client: one session, identifying User-Agent, retries with bounded
  backoff, size cap, redirects validated hop by hop, in-memory cache.
- SSRF guard that normalises decimal, hex, octal, short IPv4 and IPv6 forms and
  blocks private, loopback, link-local, CGNAT, TEST-NET, reserved, multicast, and
  cloud metadata addresses. Metadata is always blocked, even with
  `--allow-private`.
- Scope allowlist with `scope.out` precedence, wildcards, CIDR, and IP literals;
  out-of-scope discoveries are recorded without being contacted.
- Authorization gate for active mode: strict schema validation, validity window,
  scope checks, per-technique allowlist, human confirmation, and a `--dry-run`
  plan that sends no requests.
- Eleven active techniques in three tiers: DNS records, TLS handshake, `OPTIONS`
  method read, CORS probe, well-known paths, TCP port check, curated content
  discovery, read-only GraphQL check, sensitive-file existence check, marker
  reflection check, and canary-based redirect check.
- Operational controls: global and per-host rate limits, request budget,
  per-host circuit breaker, kill switch, interruption-safe partial reports.
- Hash-chained JSONL audit log with `verify-audit`.
- Secret detection with mandatory masking; sensitive files are recorded by URL,
  status, size, and hash only.
- Analyzers for headers, cookies, technology fingerprinting, endpoints,
  contextual parameter rules, source maps, and CORS.
- Transparent weighted risk engine and JSON, CSV, Markdown, HTML, and SARIF
  (2.1.0) reports.
- Streamlit interface that reuses the pipeline and the authorization gate.
- Offline test suite (265 tests, 83% coverage), ruff and mypy configuration,
  Dockerfile, and CI workflow.

### Changed

- `recon_pulse.py` was replaced by the `reconpulse` package; the old entry point
  and `requirements.txt` were removed in favour of `pyproject.toml`.
- Findings now always carry confidence, evidence type, remediation, and a safe
  manual verification step.

### Fixed

- Scope checks now recognise IP literals, including in `scope.out`.
- `AppConfig.from_mapping` accepts an unset per-host rate.

### Known limitations

- DNS rebinding inside the validation window is not fully defeated.
- Certificate transparency is not queried.
- Merged `Set-Cookie` headers can under-report cookie flags.
- `--dry-run` plans one target when several are supplied.
- Authorization expiry is checked at start, not enforced mid-run.

## [1.0.0] - 2026-03-27

Initial prototype: a single Streamlit file that fetched a page, extracted
scripts and endpoints, and applied name-based heuristics with a simple risk
score.
