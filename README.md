# ReconPulse

Authorized web reconnaissance for bug bounty programs and penetration tests.
ReconPulse collects a target's page, scripts, and metadata, explains what it can
see, and packages the result as JSON, CSV, Markdown, HTML, or SARIF — without
ever leaving read-only, scope-checked requests.

It is passive by default. Active probes exist, but only behind a written
authorization file, an explicit technique allowlist, and a human confirmation.

> **Authorized use only.** Scan systems you own or have explicit written
> permission to test. The operator is responsible for staying inside the
> program's rules. See [SECURITY.md](SECURITY.md).

---

## Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .            # CLI + library
pip install -e ".[ui]"      # adds Streamlit
pip install -e ".[dev]"     # adds pytest, ruff, mypy
```

Requires Python 3.10+.

## Quick start

```bash
# Passive scan with several exports
reconpulse scan https://example.com --format json,md,html,sarif,csv --out reports/

# Restrict passive work to an allowlist
reconpulse scan https://example.com --scope example.com

# See the techniques and their impact tiers
reconpulse techniques

# Dashboard
streamlit run src/reconpulse/ui/app.py
```

A passive run prints a per-target risk score, the findings (severity, title,
confidence), any out-of-scope assets that were deliberately *not* contacted, and
the paths of the written reports.

## What passive mode does

- fetches the page, same-origin scripts, source maps, `robots.txt`, and
  `security.txt` (GET/HEAD only)
- audits security headers and cookie flags (values are never stored)
- extracts endpoints and parameters from markup and JavaScript, with file and
  line references
- classifies parameters (IDOR, open redirect/SSRF, SQLi, debug, auth, …) and
  reports contextual indicators
- detects provider-shaped and high-entropy secrets, always masked (`AKIA****STUV`)
- flags referenced admin, upload, GraphQL, and websocket endpoints
- records external scripts and DNS answers that fall outside scope as
  out-of-scope discoveries, without contacting them

Findings are indicators for manual review, not confirmed vulnerabilities.

## Active mode

Active mode is opt-in and gated:

```bash
reconpulse auth-example                       # writes authorization.example.yaml
cp authorization.example.yaml authorization.yaml   # fill in, never commit

# Plan first: sends no requests
reconpulse scan https://example.com --mode active --auth authorization.yaml --dry-run

# Run tier 1, then explicit tiers 2–3
reconpulse scan https://example.com --mode active --auth authorization.yaml \
    --techniques common_paths,cors_probe,http_methods,graphql_check
```

The run is refused unless the file exists, is in date, lists the target inside
`scope.in`, omits it from `scope.out`, and lists every requested technique.
Interactive runs require typing `I have authorization`; unattended runs require
`--i-have-written-authorization`.

Eleven techniques exist across three tiers — DNS records, TLS handshake,
`OPTIONS` method read, CORS probe, well-known paths, TCP port check, curated
content discovery, a single read-only GraphQL query, sensitive-file existence
checks (status/size/hash only), a marker reflection check, and a canary-based
open-redirect check. The full list, limits, and what is never sent is in
[docs/ACTIVE_MODE.md](docs/ACTIVE_MODE.md).

Every active run writes a hash-chained audit log:

```bash
reconpulse verify-audit reports/audit-20260101-120000.jsonl
```

## Safety guarantees

- One HTTP client (`core/http_client.py`) is the only path to the network.
- Scope allowlist on every request and every redirect hop; `scope.out` always wins.
- SSRF guard rejects private, loopback, link-local, reserved, and cloud metadata
  addresses, including decimal/hex/octal/short IPv4 and IPv6 forms, and URLs with
  userinfo. `--allow-private` only permits addresses that are explicitly in scope.
- Read-only methods only: `GET`, `HEAD`, `OPTIONS`.
- Global and per-host rate limits, request budgets, a per-host circuit breaker,
  bounded timeouts, bounded response size, and a cooperative kill switch.
- Secrets masked everywhere; sensitive file contents are never stored.
- No evasion: a block ends work on that host instead of triggering retries with
  new identities.

## Configuration

Precedence: defaults → `--config` YAML → `RECONPULSE_*` environment variables →
CLI flags.

```yaml
# reconpulse.yaml
rate_per_second: 0.5
concurrency: 3
timeout: 20
max_response_bytes: 1000000
user_agent: "ReconPulse/2.0 (engagement: ACME-123; contact: me@example.com)"
cache_enabled: true
```

Useful flags: `--rate`, `--concurrency`, `--timeout`, `--max-bytes`,
`--user-agent`, `--allow-private`, `--audit-log`, `--resume`, `--quiet`,
`--targets FILE`, `--out`, `--out-file`, `--format`.

## Reports

| Format | Use |
| --- | --- |
| `json` | machine-readable, one object per scan (`render_json_multi` for many) |
| `csv` | spreadsheet triage |
| `md` | engagement notes |
| `html` | self-contained shareable report |
| `sarif` | GitHub code scanning / CI ingestion (SARIF 2.1.0) |

## Architecture

```
src/reconpulse/
├── cli.py              command line entry point
├── pipeline.py         orchestration: passive → optional active → scoring
├── core/               scope, SSRF guard, HTTP client, audit, budget, circuit,
│                       rate limit, kill switch, config, authorization, models
├── collectors/         page, scripts, robots/security.txt
├── analyzers/          headers, cookies, tech, endpoints, params, secrets,
│                       source maps, CORS
├── active/             eleven opt-in modules, each with plan() and run()
├── scoring/            transparent weighted risk engine
├── reporting/          json, csv, markdown, html, sarif
└── ui/app.py           thin Streamlit layer over the same pipeline
```

## Development

```bash
ruff format src tests
ruff check src tests
mypy src
pytest --cov=reconpulse
```

The test suite (265 tests, 83% coverage) never touches the internet: a threaded
mock server on `127.0.0.1` serves the fixtures, and SSRF, scope, authorization,
budget, circuit, audit, CLI, and Streamlit behaviour are all exercised offline.

See [CONTRIBUTING.md](CONTRIBUTING.md) for commit and review conventions.

## Limitations

- DNS rebinding between validation and connect is not fully defeated (a pinned
  resolution helper exists but is not enabled by default).
- Certificate transparency logs are not queried.
- `requests` merges duplicate `Set-Cookie` headers, so multi-cookie responses can
  be under-reported.
- `--dry-run` plans one target when several are supplied.
- Authorization expiry is checked at start, not enforced mid-run.

## License

MIT — see [LICENSE](LICENSE).
