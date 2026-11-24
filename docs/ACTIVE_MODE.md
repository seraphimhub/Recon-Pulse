# Active mode

ReconPulse is passive by default: it fetches the target page, its scripts, and
`robots.txt`/`security.txt`, then analyses what came back. Active mode is a
separate, opt-in step that sends a bounded set of additional probes. It only
runs when a valid authorization file is supplied **and** the operator confirms
the engagement.

Nothing in this document overrides the rules of your engagement. If a program
forbids a technique, leave it out of `allowed_techniques`.

---

## 1. Gate checklist

An active run starts only when every item below is true. Each check is
implemented in `src/reconpulse/core/authorization.py` and enforced in
`pipeline.scan_target`, so the CLI and the Streamlit page cannot bypass it.

| Check | Implementation |
| --- | --- |
| `--auth` points at an existing file | `load_authorization` raises `AuthorizationError` |
| The file is a YAML mapping with all required fields | `validate_authorization_data` |
| `valid_from` / `valid_until` are timezone-aware and bracket *now* | `ensure_valid_now` |
| `scope.in` is non-empty and contains the target | `ensure_host_in_scope` |
| `scope.out` does not contain the target | `Scope` (deny wins) |
| Every requested technique is listed in `allowed_techniques` | `select_techniques` |
| A human confirmed, or `--i-have-written-authorization` was passed | `cli._prepare_active` |

Required fields: `engagement`, `authorized_by`, `valid_from`, `valid_until`,
`scope`, `allowed_techniques`, and `contact_for_incident`.

An example lives in `authorization.example.yaml`; generate a fresh copy with
`reconpulse auth-example`. The real file is git-ignored — never commit it.

```yaml
engagement: "Program name and URL"
authorized_by: "Jane Doe <security@example.com>"
valid_from: "2026-01-01T00:00:00Z"
valid_until: "2026-12-31T23:59:59Z"
scope:
  in: ["example.com", "*.example.com"]
  out: ["internal.example.com"]
allowed_techniques: [dns_enum, tls_check, http_methods, cors_probe, common_paths]
limits:
  max_requests_per_second: 1.0
  max_concurrency: 3
  max_total_requests: 500
  per_host_requests: 200
contact_for_incident: "security@example.com"
canary_domain: "canary.example.net"   # only a domain you control
```

### Confirmation

Interactive runs print the engagement summary and require the exact phrase
`I have authorization`. Non-interactive runs (CI, containers, scripts) must pass
`--i-have-written-authorization` in addition to a valid file; nothing is sent
otherwise.

If `valid_until` is less than 24 hours away, the CLI prints a warning to stderr
before starting. It does not abort a run that is already inside the window.

### Dry run first

```bash
reconpulse scan https://example.com --mode active --auth authorization.yaml --dry-run
```

`--dry-run` prints the techniques, their request estimates, the scope, the
budget, and the canary domain. It sends **zero** requests and does not create an
audit log. Plans are generated for the first target only when `--targets` lists
several.

---

## 2. Techniques

Tier 1 runs when active mode is enabled. Tier 2 and tier 3 must be named with
`--techniques` **and** be listed by the engagement owner. List them with
`reconpulse techniques`.

| Level | Technique | What it sends |
| --- | --- | --- |
| 1 | `dns_enum` | A/AAAA/CNAME lookups for a short list of common names (no zone transfer, no CT logs) |
| 1 | `tls_check` | One TCP/TLS handshake on 443 and a read of the certificate |
| 1 | `http_methods` | One `OPTIONS` request; the `Allow` header is read, no method is tested |
| 1 | `cors_probe` | One `GET` with `Origin: https://<canary>`; `Access-Control-Allow-*` is read |
| 1 | `common_paths` | `GET` for 11 well-known documentation/health paths |
| 2 | `port_scan` | `connect()` to 19 common TCP ports with a passive banner read |
| 2 | `content_discovery` | `GET` for up to 40 curated paths with soft-404 comparison |
| 2 | `graphql_check` | `GET ?query={__typename}` against four candidate paths |
| 2 | `sensitive_file_check` | `GET` for nine known-sensitive paths; status, size, and hash only |
| 3 | `reflection_check` | `GET` with the marker `rp7f3a9c` in up to eight parameters |
| 3 | `redirect_check` | `GET` with a redirect parameter set to the canary domain, `Location` read, never followed |

What ReconPulse never does:

- exploit payloads, tags, event handlers, or injection syntax
- fuzzing, brute force, credential guessing, or directory brute forcing
- `POST`, `PUT`, `PATCH`, `DELETE`, or any state-changing request
- DoS attempts, request flooding, or evasion (no IP/UA rotation to defeat a block)
- downloading or storing sensitive file contents (only URL, status, size, SHA-256 prefix)
- contacting an asset that is outside `scope.in` or listed in `scope.out`

---

## 3. Limits and braking

| Control | Behaviour |
| --- | --- |
| Rate limit | `limits.max_requests_per_second` capped against `--rate`; one shared limiter across threads |
| Concurrency | `limits.max_concurrency` capped against `--concurrency` |
| Budget | `limits.max_total_requests` and optional `per_host_requests`; the client raises `BudgetExhausted` and the run reports partial results |
| Circuit breaker | After 5 blocking responses (403/429/5xx) or 3 consecutive timeouts the host is dropped; there is no retry-forever and no evasion |
| Kill switch | Ctrl+C trips the switch, unwinds in-flight work, marks the report `interrupted`, and still writes reports and the audit log |
| Timeouts | Per-request timeout (default 15 s), bounded redirects (default 5) |
| Response size | `--max-bytes` (default 2 MB); larger bodies are truncated, never fully buffered |

---

## 4. Audit log

Active runs always write a JSONL audit log (`--audit-log`, otherwise
`<out>/audit-<timestamp>.jsonl`). Every request produces one record:

```json
{"timestamp": "...", "module": "cors_probe", "method": "GET", "url": "...", "status": 200,
 "duration_ms": 12.4, "bytes_received": 512, "note": null, "prev": "<hash>", "hash": "<hash>"}
```

`hash` is SHA-256 over the canonical record, and `prev` is the previous record's
hash, so an edited or deleted line breaks the chain:

```bash
reconpulse verify-audit /path/to/audit-<timestamp>.jsonl
```

The log stores no response bodies, no cookie values, and no secrets. Redirects
that the SSRF guard or scope check blocks are recorded, with the reason, in the
report notes.

---

## 5. Scope and SSRF enforcement

Every request goes through `core/http_client.py`, which validates the URL before
connecting and re-validates each redirect hop:

- only `http` / `https`; URLs with userinfo are rejected outright
- hosts are resolved and every answer must be public
- private, loopback, link-local, CGNAT, benchmarking, TEST-NET, multicast, and
  reserved ranges are blocked
- cloud metadata addresses (`169.254.169.254`, `fd00:ec2::254`) are always
  blocked, even with `--allow-private`
- `--allow-private` only relaxes the check for addresses that are explicitly in
  `scope.in`; it never widens scope
- decimal (`2130706433`), hex (`0x7f000001`), octal, short (`127.1`), and IPv6
  forms are normalised before classification
- discovered assets outside scope (external scripts, DNS results) are recorded
  as *out-of-scope discovery* and never contacted

---

## 6. Findings and scoring

Every finding carries `confidence` (`low`/`medium`/`high`), `evidence_type`
(`static_indicator`/`observed_response`/`active_probe`), an explanation,
remediation, and a safe manual verification step.

```
points = severity_weight × evidence_weight × confidence_weight
score  = min(100, round(sum(points)))
```

| Weight | Values |
| --- | --- |
| severity | info 0, low 2, medium 5, high 9 |
| evidence | static_indicator 1.0, observed_response 1.5, active_probe 2.0 |
| confidence | low 0.6, medium 1.0, high 1.4 |

Risk levels: `high` ≥ 70, `medium` ≥ 40, `low` ≥ 15, otherwise `info`.

Active findings are indicators, not proof. Report them with the evidence
ReconPulse captured and let the program owner confirm impact.

---

## 7. Known limitations

- **DNS rebinding window.** Addresses are validated before the connection opens.
  `netguard.pinned_resolution` narrows the window but is not enabled by default;
  a hostile resolver can still answer differently inside that gap.
- **Certificate transparency is not queried.** `dns_enum` uses a short name list
  and A/AAAA/CNAME records only.
- **Combined `Set-Cookie` headers.** `requests` merges duplicate headers, so a
  multi-cookie response can be reported as one cookie.
- **Plans cover one target.** `--dry-run` with `--targets` plans the first target.
- **Expiry is checked at start.** A run that outlives `valid_until` is not
  aborted automatically; keep the budget small enough to finish in time.
- **Fingerprints can be spoofed.** Technology detection is header/markup based.

---

## 8. Incident response

If a technique causes unexpected load, a block, or a complaint:

1. Stop the run (Ctrl+C) and keep the audit log.
2. Contact `contact_for_incident` from the authorization file with the audit log
   and the exact timestamps.
3. Do not retry with rotated IPs, User-Agents, or proxies.
4. Record the incident in the engagement notes and, if needed, disable the
   technique for the rest of the engagement.
