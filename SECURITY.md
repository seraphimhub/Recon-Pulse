# Security policy

## Supported versions

| Version | Supported |
| --- | --- |
| 2.x | yes |
| 1.x (prototype) | no |

## Reporting a vulnerability

Do **not** open a public issue for a vulnerability in ReconPulse. Report it
privately to the maintainers (for example through GitHub's *Report a
vulnerability* advisory form on the repository, or the security contact listed
in the program you are working with) and include:

- the affected version (`reconpulse --version`) and platform
- a minimal reproduction, ideally against a local mock server
- the impact you believe it has, and whether it involves network access,
  scope enforcement, secret handling, or the audit log

Expect an acknowledgement within a few days. Please give maintainers a reasonable
window to ship a fix before disclosing publicly.

## Scope of this policy

This policy covers vulnerabilities in the tool itself, for example:

- a way to make a request that bypasses scope, the SSRF guard, or the read-only
  method restriction
- a way to run active techniques without a valid authorization file
- a path that writes a secret, cookie value, or sensitive file body to a report,
  the UI, or the audit log
- a way to forge or silently truncate the audit log chain
- dependency or packaging issues that affect installed users

It does **not** cover findings produced by scanning a third-party site, or
misuse of the tool against systems you are not authorized to test.

## What the tool deliberately does

ReconPulse is a read-only reconnaissance tool. It sends `GET`, `HEAD`, and
`OPTIONS` only, never exploits anything it finds, and never evades a block. It
does not store response bodies, cookie values, or the contents of sensitive
files; only URLs, status codes, sizes, and hash prefixes are kept.

Active probes are gated by `authorization.yaml`, an explicit per-technique
allowlist, and a human confirmation. If you find a bypass of any of those three,
treat it as a security issue.

## Known limitations

- **DNS rebinding.** Addresses are validated before connecting. A resolver that
  changes its answer inside that window can still defeat the guard;
  `netguard.pinned_resolution` narrows but does not remove the risk.
- **Header merging.** `requests` combines duplicate `Set-Cookie` headers, which
  can under-report cookie flags on multi-cookie responses.
- **Fingerprints** are based on headers and markup and can be spoofed.
- **Authorization expiry** is checked when a run starts, not continuously.

## Handling secrets you discover

If a scan finds a live credential, stop, do not use it, and notify
`contact_for_incident` from the authorization file. Reports only contain masked
values by design, but treat the whole report as sensitive engagement material.
