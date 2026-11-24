"""Command line interface.

Examples
--------
Passive scan with several exports::

    reconpulse scan https://example.com --format json,md,html

Authorized active dry run (no requests)::

    reconpulse scan https://example.com --mode active --auth authorization.yaml --dry-run

Authorized active run with explicit techniques::

    reconpulse scan https://example.com --mode active --auth authorization.yaml \\
        --techniques dns_enum,tls_check,cors_probe
"""

from __future__ import annotations

import argparse
import json
import signal
import sys
from contextlib import suppress
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlparse

from ._version import __version__
from .active import available_techniques
from .core.audit import AuditLog, verify_chain
from .core.authorization import (
    EXPIRY_WARNING_HOURS,
    Authorization,
    load_authorization,
    write_example_authorization,
)
from .core.config import AppConfig
from .core.errors import AuthorizationError, ConfigError, ReconPulseError, ScopeError
from .core.killswitch import KillSwitch
from .core.models import ScanMode, ScanReport
from .core.scope import Scope
from .pipeline import ScanOptions, dry_run_plan, scan_target
from .reporting import SUPPORTED_FORMATS, export_report, export_reports

CONFIRMATION_PHRASE = "I have authorization"
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_REFUSED = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reconpulse",
        description=(
            "Authorized web reconnaissance. Passive by default; active mode requires a validated authorization file."
        ),
    )
    parser.add_argument("--version", action="version", version=f"reconpulse {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser("scan", help="scan one target or a list of targets")
    scan.add_argument("target", nargs="?", help="target URL (omit when using --targets)")
    scan.add_argument("--targets", help="file with one target URL per line")
    scan.add_argument("--scope", help="comma-separated scope allowlist for passive mode")
    scan.add_argument("--mode", choices=["passive", "active"], default="passive")
    scan.add_argument("--auth", help="authorization.yaml (required for active mode)")
    scan.add_argument("--techniques", help="comma-separated active techniques")
    scan.add_argument("--dry-run", action="store_true", help="show the active plan without sending requests")
    scan.add_argument("--i-have-written-authorization", action="store_true")
    scan.add_argument("--format", default="json,md", help=f"comma-separated: {', '.join(SUPPORTED_FORMATS)}")
    scan.add_argument("--out", default="reconpulse-output", help="output directory")
    scan.add_argument("--out-file", help="write the first format to this exact path")
    scan.add_argument("--config", help="YAML config file")
    scan.add_argument("--rate", type=float, help="requests per second (global)")
    scan.add_argument("--concurrency", type=int, help="parallel fetch workers")
    scan.add_argument("--timeout", type=int, help="per-request timeout in seconds")
    scan.add_argument("--max-bytes", type=int, help="maximum response body size")
    scan.add_argument("--user-agent", help="User-Agent to identify your testing")
    scan.add_argument("--allow-private", action="store_true", help="permit in-scope private addresses")
    scan.add_argument("--audit-log", help="path for the chained audit log (JSONL)")
    scan.add_argument("--resume", help="state file listing targets already completed")
    scan.add_argument("--quiet", action="store_true", help="only print the final summary")

    techniques = subparsers.add_parser("techniques", help="list active techniques and impact levels")
    techniques.add_argument("--json", action="store_true")

    example = subparsers.add_parser("auth-example", help="write authorization.example.yaml")
    example.add_argument("path", nargs="?", default="authorization.example.yaml")

    verify = subparsers.add_parser("verify-audit", help="verify an audit log hash chain")
    verify.add_argument("path")

    return parser


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _split_list(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _load_config(args: argparse.Namespace) -> AppConfig:
    overrides = {
        "rate_per_second": args.rate,
        "concurrency": args.concurrency,
        "timeout": args.timeout,
        "max_response_bytes": args.max_bytes,
        "user_agent": args.user_agent,
        "allow_private": True if args.allow_private else None,
    }
    return AppConfig.load(args.config, overrides=overrides)


def _passive_scope(args: argparse.Namespace) -> Scope | None:
    entries = _split_list(args.scope)
    if not entries:
        return None
    return Scope(entries, [], default_deny=False)


def _targets_from_args(args: argparse.Namespace) -> list[str]:
    targets: list[str] = []
    if args.target:
        targets.append(args.target.strip())
    if args.targets:
        path = Path(args.targets)
        if not path.is_file():
            raise ConfigError(f"targets file not found: {path}")
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)
    if not targets:
        raise ConfigError("provide a target URL or --targets FILE")
    return targets


def _load_resume(path: str | None) -> set[str]:
    if not path:
        return set()
    file = Path(path)
    if not file.is_file():
        return set()
    try:
        data = json.loads(file.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return set()
    completed = data.get("completed", []) if isinstance(data, dict) else []
    return {str(item) for item in completed}


def _save_resume(path: str | None, completed: set[str]) -> None:
    if not path:
        return
    file = Path(path)
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text(json.dumps({"completed": sorted(completed)}, indent=2), encoding="utf-8")


def _print_report(report: ScanReport, quiet: bool = False) -> None:
    risk = report.risk or {}
    counts = risk.get("counts", {})
    print(
        f"\n{report.metadata.target}: risk {risk.get('score', 0)}/100 "
        f"({risk.get('level', 'info')}) - {len(report.findings)} findings "
        f"[high {counts.get('high', 0)}, medium {counts.get('medium', 0)}, "
        f"low {counts.get('low', 0)}, info {counts.get('info', 0)}]"
    )
    if report.metadata.interrupted:
        print("  scan interrupted; partial results reported")
    if not quiet:
        for finding in report.findings[:25]:
            print(f"  - [{finding.severity.value.upper()}] {finding.title} ({finding.confidence.value} confidence)")
        if len(report.findings) > 25:
            print(f"  ... {len(report.findings) - 25} more findings in the report files")
    if report.out_of_scope:
        print(f"  out-of-scope discoveries (not contacted): {len(report.out_of_scope)}")
    if report.errors:
        for error in report.errors:
            print(f"  error: {error}")


def _prepare_active(args: argparse.Namespace, targets: list[str]) -> tuple[Authorization, list[str]]:
    if not args.auth:
        raise AuthorizationError(
            "active mode requires --auth authorization.yaml; the file must exist, be in date, and "
            "list the target inside scope.in"
        )
    authorization = load_authorization(args.auth)
    authorization.ensure_valid_now()

    for target in targets:
        host = urlparse(target).hostname or ""
        authorization.ensure_host_in_scope(host)

    if authorization.expires_within(EXPIRY_WARNING_HOURS):
        print(
            f"WARNING: authorization expires within {EXPIRY_WARNING_HOURS}h "
            f"({authorization.valid_until.isoformat()}); the scan stops at that time.",
            file=sys.stderr,
        )

    techniques = _split_list(args.techniques)
    if not args.dry_run and not args.i_have_written_authorization:
        if not sys.stdin.isatty():
            raise AuthorizationError(
                "non-interactive active scan needs --i-have-written-authorization in addition to a "
                "valid authorization file"
            )
        print(
            f"\nEngagement : {authorization.engagement}\n"
            f"Authorized : {authorization.authorized_by}\n"
            f"Scope      : {', '.join(authorization.scope_in)}"
            + (f" (excluding {', '.join(authorization.scope_out)})" if authorization.scope_out else "")
            + f"\nValid      : {authorization.valid_from.isoformat()} -> {authorization.valid_until.isoformat()}\n"
            f"Techniques : {', '.join(techniques) or ', '.join(authorization.allowed_techniques)}\n"
            f"Budget     : {authorization.limits.max_total_requests} requests at "
            f"{authorization.limits.max_requests_per_second}/s\n"
        )
        answer = input(f'Type exactly "{CONFIRMATION_PHRASE}" to continue: ').strip()
        if answer != CONFIRMATION_PHRASE:
            raise AuthorizationError("confirmation phrase did not match; nothing was sent")
    return authorization, techniques


def _print_dry_run(plan: dict[str, object]) -> None:
    print("\nActive scan plan (dry run - no requests sent)")
    print(f"  target        : {plan['target']}")
    print(f"  engagement    : {plan['engagement']}")
    print(f"  scope in      : {', '.join(plan['scope_in'])}")  # type: ignore[arg-type]
    if plan.get("scope_out"):
        print(f"  scope out     : {', '.join(plan['scope_out'])}")  # type: ignore[arg-type]
    print(f"  valid from    : {plan['valid_from']}")
    print(f"  valid until   : {plan['valid_until']}")
    print(f"  budget        : {plan['budget']} requests")
    print(f"  concurrency   : {plan['max_concurrency']}")
    print(f"  canary domain : {plan.get('canary_domain') or '(none set)'}")
    print(f"  est. requests : {plan['estimated_requests']}")
    print("  techniques:")
    for item in cast(list[dict[str, Any]], plan["techniques"]):
        print(f"    - {item.get('technique')}: {item.get('requests')} request(s) - {item.get('description')}")
    print()


def _install_sigint(kill_switch: KillSwitch) -> None:
    def handler(signum: int, frame: object) -> None:
        kill_switch.trip()
        print("\ninterrupt received: finishing current request and writing partial results", file=sys.stderr)

    with suppress(ValueError):  # not in the main thread
        signal.signal(signal.SIGINT, handler)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def command_scan(args: argparse.Namespace) -> int:
    targets = _targets_from_args(args)
    mode = ScanMode.ACTIVE if args.mode == "active" else ScanMode.PASSIVE
    formats = _split_list(args.format) or ["json"]

    authorization: Authorization | None = None
    techniques: list[str] = []
    if mode is ScanMode.ACTIVE:
        try:
            authorization, techniques = _prepare_active(args, targets)
        except (AuthorizationError, ScopeError) as exc:
            print(f"refused: {exc}", file=sys.stderr)
            return EXIT_REFUSED

        if args.dry_run:
            plan = dry_run_plan(targets[0], authorization, techniques)
            _print_dry_run(plan)
            return EXIT_OK

    config = _load_config(args)

    audit_log = None
    if mode is ScanMode.ACTIVE or args.audit_log:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        audit_path = args.audit_log or str(Path(args.out) / f"audit-{stamp}.jsonl")
        audit_log = AuditLog(audit_path)
        print(f"audit log: {audit_path}")

    kill_switch = KillSwitch()
    _install_sigint(kill_switch)

    completed = _load_resume(args.resume)
    reports: list[ScanReport] = []
    failures = 0

    for target in targets:
        if target in completed:
            print(f"skip (already completed): {target}")
            continue
        print(f"\nscanning {target} [{mode.value}] ...")
        options = ScanOptions(
            mode=mode,
            scope=_passive_scope(args),
            authorization=authorization,
            techniques=techniques or None,
            audit_log=audit_log,
            kill_switch=kill_switch,
        )
        try:
            report = scan_target(target, config, options)
        except ReconPulseError as exc:
            failures += 1
            print(f"  failed: {exc}", file=sys.stderr)
            continue
        if kill_switch.triggered:
            report.metadata.interrupted = True
        reports.append(report)
        _print_report(report, quiet=args.quiet)
        completed.add(target)
        _save_resume(args.resume, completed)

    if not reports:
        print("no scan completed", file=sys.stderr)
        return EXIT_ERROR if failures else EXIT_OK

    written: list[Path] = []
    for report in reports:
        if args.out_file and report is reports[0]:
            written.append(export_report(report, formats[0], args.out_file))
        else:
            written.extend(export_reports(report, formats, output_dir=args.out).values())

    if len(reports) > 1 and "json" in formats:
        combined = Path(args.out) / f"reconpulse_combined_{datetime.now(timezone.utc):%Y%m%d-%H%M%S}.json"
        combined.parent.mkdir(parents=True, exist_ok=True)
        from .reporting import render_json_multi

        combined.write_text(render_json_multi(reports), encoding="utf-8")
        written.append(combined)

    print("\nreports written:")
    for path in written:
        print(f"  {path}")
    if audit_log is not None and audit_log.path is not None:
        print(f"  audit log: {audit_log.path} ({len(audit_log)} entries, last hash {audit_log.last_hash[:16]})")

    return EXIT_REFUSED if failures and not reports else (EXIT_ERROR if failures else EXIT_OK)


def command_techniques(args: argparse.Namespace) -> int:
    data = available_techniques()
    if args.json:
        print(json.dumps(data, indent=2))
        return EXIT_OK
    print("Active techniques (opt-in via allowed_techniques):\n")
    for name, info in data.items():
        print(f"  {name:22s} level {info['level']}  {info['description']}")
    print("\nTier 1 runs by default in active mode; tiers 2 and 3 must be requested with --techniques.")
    return EXIT_OK


def command_auth_example(args: argparse.Namespace) -> int:
    path = write_example_authorization(args.path)
    print(f"wrote {path}; copy to authorization.yaml, fill in real values, and never commit it")
    return EXIT_OK


def command_verify_audit(args: argparse.Namespace) -> int:
    valid, message = verify_chain(args.path)
    print(("OK: " if valid else "FAILED: ") + message)
    return EXIT_OK if valid else EXIT_ERROR


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return EXIT_OK
    try:
        if args.command == "scan":
            return command_scan(args)
        if args.command == "techniques":
            return command_techniques(args)
        if args.command == "auth-example":
            return command_auth_example(args)
        if args.command == "verify-audit":
            return command_verify_audit(args)
    except (AuthorizationError, ConfigError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_REFUSED
    except ReconPulseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    parser.print_help()
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
