"""CLI behaviour: exit codes, dry runs, refusals, exports, and audit verification."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from reconpulse.cli import EXIT_ERROR, EXIT_OK, EXIT_REFUSED, main


class TestInformationalCommands:
    def test_no_command_prints_help(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main([]) == EXIT_OK
        assert "usage" in capsys.readouterr().out.lower()

    def test_techniques(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["techniques"]) == EXIT_OK
        output = capsys.readouterr().out
        assert "common_paths" in output
        assert "level 1" in output

    def test_techniques_json(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["techniques", "--json"]) == EXIT_OK
        payload = json.loads(capsys.readouterr().out)
        assert payload["common_paths"]["level"] == 1

    def test_auth_example(self, tmp_path: Path) -> None:
        path = tmp_path / "authorization.example.yaml"
        assert main(["auth-example", str(path)]) == EXIT_OK
        assert path.is_file()

    def test_verify_audit_success_and_failure(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        from reconpulse.core.audit import AuditLog

        path = tmp_path / "audit.jsonl"
        log = AuditLog(path)
        log.append(module="test", method="GET", url="https://example.com/", status=200)
        assert main(["verify-audit", str(path)]) == EXIT_OK
        lines = path.read_text(encoding="utf-8").replace('"status": 200', '"status": 500')
        path.write_text(lines, encoding="utf-8")
        assert main(["verify-audit", str(path)]) == EXIT_ERROR
        assert "FAILED" in capsys.readouterr().out


class TestPassiveScan:
    def test_scan_writes_reports(self, site: Any, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        out = tmp_path / "out"
        code = main(
            [
                "scan",
                site.base_url,
                "--scope",
                "127.0.0.1",
                "--allow-private",
                "--format",
                "json,md,csv",
                "--out",
                str(out),
                "--quiet",
            ]
        )
        assert code == EXIT_OK
        written = sorted(out.glob("reconpulse_*"))
        assert {path.suffix for path in written} == {".json", ".md", ".csv"}
        assert "findings" in capsys.readouterr().out

    def test_out_file_writes_exact_path(self, site: Any, tmp_path: Path) -> None:
        destination = tmp_path / "report.json"
        code = main(
            [
                "scan",
                site.base_url,
                "--scope",
                "127.0.0.1",
                "--allow-private",
                "--format",
                "json",
                "--out-file",
                str(destination),
            ]
        )
        assert code == EXIT_OK
        assert json.loads(destination.read_text(encoding="utf-8"))["metadata"]["mode"] == "passive"

    def test_missing_target_is_a_config_error(self, tmp_path: Path) -> None:
        assert main(["scan", "--out", str(tmp_path)]) == EXIT_REFUSED

    def test_missing_targets_file(self, tmp_path: Path) -> None:
        assert main(["scan", "--targets", str(tmp_path / "absent.txt")]) == EXIT_REFUSED

    def test_out_of_scope_target_reports_an_error(
        self, site: Any, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        code = main(
            [
                "scan",
                "https://out-of-scope.example/",
                "--scope",
                "127.0.0.1",
                "--out",
                str(tmp_path),
            ]
        )
        assert code == EXIT_OK
        assert "error" in capsys.readouterr().out

    def test_targets_file_and_resume(self, site: Any, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        targets = tmp_path / "targets.txt"
        targets.write_text(f"# comment\n{site.base_url}\n", encoding="utf-8")
        resume = tmp_path / "resume.json"
        resume.write_text(json.dumps({"completed": [site.base_url]}), encoding="utf-8")
        code = main(
            [
                "scan",
                "--targets",
                str(targets),
                "--resume",
                str(resume),
                "--scope",
                "127.0.0.1",
                "--allow-private",
                "--out",
                str(tmp_path / "out"),
            ]
        )
        assert code == EXIT_OK
        assert "skip (already completed)" in capsys.readouterr().out


class TestActiveMode:
    def test_active_without_auth_is_refused(self, site: Any, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["scan", site.base_url, "--mode", "active"]) == EXIT_REFUSED
        assert "refused" in capsys.readouterr().err

    def test_active_with_missing_file(self, site: Any, tmp_path: Path) -> None:
        code = main(["scan", site.base_url, "--mode", "active", "--auth", str(tmp_path / "absent.yaml")])
        assert code == EXIT_REFUSED

    def test_active_with_expired_authorization(self, site: Any, make_auth_file: Any) -> None:
        path = make_auth_file(valid_from="2000-01-01T00:00:00Z", valid_until="2001-01-01T00:00:00Z")
        assert main(["scan", site.base_url, "--mode", "active", "--auth", str(path)]) == EXIT_REFUSED

    def test_active_target_outside_scope(self, site: Any, make_auth_file: Any) -> None:
        path = make_auth_file(scope={"in": ["example.com"], "out": []})
        assert main(["scan", site.base_url, "--mode", "active", "--auth", str(path)]) == EXIT_REFUSED

    def test_dry_run_sends_nothing(self, site: Any, make_auth_file: Any, capsys: pytest.CaptureFixture[str]) -> None:
        path = make_auth_file()
        code = main(
            [
                "scan",
                site.base_url,
                "--mode",
                "active",
                "--auth",
                str(path),
                "--techniques",
                "common_paths,http_methods",
                "--dry-run",
            ]
        )
        assert code == EXIT_OK
        output = capsys.readouterr().out
        assert "dry run" in output.lower()
        assert site.requests == []

    def test_active_scan_requires_explicit_flag_when_non_interactive(
        self, site: Any, make_auth_file: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("sys.stdin.isatty", lambda: False, raising=False)
        path = make_auth_file()
        code = main(
            [
                "scan",
                site.base_url,
                "--mode",
                "active",
                "--auth",
                str(path),
                "--techniques",
                "common_paths",
            ]
        )
        assert code == EXIT_REFUSED
        assert site.requests == []

    def test_active_scan_runs_with_flag_and_writes_audit(
        self, site: Any, make_auth_file: Any, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = make_auth_file()
        out = tmp_path / "active"
        audit = tmp_path / "audit.jsonl"
        code = main(
            [
                "scan",
                site.base_url,
                "--mode",
                "active",
                "--auth",
                str(path),
                "--i-have-written-authorization",
                "--allow-private",
                "--techniques",
                "common_paths,cors_probe,http_methods",
                "--format",
                "json",
                "--out",
                str(out),
                "--audit-log",
                str(audit),
            ]
        )
        assert code == EXIT_OK
        assert audit.is_file()
        assert main(["verify-audit", str(audit)]) == EXIT_OK
        assert "audit log:" in capsys.readouterr().out
        assert site.requests
        report = json.loads(next(out.glob("reconpulse_*.json")).read_text(encoding="utf-8"))
        assert report["metadata"]["mode"] == "active"
        assert report["summary"]["active_findings"] > 0
