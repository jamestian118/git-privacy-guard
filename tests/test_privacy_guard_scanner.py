from __future__ import annotations

import json
import io
import subprocess
from pathlib import Path

import pytest

import privacy_guard_scanner as scanner


def make_config(**overrides: object) -> scanner.Config:
    base = {
        "profile": "public",
        "require_gitleaks": True,
        "gitleaks_redact": True,
        "pii_policy": "block",
        "pii_allow_comment_tags": ["privacy:allow", "gitleaks:allow"],
        "allow_email_domains": ["example.com", "example.org", "example.net"],
        "blocked_path_globs": [],
        "binary_policy": "block",
        "blocked_binary_exts": [],
        "max_diff_bytes": 2_000_000,
    }
    base.update(overrides)
    return scanner.Config(**base)


def write_config(root: Path, payload: dict[str, object]) -> None:
    (root / ".privacy_guard.json").write_text(json.dumps(payload), encoding="utf-8")


def test_extract_added_lines_tracks_paths_and_ignores_removed_lines() -> None:
    diff_text = """diff --git a/a.txt b/a.txt
index 1111111..2222222 100644
--- a/a.txt
+++ b/a.txt
@@ -0,0 +1,3 @@
+first
 second
+third
diff --git a/new.txt b/new.txt
new file mode 100644
--- /dev/null
+++ b/new.txt
@@ -0,0 +1 @@
+brand-new
"""
    assert scanner.extract_added_lines(diff_text) == [
        ("a.txt", "first"),
        ("a.txt", "third"),
        ("new.txt", "brand-new"),
    ]


def test_check_pii_on_lines_detects_denylist_and_common_pii() -> None:
    cfg = make_config(allow_email_domains=["example.com"], pii_allow_comment_tags=["privacy:allow"])
    lines = [
        ("src/app.py", "token = top-secret-value"),
        ("src/app.py", "email = 'dev@corp.local'"),
        ("src/app.py", "home = '/Users/alice/work/project'"),
        ("src/app.py", "api = 'https://alice:secret@example.com'"),
        ("src/app.py", "safe = 'dev@corp.local'  # privacy:allow"),
    ]
    problems = scanner.check_pii_on_lines(lines, cfg=cfg, denylist=["top-secret-value"])

    assert any("[DENYLIST]" in item for item in problems)
    assert any("[PII] email detected" in item for item in problems)
    assert any("[PII] absolute home path detected" in item for item in problems)
    assert any("[PII] URL with basic-auth detected" in item for item in problems)
    assert all("privacy:allow" not in item for item in problems)


def test_regex_boundaries_avoid_false_positive_prefix_and_ip_range() -> None:
    cfg = make_config()
    lines = [
        ("src/sample.txt", "prefix/Users/alice/path should not match"),
        ("src/sample.txt", "/Users/alice/path should match"),
        ("src/sample.txt", "172.15.8.9 should not be internal"),
        ("src/sample.txt", "172.16.8.9 should be internal"),
    ]
    problems = scanner.check_pii_on_lines(lines, cfg=cfg, denylist=[])

    assert any("absolute home path detected" in item for item in problems)
    assert any("internal IP detected" in item for item in problems)
    assert not any("172.15.8.9" in item for item in problems)


def test_read_denylist_merges_sources_with_stable_dedup(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    env_path = tmp_path / "env-deny.txt"
    env_path.write_text("# env\nalpha\nbeta\n", encoding="utf-8")

    git_path = tmp_path / "git-deny.txt"
    git_path.write_text("beta\ngamma\n", encoding="utf-8")

    local_path = tmp_path / ".privacy_guard.denylist.local.txt"
    local_path.write_text("gamma\ndelta\n", encoding="utf-8")

    monkeypatch.setenv("PRIVACY_GUARD_DENYLIST", "env-deny.txt")

    def fake_git(
        args: list[str], *, check: bool = True, input_text: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        assert args == ["config", "--get", "privacy.guard.denylist"]
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="git-deny.txt\n", stderr="")

    monkeypatch.setattr(scanner, "git", fake_git)

    assert scanner.read_denylist(tmp_path) == ["alpha", "beta", "gamma", "delta"]


def test_load_config_validates_pii_policy(tmp_path: Path) -> None:
    write_config(
        tmp_path,
        {
            "profile": "public",
            "pii_policy": "maybe",
        },
    )
    with pytest.raises(RuntimeError, match="pii_policy"):
        scanner.load_config(tmp_path)


def test_load_config_validates_binary_policy(tmp_path: Path) -> None:
    write_config(
        tmp_path,
        {
            "profile": "public",
            "pii_policy": "block",
            "binary_policy": "strict",
        },
    )
    with pytest.raises(RuntimeError, match="binary_policy"):
        scanner.load_config(tmp_path)


def test_load_config_validates_profile(tmp_path: Path) -> None:
    write_config(
        tmp_path,
        {
            "profile": "shared",
            "pii_policy": "block",
        },
    )
    with pytest.raises(RuntimeError, match="profile"):
        scanner.load_config(tmp_path)


def test_load_config_validates_max_diff_bytes(tmp_path: Path) -> None:
    write_config(
        tmp_path,
        {
            "profile": "public",
            "pii_policy": "block",
            "binary_policy": "block",
            "max_diff_bytes": 0,
        },
    )
    with pytest.raises(RuntimeError, match="max_diff_bytes"):
        scanner.load_config(tmp_path)


def test_gitleaks_cmd_args_respects_redact_flag() -> None:
    assert scanner.gitleaks_cmd_args(make_config(gitleaks_redact=True)) == ["gitleaks", "--redact"]
    assert scanner.gitleaks_cmd_args(make_config(gitleaks_redact=False)) == ["gitleaks"]


def test_require_gitleaks_respects_require_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    scanner.require_gitleaks(make_config(require_gitleaks=False))

    monkeypatch.setattr(scanner, "which", lambda _cmd: None)
    with pytest.raises(RuntimeError, match="gitleaks not found"):
        scanner.require_gitleaks(make_config(require_gitleaks=True))

    monkeypatch.setattr(scanner, "which", lambda _cmd: "/usr/local/bin/gitleaks")
    scanner.require_gitleaks(make_config(require_gitleaks=True))


def test_run_raises_timeout_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(cmd=["git"], timeout=3)

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(RuntimeError, match="Command timed out"):
        scanner.run(["git", "status"], timeout_seconds=3)


def test_run_gitleaks_pre_commit_handles_return_codes(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = make_config(require_gitleaks=True)

    monkeypatch.setattr(
        scanner,
        "run",
        lambda *_a, **_kw: subprocess.CompletedProcess(args=["gitleaks"], returncode=0, stdout="", stderr=""),
    )
    scanner.run_gitleaks_pre_commit(cfg)

    monkeypatch.setattr(
        scanner,
        "run",
        lambda *_a, **_kw: subprocess.CompletedProcess(args=["gitleaks"], returncode=127, stdout="", stderr=""),
    )
    with pytest.raises(RuntimeError, match="not found"):
        scanner.run_gitleaks_pre_commit(cfg)

    monkeypatch.setattr(
        scanner,
        "run",
        lambda *_a, **_kw: subprocess.CompletedProcess(args=["gitleaks"], returncode=2, stdout="", stderr=""),
    )
    with pytest.raises(RuntimeError, match="detected secrets"):
        scanner.run_gitleaks_pre_commit(cfg)


def test_run_gitleaks_pre_push_handles_nonzero(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cfg = make_config(require_gitleaks=True)
    monkeypatch.setattr(
        scanner,
        "run",
        lambda *_a, **_kw: subprocess.CompletedProcess(args=["gitleaks"], returncode=1, stdout="", stderr=""),
    )
    with pytest.raises(RuntimeError, match="detected secrets"):
        scanner.run_gitleaks_pre_push(cfg, tmp_path, "HEAD")


def test_commits_to_push_supports_new_and_existing_remote(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def fake_git(args: list[str], *, check: bool = True, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
        del check, input_text
        calls.append(args)
        if args[0] == "rev-list" and "--not" in args:
            return subprocess.CompletedProcess(args=args, returncode=0, stdout="a\nb\n", stderr="")
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="c\nd\n", stderr="")

    monkeypatch.setattr(scanner, "git", fake_git)
    assert scanner.commits_to_push("origin", "localsha", scanner.ZERO_SHA) == ["a", "b"]
    assert scanner.commits_to_push("origin", "localsha", "remotesha") == ["c", "d"]
    assert calls[0] == ["rev-list", "localsha", "--not", "--remotes=origin"]
    assert calls[1] == ["rev-list", "remotesha..localsha"]


def test_scan_commit_patches_collects_and_prefixes_commit(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = make_config()

    def fake_git(args: list[str], *, check: bool = True, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
        del check, input_text
        sha = args[-1]
        diff = f"+++ b/file-{sha}.txt\n+bad-{sha}\n"
        return subprocess.CompletedProcess(args=args, returncode=0, stdout=diff, stderr="")

    monkeypatch.setattr(scanner, "git", fake_git)
    problems = scanner.scan_commit_patches(["aaa", "bbb"], cfg=cfg, denylist=["bad"])
    assert any(item == "commit aaa:" for item in problems)
    assert any(item == "commit bbb:" for item in problems)
    assert any("[DENYLIST]" in item for item in problems)


def test_main_pre_commit_success_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cfg = make_config()
    called = {"gitleaks": 0}

    monkeypatch.setattr(scanner, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(scanner, "load_config", lambda _root: cfg)
    monkeypatch.setattr(scanner, "read_denylist", lambda _root: [])
    monkeypatch.setattr(scanner, "require_gitleaks", lambda _cfg: None)
    monkeypatch.setattr(scanner, "staged_files", lambda: ["src/main.py"])
    monkeypatch.setattr(scanner, "staged_binary_files", lambda: set())
    monkeypatch.setattr(scanner, "staged_diff_text", lambda _cfg: "+++ b/src/main.py\n+safe line\n")
    monkeypatch.setattr(scanner, "check_pii_on_lines", lambda _lines, *, cfg, denylist: [])

    def fake_run_gitleaks_pre_commit(_cfg: scanner.Config) -> None:
        called["gitleaks"] += 1

    monkeypatch.setattr(scanner, "run_gitleaks_pre_commit", fake_run_gitleaks_pre_commit)

    assert scanner.main(["privacy_guard.py", "pre-commit"]) == 0
    assert called["gitleaks"] == 1


def test_main_pre_commit_blocks_on_denylist(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cfg = make_config()
    errors: list[str] = []

    monkeypatch.setattr(scanner, "eprint", lambda *args: errors.append(" ".join(str(item) for item in args)))
    monkeypatch.setattr(scanner, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(scanner, "load_config", lambda _root: cfg)
    monkeypatch.setattr(scanner, "read_denylist", lambda _root: ["secret"])
    monkeypatch.setattr(scanner, "require_gitleaks", lambda _cfg: None)
    monkeypatch.setattr(scanner, "staged_files", lambda: [])
    monkeypatch.setattr(scanner, "staged_binary_files", lambda: set())
    monkeypatch.setattr(scanner, "staged_diff_text", lambda _cfg: "+++ b/src/main.py\n+secret\n")
    monkeypatch.setattr(
        scanner,
        "check_pii_on_lines",
        lambda _lines, *, cfg, denylist: ["src/main.py: [DENYLIST] matched local denylist (redacted): secret"],
    )
    monkeypatch.setattr(scanner, "run_gitleaks_pre_commit", lambda _cfg: None)

    assert scanner.main(["privacy_guard.py", "pre-commit"]) == 1
    assert any("denylist" in item.lower() for item in errors)


def test_main_pre_push_warn_mode_allows_push(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cfg = make_config(pii_policy="warn", binary_policy="warn")
    logs: list[str] = []
    gitleaks_calls: list[tuple[Path, str]] = []

    monkeypatch.setattr(scanner, "eprint", lambda *args: logs.append(" ".join(str(item) for item in args)))
    monkeypatch.setattr(scanner, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(scanner, "load_config", lambda _root: cfg)
    monkeypatch.setattr(scanner, "read_denylist", lambda _root: [])
    monkeypatch.setattr(scanner, "require_gitleaks", lambda _cfg: None)
    monkeypatch.setattr(
        scanner,
        "commits_to_push",
        lambda _remote, local_sha, _remote_sha: [f"{local_sha}-1", f"{local_sha}-1", f"{local_sha}-2"],
    )
    monkeypatch.setattr(scanner, "binary_files_in_commit", lambda _sha: {"image.png"})
    monkeypatch.setattr(scanner, "scan_commit_patches", lambda _commits, *, cfg, denylist: ["src/x.py: [PII] email detected"])

    def fake_run_gitleaks_pre_push(_cfg: scanner.Config, root: Path, log_opts: str) -> None:
        gitleaks_calls.append((root, log_opts))

    monkeypatch.setattr(scanner, "run_gitleaks_pre_push", fake_run_gitleaks_pre_push)
    monkeypatch.setattr(
        scanner.sys,
        "stdin",
        io.StringIO("refs/heads/main abc refs/heads/main def\nrefs/heads/dev 111 refs/heads/dev " + scanner.ZERO_SHA + "\n"),
    )

    assert scanner.main(["privacy_guard.py", "pre-push", "origin", "https://example.com/repo.git"]) == 0
    assert gitleaks_calls == [(tmp_path, "def..abc"), (tmp_path, "111")]
    assert any("warning" in item.lower() for item in logs)


def test_main_unknown_stage_returns_error(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cfg = make_config()
    errors: list[str] = []
    monkeypatch.setattr(scanner, "eprint", lambda *args: errors.append(" ".join(str(item) for item in args)))
    monkeypatch.setattr(scanner, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(scanner, "load_config", lambda _root: cfg)
    monkeypatch.setattr(scanner, "read_denylist", lambda _root: [])

    assert scanner.main(["privacy_guard.py", "unknown-stage"]) == 1
    assert any("unknown stage" in item.lower() for item in errors)
