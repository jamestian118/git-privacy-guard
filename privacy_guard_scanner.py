#!/usr/bin/env python3
"""
Repo-local privacy guard for git hooks.

Goals
- Block obvious "this should never be public" content before it enters history.
- Keep customization local-only (denylist via env/git-config/gitignored file).

Limitations
- This is NOT a perfect PII detector. It focuses on "strong signals":
  - emails (non-example domains)
  - local absolute paths (/Users/<name>/..., C:\\Users\\<name>\\..., /home/<name>/...)
  - internal IP ranges (10/172.16-31/192.168)
  - user-provided denylist substrings
- For binaries (images/pdfs/etc), we can't reliably inspect contents. Public profile blocks by default.
"""

from __future__ import annotations

import fnmatch
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import Iterable


def eprint(*args: object) -> None:
    print(*args, file=sys.stderr)


def run(
    cmd: list[str],
    *,
    check: bool = True,
    input_text: str | None = None,
    timeout_seconds: int | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            cmd,
            check=check,
            input=input_text,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as ex:
        if timeout_seconds is None:
            raise
        raise RuntimeError(f"Command timed out after {timeout_seconds}s: {' '.join(cmd)}") from ex


def git(args: list[str], *, check: bool = True, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return run(["git", *args], check=check, input_text=input_text)


def repo_root() -> pathlib.Path:
    p = git(["rev-parse", "--show-toplevel"])
    return pathlib.Path(p.stdout.strip())


@dataclass(frozen=True)
class Config:
    profile: str
    require_gitleaks: bool
    gitleaks_redact: bool
    pii_policy: str
    pii_allow_comment_tags: list[str]
    allow_email_domains: list[str]
    blocked_path_globs: list[str]
    binary_policy: str
    blocked_binary_exts: list[str]
    max_diff_bytes: int


def load_config(root: pathlib.Path) -> Config:
    path = root / ".privacy_guard.json"
    raw = json.loads(path.read_text(encoding="utf-8"))
    profile = str(raw.get("profile", "public")).lower()
    if profile not in {"public", "private"}:
        raise RuntimeError("Invalid .privacy_guard.json: profile must be one of public|private")

    pii_policy = str(raw.get("pii_policy", "block")).lower()
    if pii_policy not in {"block", "warn", "allow"}:
        raise RuntimeError("Invalid .privacy_guard.json: pii_policy must be one of block|warn|allow")

    binary_policy = str(raw.get("binary_policy", "block")).lower()
    if binary_policy not in {"block", "warn", "allow"}:
        raise RuntimeError("Invalid .privacy_guard.json: binary_policy must be one of block|warn|allow")

    max_diff_bytes = int(raw.get("max_diff_bytes", 2_000_000))
    if max_diff_bytes <= 0:
        raise RuntimeError("Invalid .privacy_guard.json: max_diff_bytes must be > 0")

    return Config(
        profile=profile,
        require_gitleaks=bool(raw.get("require_gitleaks", True)),
        gitleaks_redact=bool(raw.get("gitleaks_redact", True)),
        pii_policy=pii_policy,
        pii_allow_comment_tags=list(raw.get("pii_allow_comment_tags", ["privacy:allow", "gitleaks:allow"])),
        allow_email_domains=list(raw.get("allow_email_domains", ["example.com", "example.org", "example.net"])),
        blocked_path_globs=list(raw.get("blocked_path_globs", [])),
        binary_policy=binary_policy,
        blocked_binary_exts=list(raw.get("blocked_binary_exts", [])),
        max_diff_bytes=max_diff_bytes,
    )


def which(cmd: str) -> str | None:
    return shutil.which(cmd)


def gitleaks_cmd_args(cfg: Config) -> list[str]:
    args = ["gitleaks"]
    if cfg.gitleaks_redact:
        args.append("--redact")
    return args


def read_denylist(root: pathlib.Path) -> list[str]:
    # Order of precedence:
    # 1) env var (absolute or relative)
    # 2) repo-local git config (not committed)
    # 3) repo-local gitignored file
    paths: list[pathlib.Path] = []
    env = os.environ.get("PRIVACY_GUARD_DENYLIST")
    if env:
        paths.append((root / env).resolve() if not os.path.isabs(env) else pathlib.Path(env))

    try:
        p = git(["config", "--get", "privacy.guard.denylist"], check=False)
        if p.returncode == 0:
            val = p.stdout.strip()
            if val:
                paths.append((root / val).resolve() if not os.path.isabs(val) else pathlib.Path(val))
    except Exception:
        pass

    paths.append(root / ".privacy_guard.denylist.local.txt")

    items: list[str] = []
    for p in paths:
        if not p.exists():
            continue
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            items.append(s)
    # Deduplicate (stable)
    seen: set[str] = set()
    out: list[str] = []
    for s in items:
        if s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+\-]+)@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})\b")
MAC_PATH_RE = re.compile(r"(?<![A-Za-z0-9_])(/Users/[^/\s]+/)")
LINUX_HOME_RE = re.compile(r"(?<![A-Za-z0-9_])(/home/[^/\s]+/)")
WIN_USERS_RE = re.compile(r"(?<![A-Za-z0-9_])([A-Za-z]:\\\\Users\\\\[^\\\\\\s]+\\\\)")
INTERNAL_IP_RE = re.compile(r"\b(10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2})\b")
BASIC_AUTH_URL_RE = re.compile(r"\bhttps?://[^/\s:@]+:[^/\s@]+@")


def _is_allowed_line(line: str, cfg: Config) -> bool:
    return any(tag in line for tag in cfg.pii_allow_comment_tags)


def _redact_line(line: str) -> str:
    # Keep it simple: redact only common match types.
    line = EMAIL_RE.sub("<EMAIL>", line)
    line = MAC_PATH_RE.sub("<PATH>/", line)
    line = LINUX_HOME_RE.sub("<PATH>/", line)
    line = WIN_USERS_RE.sub("<PATH>\\\\", line)
    line = INTERNAL_IP_RE.sub("<IP>", line)
    line = BASIC_AUTH_URL_RE.sub("https://<USER>:<PASS>@", line)
    return line


def _match_any_glob(path: str, globs: Iterable[str]) -> bool:
    return any(fnmatch.fnmatch(path, g) for g in globs)


def staged_files() -> list[str]:
    p = git(["diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"])
    items = p.stdout.split("\0")
    return [s for s in items if s]


def staged_binary_files() -> set[str]:
    # `--numstat` prints "-" "-" for binary changes.
    p = git(["diff", "--cached", "--numstat", "--diff-filter=ACMR"], check=True)
    out: set[str] = set()
    for line in p.stdout.splitlines():
        parts = line.split("\t", 2)
        if len(parts) != 3:
            continue
        a, d, path = parts
        if a == "-" and d == "-":
            out.add(path)
    return out


def binary_files_in_commit(sha: str) -> set[str]:
    # `git show --numstat` prints "-" "-" for binary changes within a commit.
    p = git(["show", "--numstat", "--format=", sha], check=True)
    out: set[str] = set()
    for line in p.stdout.splitlines():
        parts = line.split("\t", 2)
        if len(parts) != 3:
            continue
        a, d, path = parts
        if a == "-" and d == "-":
            out.add(path)
    return out


def staged_diff_text(cfg: Config) -> str:
    p = git(["diff", "--cached", "--patch", "--unified=0", "--no-color", "--no-ext-diff"], check=True)
    if len(p.stdout.encode("utf-8", errors="replace")) > cfg.max_diff_bytes:
        raise RuntimeError(
            f"Staged diff is too large (>{cfg.max_diff_bytes} bytes). Split the commit, or raise max_diff_bytes in .privacy_guard.json."
        )
    return p.stdout


def extract_added_lines(diff_text: str) -> list[tuple[str, str]]:
    """
    Return list of (path, line) for added lines in a unified diff.
    We intentionally ignore removed lines to avoid blocking when you are deleting private data.
    """
    current_path = "<unknown>"
    out: list[tuple[str, str]] = []
    for raw in diff_text.splitlines():
        if raw.startswith("+++ "):
            # +++ b/<path> or +++ /dev/null
            s = raw[4:].strip()
            if s.startswith("b/"):
                current_path = s[2:]
            else:
                current_path = "<unknown>"
            continue
        if raw.startswith("+") and not raw.startswith("+++"):
            out.append((current_path, raw[1:]))
    return out


def check_pii_on_lines(lines: list[tuple[str, str]], *, cfg: Config, denylist: list[str]) -> list[str]:
    problems: list[str] = []
    for path, line in lines:
        if _is_allowed_line(line, cfg):
            continue
        # Exact denylist (local-only values)
        denylist_hit = False
        for needle in denylist:
            if needle and needle in line:
                problems.append(f"{path}: [DENYLIST] matched local denylist (redacted): {_redact_line(line)}")
                denylist_hit = True
                break
        if denylist_hit:
            continue

        # Heuristics
        m = EMAIL_RE.search(line)
        if m:
            domain = m.group(2).lower()
            if domain not in {d.lower() for d in cfg.allow_email_domains}:
                problems.append(f"{path}: [PII] email detected (redacted): {_redact_line(line)}")

        if MAC_PATH_RE.search(line) or LINUX_HOME_RE.search(line) or WIN_USERS_RE.search(line):
            problems.append(f"{path}: [PII] absolute home path detected (redacted): {_redact_line(line)}")

        if INTERNAL_IP_RE.search(line):
            problems.append(f"{path}: [PII] internal IP detected (redacted): {_redact_line(line)}")

        if BASIC_AUTH_URL_RE.search(line):
            problems.append(f"{path}: [PII] URL with basic-auth detected (redacted): {_redact_line(line)}")

        if len(problems) >= 50:
            problems.append("Too many findings; stopping early.")
            break
    return problems


def require_gitleaks(cfg: Config) -> None:
    if not cfg.require_gitleaks:
        return
    if which("gitleaks") is None:
        raise RuntimeError("gitleaks not found. Install it first: `brew install gitleaks`")


def run_gitleaks_pre_commit(cfg: Config) -> None:
    if not cfg.require_gitleaks:
        return
    # Prefer the staged scanner. Newer gitleaks versions deprecate protect/detect but keep them.
    cmd = gitleaks_cmd_args(cfg) + ["protect", "-v", "--staged"]
    p = run(cmd, check=False, timeout_seconds=60)
    if p.returncode == 0:
        return
    if p.returncode == 127:
        raise RuntimeError("gitleaks is required but not found. Install it first: `brew install gitleaks`")
    # Non-zero means leaks found.
    raise RuntimeError("gitleaks detected secrets in staged changes (see output above).")


def run_gitleaks_pre_push(cfg: Config, root: pathlib.Path, log_opts: str) -> None:
    if not cfg.require_gitleaks:
        return
    cmd = gitleaks_cmd_args(cfg) + ["git", "-v", "--log-opts", log_opts, str(root)]
    p = run(cmd, check=False, timeout_seconds=120)
    if p.returncode == 0:
        return
    if p.returncode == 127:
        raise RuntimeError("gitleaks is required but not found. Install it first: `brew install gitleaks`")
    raise RuntimeError("gitleaks detected secrets in commits being pushed (see output above).")


ZERO_SHA = "0" * 40


def commits_to_push(remote: str, local_sha: str, remote_sha: str) -> list[str]:
    if remote_sha == ZERO_SHA:
        # New branch or new remote ref; approximate using "not on any remote tracking branch for this remote".
        p = git(["rev-list", local_sha, "--not", f"--remotes={remote}"], check=True)
    else:
        p = git(["rev-list", f"{remote_sha}..{local_sha}"], check=True)
    commits = [s for s in p.stdout.splitlines() if s.strip()]
    return commits


def scan_commit_patches(commits: list[str], *, cfg: Config, denylist: list[str]) -> list[str]:
    problems: list[str] = []
    for sha in commits:
        p = git(["show", "--no-color", "--pretty=format:%H", "--patch", "--unified=0", sha], check=True)
        added = extract_added_lines(p.stdout)
        probs = check_pii_on_lines(added, cfg=cfg, denylist=denylist)
        if probs:
            problems.append(f"commit {sha}:")
            problems.extend(probs[:50])
        if len(problems) >= 200:
            problems.append("Too many findings; stopping early.")
            break
    return problems


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        eprint("usage: privacy_guard.py <pre-commit|pre-push> ...")
        return 2

    stage = argv[1]
    root = repo_root()
    cfg = load_config(root)
    denylist = read_denylist(root)

    try:
        if stage == "pre-commit":
            require_gitleaks(cfg)

            files = staged_files()
            if files:
                blocked = [p for p in files if _match_any_glob(p, cfg.blocked_path_globs)]
                if blocked:
                    raise RuntimeError("Blocked file paths staged for commit:\n- " + "\n- ".join(blocked))

                # Extension-based blocking is a coarse but useful safety net (especially for public repos).
                lowered_exts = {e.lower() for e in cfg.blocked_binary_exts}
                blocked_exts = [p for p in files if any(p.lower().endswith(ext) for ext in lowered_exts)]
                if blocked_exts and cfg.binary_policy == "block":
                    raise RuntimeError(
                        "Blocked file types staged (often binary artifacts that can't be reliably scanned). For public repos, prefer text-only.\n- "
                        + "\n- ".join(blocked_exts)
                    )
                if blocked_exts and cfg.binary_policy == "warn":
                    eprint("privacy-guard warning: potentially binary artifacts staged; manual review recommended:")
                    for b in blocked_exts:
                        eprint("  -", b)

            binaries = staged_binary_files()
            if binaries and cfg.binary_policy == "block":
                raise RuntimeError(
                    "Binary files staged (cannot be reliably scanned for private info). For public repos, move them to a private repo or remove from commit:\n- "
                    + "\n- ".join(sorted(binaries))
                )
            if binaries and cfg.binary_policy == "warn":
                eprint("privacy-guard warning: binary files staged; manual review recommended:")
                for b in sorted(binaries):
                    eprint("  -", b)

            diff_text = staged_diff_text(cfg)
            added = extract_added_lines(diff_text)
            probs = check_pii_on_lines(added, cfg=cfg, denylist=denylist)
            if probs:
                deny_hits = [p for p in probs if "[DENYLIST]" in p]
                pii_hits = [p for p in probs if "[PII]" in p]

                if deny_hits:
                    msg = "privacy-guard blocked this commit due to local denylist hits:\n- " + "\n- ".join(deny_hits[:50])
                    msg += "\n\nFix: remove/replace the private data before committing."
                    raise RuntimeError(msg)

                if pii_hits and cfg.pii_policy == "warn":
                    eprint("privacy-guard warning: potential PII patterns detected in staged diff:")
                    for p in pii_hits[:50]:
                        eprint("  -", p)
                elif pii_hits and cfg.pii_policy == "block":
                    msg = "privacy-guard blocked this commit due to potential private data:\n- " + "\n- ".join(pii_hits[:50])
                    msg += "\n\nFix: replace with placeholders (e.g., $HOME, user@example.com) or add `privacy:allow` on safe example lines."
                    raise RuntimeError(msg)

            # Secrets scan
            run_gitleaks_pre_commit(cfg)
            return 0

        if stage == "pre-push":
            # args: remote_name remote_url
            require_gitleaks(cfg)
            if len(argv) < 4:
                raise RuntimeError("pre-push hook must pass <remote_name> <remote_url>")
            remote_name = argv[2]

            # Read ref updates from stdin.
            updates = [ln.strip().split() for ln in sys.stdin.read().splitlines() if ln.strip()]
            # Each line: <local ref> <local sha> <remote ref> <remote sha>
            commits: list[str] = []
            log_opts_list: list[str] = []
            for u in updates:
                if len(u) != 4:
                    continue
                _local_ref, local_sha, _remote_ref, remote_sha = u
                if local_sha == ZERO_SHA:
                    continue  # deleting remote ref
                # Collect commits for PII scan.
                commits.extend(commits_to_push(remote_name, local_sha, remote_sha))
                # Collect log-opts for gitleaks scan.
                if remote_sha == ZERO_SHA:
                    log_opts_list.append(local_sha)
                else:
                    log_opts_list.append(f"{remote_sha}..{local_sha}")

            # Deduplicate commits (stable).
            seen: set[str] = set()
            uniq_commits: list[str] = []
            for c in commits:
                if c in seen:
                    continue
                seen.add(c)
                uniq_commits.append(c)

            if uniq_commits:
                if cfg.binary_policy in ("block", "warn"):
                    offenders: list[str] = []
                    for sha in uniq_commits:
                        bins = binary_files_in_commit(sha)
                        if not bins:
                            continue
                        if cfg.binary_policy == "warn":
                            eprint(f"privacy-guard warning: commit {sha} includes binary diffs; manual review recommended:")
                            for b in sorted(bins):
                                eprint("  -", b)
                        else:
                            offenders.append(f"{sha}: " + ", ".join(sorted(bins)[:5]))
                    if offenders and cfg.binary_policy == "block":
                        raise RuntimeError(
                            "Binary diffs detected in commits being pushed (cannot be reliably scanned for private info). For public repos, keep history text-only.\n- "
                            + "\n- ".join(offenders[:20])
                        )

                probs = scan_commit_patches(uniq_commits, cfg=cfg, denylist=denylist)
                if probs:
                    deny_hits = [p for p in probs if "[DENYLIST]" in p]
                    pii_hits = [p for p in probs if "[PII]" in p]

                    if deny_hits:
                        msg = (
                            "privacy-guard blocked this push due to local denylist hits in commits being pushed:\n- "
                            + "\n- ".join(deny_hits[:80])
                        )
                        msg += "\n\nFix: rewrite the commits (interactive rebase) to remove/replace the private data before pushing."
                        raise RuntimeError(msg)

                    if pii_hits and cfg.pii_policy == "warn":
                        eprint("privacy-guard warning: potential PII patterns detected in commits being pushed:")
                        for p in pii_hits[:80]:
                            eprint("  -", p)
                    elif pii_hits and cfg.pii_policy == "block":
                        msg = (
                            "privacy-guard blocked this push due to potential private data in commits being pushed:\n- "
                            + "\n- ".join(pii_hits[:80])
                        )
                        msg += "\n\nFix: rewrite the commits (interactive rebase) to remove/replace the private data before pushing."
                        raise RuntimeError(msg)

            # Secrets scan (per ref update). Keep it simple; scanning full history is slow but safe.
            for log_opts in log_opts_list:
                run_gitleaks_pre_push(cfg, root, log_opts)

            return 0

        raise RuntimeError(f"Unknown stage: {stage}")

    except RuntimeError as ex:
        eprint(str(ex))
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
