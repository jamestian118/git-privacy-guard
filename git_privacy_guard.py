#!/usr/bin/env python3
"""
git-privacy-guard

Bootstrap "public-safe" git hooks for:
- Secrets: via gitleaks (must be installed separately)
- Privacy/PII heuristics: local Python scanner (paths/emails/internal IPs + optional local denylist)

This installer does NOT change your global git config. It only writes files into a target repo and
sets repo-local `core.hooksPath=.githooks`.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import stat
import subprocess
import sys
from typing import Any, Iterable


VERSION = "0.1.0"


def _eprint(*args: object) -> None:
    print(*args, file=sys.stderr)


def _run(cmd: list[str], *, cwd: pathlib.Path | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        check=check,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _git(repo: pathlib.Path, args: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return _run(["git", "-C", str(repo), *args], check=check)


def _repo_root(repo: pathlib.Path) -> pathlib.Path:
    p = _git(repo, ["rev-parse", "--show-toplevel"])
    return pathlib.Path(p.stdout.strip())


def _write_text(path: pathlib.Path, content: str, *, executable: bool = False, force: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not force:
        raise FileExistsError(str(path))

    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    os.replace(tmp, path)

    if executable:
        st = os.stat(path)
        os.chmod(path, st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _append_gitignore_block(repo_root: pathlib.Path, *, force: bool = False) -> None:
    gitignore = repo_root / ".gitignore"
    start = "# --- privacy-guard (generated) ---"
    end = "# --- /privacy-guard ---"
    block_lines = [
        start,
        "# Local secrets / machine-private config",
        ".env",
        ".env.*",
        "*.local.*",
        "config.local.*",
        "",
        "# privacy-guard local config",
        ".privacy_guard.denylist.local.txt",
        end,
        "",
    ]
    block = "\n".join(block_lines)

    if not gitignore.exists():
        _write_text(gitignore, block, force=force)
        return

    old = gitignore.read_text(encoding="utf-8", errors="replace")
    if start in old and end in old:
        # Replace existing block (idempotent updates).
        pre = old.split(start)[0]
        post = old.split(end)[1]
        new = pre.rstrip("\n") + "\n" + block + post.lstrip("\n")
        _write_text(gitignore, new, force=True)
        return

    if old and not old.endswith("\n"):
        old += "\n"
    new = old + block
    _write_text(gitignore, new, force=True)


def _remove_gitignore_block(repo_root: pathlib.Path) -> bool:
    gitignore = repo_root / ".gitignore"
    start = "# --- privacy-guard (generated) ---"
    end = "# --- /privacy-guard ---"

    if not gitignore.exists():
        return False

    old = gitignore.read_text(encoding="utf-8", errors="replace")
    if start not in old or end not in old:
        return False

    before, rest = old.split(start, 1)
    _, after = rest.split(end, 1)

    left = before.rstrip("\n")
    right = after.lstrip("\n")

    if left and right:
        new = left + "\n" + right
    elif left:
        new = left + "\n"
    else:
        new = right

    if new and not new.endswith("\n"):
        new += "\n"

    _write_text(gitignore, new, force=True)
    return True


def _json_dumps(obj: Any) -> str:
    return json.dumps(obj, indent=2, sort_keys=True) + "\n"


def _template_config(profile: str) -> dict[str, Any]:
    if profile not in ("public", "private"):
        raise ValueError(f"Unknown profile: {profile}")

    # Public: strict blocking.
    # Private: allow private content (repo stays private), but still block explicit denylist hits and secrets.
    binary_policy = "block" if profile == "public" else "warn"
    pii_policy = "block" if profile == "public" else "warn"

    return {
        "profile": profile,
        "require_gitleaks": True,
        "gitleaks_redact": True,
        "pii_policy": pii_policy,
        "pii_allow_comment_tags": ["privacy:allow", "gitleaks:allow"],
        "allow_email_domains": [
            "example.com",
            "example.org",
            "example.net",
            "users.noreply.github.com",
        ],
        "blocked_path_globs": [
            ".env",
            ".env.*",
            "*.pem",
            "*.key",
            "*.p12",
            "*.pfx",
            "*.jks",
            "*.keystore",
            "id_rsa",
            "id_dsa",
        ],
        "binary_policy": binary_policy,
        "blocked_binary_exts": [
            ".png",
            ".jpg",
            ".jpeg",
            ".gif",
            ".webp",
            ".pdf",
            ".docx",
            ".xlsx",
            ".pptx",
            ".zip",
        ],
        # To avoid accidentally dumping private info in CI logs, privacy_guard.py will redact matches.
        "max_diff_bytes": 2_000_000,
    }


def _template_denylist_example() -> str:
    return (
        "# privacy-guard local denylist (EXAMPLE)\n"
        "#\n"
        "# Put real values in `.privacy_guard.denylist.local.txt` (gitignored).\n"
        "# Add exact substrings that must never appear in commits.\n"
        "#\n"
        "# Examples (replace with your real values in the *local* file):\n"
        "# - your full name\n"
        "# - your private email\n"
        "# - your company internal domain (e.g. corp.example)\n"
        "# - customer names / project codenames\n"
        "\n"
        "<YOUR_PRIVATE_EMAIL@example.com>\n"
        "<YOUR_REAL_NAME>\n"
        "<INTERNAL_DOMAIN.example>\n"
    )


def _template_pre_commit_hook() -> str:
    return (
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "\n"
        "repo_root=\"$(git rev-parse --show-toplevel)\"\n"
        "python3 \"$repo_root/.githooks/privacy_guard.py\" pre-commit\n"
    )


def _template_pre_push_hook() -> str:
    return (
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "\n"
        "repo_root=\"$(git rev-parse --show-toplevel)\"\n"
        "python3 \"$repo_root/.githooks/privacy_guard.py\" pre-push \"$@\"\n"
    )


def _template_repo_scanner_py() -> str:
    # Kept as a single file so the repo stays self-contained.
    return r'''#!/usr/bin/env python3
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
    pii_policy = str(raw.get("pii_policy", "block")).lower()
    if pii_policy not in {"block", "warn", "allow"}:
        raise RuntimeError("Invalid .privacy_guard.json: pii_policy must be one of block|warn|allow")
    return Config(
        profile=raw.get("profile", "public"),
        require_gitleaks=bool(raw.get("require_gitleaks", True)),
        gitleaks_redact=bool(raw.get("gitleaks_redact", True)),
        pii_policy=pii_policy,
        pii_allow_comment_tags=list(raw.get("pii_allow_comment_tags", ["privacy:allow", "gitleaks:allow"])),
        allow_email_domains=list(raw.get("allow_email_domains", ["example.com", "example.org", "example.net"])),
        blocked_path_globs=list(raw.get("blocked_path_globs", [])),
        binary_policy=str(raw.get("binary_policy", "block")),
        blocked_binary_exts=list(raw.get("blocked_binary_exts", [])),
        max_diff_bytes=int(raw.get("max_diff_bytes", 2_000_000)),
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
'''


def _template_github_actions_workflow() -> str:
    # Basic secrets scan on push/PR. PII scan is local-first; CI PII scanning is optional and can be noisy.
    return (
        "name: gitleaks\n"
        "on:\n"
        "  pull_request:\n"
        "  push:\n"
        "  workflow_dispatch:\n"
        "\n"
        "jobs:\n"
        "  scan:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "        with:\n"
        "          fetch-depth: 0\n"
        "      - uses: gitleaks/gitleaks-action@v2\n"
        "        env:\n"
        "          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n"
    )


def cmd_init(args: argparse.Namespace) -> int:
    repo = pathlib.Path(args.repo).expanduser().resolve()
    root = _repo_root(repo)

    profile = args.profile
    config_path = root / ".privacy_guard.json"
    deny_example = root / ".privacy_guard.denylist.example.txt"
    hooks_dir = root / ".githooks"
    repo_scanner = hooks_dir / "privacy_guard.py"
    hook_pre_commit = hooks_dir / "pre-commit"
    hook_pre_push = hooks_dir / "pre-push"

    if (hooks_dir.exists() or config_path.exists()) and not args.force:
        _eprint("Refusing to overwrite existing privacy-guard files without --force.")
        _eprint(f"Repo: {root}")
        _eprint(f"Existing: {hooks_dir if hooks_dir.exists() else config_path}")
        return 1

    # Write files
    _write_text(config_path, _json_dumps(_template_config(profile)), force=True)
    _write_text(deny_example, _template_denylist_example(), force=True)
    _write_text(repo_scanner, _template_repo_scanner_py(), executable=True, force=True)
    _write_text(hook_pre_commit, _template_pre_commit_hook(), executable=True, force=True)
    _write_text(hook_pre_push, _template_pre_push_hook(), executable=True, force=True)

    if args.gitignore:
        _append_gitignore_block(root, force=True)

    if args.ci:
        wf_path = root / ".github" / "workflows" / "gitleaks.yml"
        _write_text(wf_path, _template_github_actions_workflow(), force=True)

    # Enable repo-local hooks path.
    _git(root, ["config", "core.hooksPath", ".githooks"])

    print("Initialized privacy-guard in repo:")
    print(f"  {root}")
    print("Next:")
    print("  1) Install gitleaks: brew install gitleaks")
    print("  2) Create your local denylist (gitignored):")
    print("     -", str(root / ".privacy_guard.denylist.local.txt"))
    print("  3) Make a test commit; the hooks will block leaks automatically.")
    return 0


def cmd_uninstall(args: argparse.Namespace) -> int:
    repo = pathlib.Path(args.repo).expanduser().resolve()
    try:
        root = _repo_root(repo)
    except subprocess.CalledProcessError:
        _eprint("Not a git repo (or not inside one).")
        return 1

    config_path = root / ".privacy_guard.json"
    deny_example = root / ".privacy_guard.denylist.example.txt"
    hooks_dir = root / ".githooks"
    hook_files = [
        hooks_dir / "privacy_guard.py",
        hooks_dir / "pre-commit",
        hooks_dir / "pre-push",
    ]

    removed: list[str] = []
    skipped: list[str] = []

    for path in [config_path, deny_example, *hook_files]:
        if path.exists() and path.is_file():
            path.unlink()
            removed.append(str(path.relative_to(root)))

    if hooks_dir.exists():
        try:
            hooks_dir.rmdir()
            removed.append(".githooks/")
        except OSError:
            skipped.append(".githooks/ (not empty, left as-is)")

    if args.remove_ci:
        workflow_path = root / ".github" / "workflows" / "gitleaks.yml"
        if workflow_path.exists():
            generated_workflow = _template_github_actions_workflow()
            current = workflow_path.read_text(encoding="utf-8", errors="replace")
            if args.force or current == generated_workflow:
                workflow_path.unlink()
                removed.append(str(workflow_path.relative_to(root)))
                for parent in [workflow_path.parent, workflow_path.parent.parent]:
                    try:
                        parent.rmdir()
                    except OSError:
                        pass
            else:
                skipped.append(".github/workflows/gitleaks.yml (content differs; use --force to remove)")

    if args.gitignore:
        if _remove_gitignore_block(root):
            removed.append(".gitignore [privacy-guard block]")
        else:
            skipped.append(".gitignore [privacy-guard block not found]")

    hooks_path_proc = _git(root, ["config", "--get", "core.hooksPath"], check=False)
    hooks_path = hooks_path_proc.stdout.strip() if hooks_path_proc.returncode == 0 else ""
    if hooks_path == ".githooks":
        _git(root, ["config", "--unset", "core.hooksPath"], check=False)
        removed.append("git config core.hooksPath")
    elif hooks_path:
        skipped.append(f"git config core.hooksPath={hooks_path} (left unchanged)")

    print("Uninstalled privacy-guard from repo:")
    print(f"  {root}")
    if removed:
        print("Removed:")
        for item in removed:
            print(f"  - {item}")
    if skipped:
        print("Skipped:")
        for item in skipped:
            print(f"  - {item}")
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    repo = pathlib.Path(args.repo).expanduser().resolve()
    try:
        root = _repo_root(repo)
    except subprocess.CalledProcessError:
        _eprint("Not a git repo (or not inside one).")
        return 1

    print(f"Repo: {root}")
    p = _git(root, ["config", "--get", "core.hooksPath"], check=False)
    hooks = p.stdout.strip() if p.returncode == 0 else ""
    print(f"core.hooksPath: {hooks or '(not set)'}")
    print(f"gitleaks: {'found' if shutil.which('gitleaks') else 'missing'}")
    print(f"python3: {sys.executable}")
    cfg = root / ".privacy_guard.json"
    print(f".privacy_guard.json: {'present' if cfg.exists() else 'missing'}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="git-privacy-guard", description="Bootstrap privacy guard hooks for a git repo.")
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")

    sub = p.add_subparsers(dest="cmd", required=True)

    s_init = sub.add_parser("init", help="Initialize privacy-guard files in a repo")
    s_init.add_argument("repo", nargs="?", default=".", help="Path inside target git repo (default: .)")
    s_init.add_argument("--profile", choices=["public", "private"], default="public", help="Guard profile (default: public)")
    s_init.add_argument("--ci", action="store_true", help="Add a minimal GitHub Actions workflow to run gitleaks")
    s_init.add_argument("--gitignore", action="store_true", default=True, help="Append a .gitignore block (default: true)")
    s_init.add_argument("--no-gitignore", dest="gitignore", action="store_false", help="Do not modify .gitignore")
    s_init.add_argument("--force", action="store_true", help="Overwrite existing privacy-guard files")
    s_init.set_defaults(func=cmd_init)

    s_doc = sub.add_parser("doctor", help="Show repo status and dependency checks")
    s_doc.add_argument("repo", nargs="?", default=".", help="Path inside target git repo (default: .)")
    s_doc.set_defaults(func=cmd_doctor)

    s_uninstall = sub.add_parser("uninstall", help="Remove privacy-guard files from a repo")
    s_uninstall.add_argument("repo", nargs="?", default=".", help="Path inside target git repo (default: .)")
    s_uninstall.add_argument("--remove-ci", action="store_true", help="Remove generated .github/workflows/gitleaks.yml")
    s_uninstall.add_argument("--force", action="store_true", help="Force remove CI workflow even when content differs")
    s_uninstall.add_argument(
        "--gitignore",
        action="store_true",
        default=True,
        help="Remove the privacy-guard block from .gitignore (default: true)",
    )
    s_uninstall.add_argument("--no-gitignore", dest="gitignore", action="store_false", help="Do not modify .gitignore")
    s_uninstall.set_defaults(func=cmd_uninstall)

    return p


def main(argv: list[str]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


def cli() -> int:
    return main(sys.argv[1:])


if __name__ == "__main__":
    raise SystemExit(cli())
