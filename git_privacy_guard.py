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
        # Optional extra PII signals; each item is a regex string.
        "custom_patterns": [],
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
    scanner_src = pathlib.Path(__file__).with_name("privacy_guard_scanner.py")
    return scanner_src.read_text(encoding="utf-8")

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
