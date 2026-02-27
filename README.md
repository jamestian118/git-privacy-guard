# git-privacy-guard

## 中文

### 这是什么

`git-privacy-guard` 是一个**本地工具**，用于给你的 Git 仓库加两道“闸门”，让你在把代码推到 GitHub（尤其是公开仓库）之前，尽量避免把隐私/敏感信息写进提交历史。

它做两类检查：

- **Secrets（密钥/令牌/密码）**：调用 `gitleaks` 扫描（你需要自己安装 `gitleaks`）
- **隐私/PII（启发式）**：仓库内置一个轻量扫描器，主要抓“强特征”：
  - 邮箱（非 `example.com/org/net`、非 `users.noreply.github.com`）
  - 本机绝对路径（`/Users/<name>/...`、`/home/<name>/...`、`C:\Users\<name>\...`）
  - 内网 IP（`10.*` / `172.16-31.*` / `192.168.*`）
  - 你自己配置的本地 denylist（不进 Git，不会推到 GitHub）

重要限制（必须接受的事实）：

- “自动处理所有隐私信息”不可能 100% 靠机器完成。这个工具的定位是：**自动拦截 + 给出可执行修复建议**，避免隐私进入任何 commit。
- 对二进制文件（图片/PDF/Office/zip 等）无法可靠检测内容。公开仓库默认会阻止提交这些类型，除非你手动调整策略。

### 适用场景

- 你希望 **GitHub 上保留完整提交历史**（而不是导出脱敏快照）
- 你的仓库可能是 **个人公开仓库**（更严格）或 **个人私有仓库**（相对宽松）
- 你希望“无痛”：不想每次推送都靠脑子记得检查

### 依赖

- macOS / Linux / Windows 都可用（脚本本身是 Python）
- `python3`（你机器上一般已有）
- `git`
- `gitleaks`（必须安装，否则会阻止 commit/push）

安装 `gitleaks`（macOS Homebrew）：

```bash
brew install gitleaks
```

可选：把工具安装为 CLI（需要仓库里新增的 `pyproject.toml`）：

```bash
python3 -m pip install -e "$HOME/Documents/Code/git-privacy-guard"
```

### 使用方法（初始化某个仓库）

进入你的目标仓库（或任意子目录）：

```bash
cd /path/to/your-repo
```

运行初始化（公开仓库建议 `--profile public`）：

```bash
git-privacy-guard init --profile public --ci
```

私有仓库（更宽松：PII 启发式默认只警告不阻止，但仍会阻止 secrets 和本地 denylist 命中）：

```bash
git-privacy-guard init --profile private --ci
```

如果你不想安装 CLI，也可以直接调用脚本：

```bash
python3 "$HOME/Documents/Code/git-privacy-guard/git_privacy_guard.py" init --profile public --ci
```

初始化会做这些事：

- 写入/更新（会被提交进仓库）：
  - `.privacy_guard.json`（规则配置，不含私人信息）
  - `.privacy_guard.denylist.example.txt`（示例，不参与扫描）
  - `.githooks/`（可提交的 git hooks + 扫描脚本）
  - 可选：`.github/workflows/gitleaks.yml`（CI 扫 secrets）
- 写入/更新 `.gitignore`（追加一个标记区块），其中包含：
  - `.privacy_guard.denylist.local.txt`（本地 denylist，**不会进 Git**）
  - `.env` / `.env.*` 等常见本地配置
- 设置 repo-local 配置：`git config core.hooksPath .githooks`

### 卸载（撤销初始化）

在目标仓库里运行：

```bash
git-privacy-guard uninstall
```

默认行为：

- 删除 `.privacy_guard.json`、`.privacy_guard.denylist.example.txt`、`.githooks/privacy_guard.py`、`.githooks/pre-commit`、`.githooks/pre-push`
- 如果 `.githooks/` 已空则删除目录；若目录内有其他文件则保留并提示
- 删除 `.gitignore` 里由本工具插入的标记区块
- 当 `core.hooksPath` 当前值为 `.githooks` 时自动 unset

如果你也想移除本工具生成的 CI workflow：

```bash
git-privacy-guard uninstall --remove-ci
```

当 `.github/workflows/gitleaks.yml` 内容已被手改时，默认不会删除；可加 `--force` 强制删除。

### 配置本地 denylist（最关键）

在仓库根目录新建（或编辑）：

```text
.privacy_guard.denylist.local.txt
```

把你明确不允许进入提交历史的字符串写进去（每行一个），比如：

- 你的私人邮箱
- 公司内网域名
- 客户名/项目代号
- 任何你认为“出现一次就算事故”的字串

这个文件被 `.gitignore` 忽略，所以不会推到 GitHub。

你也可以用 git config 指定 denylist 路径（同样不会被提交）：

```bash
git config privacy.guard.denylist /absolute/path/to/denylist.txt
```

或用环境变量（临时生效）：

```bash
export PRIVACY_GUARD_DENYLIST=/absolute/path/to/denylist.txt
```

### 策略字段与 hook timeout

`.privacy_guard.json` 的 `pii_policy` 只允许以下值：

- `block`：命中 PII 规则时阻止 commit/push
- `warn`：命中 PII 规则时仅告警
- `allow`：跳过 PII 启发式规则（但 denylist 与 secrets 仍会阻止）

说明：

- 当某一行命中本地 denylist 时，工具只报告 `[DENYLIST]`，不会再重复追加同一行的 `[PII]` 告警。
- gitleaks 子进程有 timeout 保护：
  - `pre-commit`：60s
  - `pre-push`：120s（每个 ref 更新范围）

### 允许某一行（少用）

如果某一行是“假数据/示例”，你确认可以公开，可以在该行加入：

- `privacy:allow` 或
- `gitleaks:allow`

工具会跳过那一行的隐私扫描。

### 验证是否生效

检查状态：

```bash
git-privacy-guard doctor
```

运行本地 gate：

```bash
./scripts/verify
./scripts/secrets-check
```

然后做一次“故意包含敏感信息”的测试（例如在临时分支里），看 commit/push 是否按策略被阻止或告警。

### 常见问题

1) 提示 `gitleaks not found`

解决：

```bash
brew install gitleaks
```

2) 提交被阻止：检测到邮箱/路径/内网 IP

这是预期行为。修复方式通常是把内容替换成占位符：

- 路径：`/Users/<username>/...` -> `$HOME/...` 或 `<REPO_ROOT>/...`
- 邮箱：`xxx@yyy.com` -> `user@example.com`
- 内网 IP：`192.168.1.10` -> `<IP>`

3) 我需要提交图片/PDF 到公开仓库

默认公开策略会阻止，因为二进制文件无法可靠扫描隐私内容。你可以改 `.privacy_guard.json` 的：

- `binary_policy` 改成 `warn` 或 `allow`
- 或把文件放到私有仓库

（建议：公开仓库尽量只放可审查的文本内容。）

---

## English

### What This Is

`git-privacy-guard` is a **local bootstrapper** that adds two guardrails to a Git repository, so you are less likely to accidentally push private/sensitive data to GitHub (especially to **public** repos).

It checks two classes of problems:

- **Secrets**: runs `gitleaks` (you must install `gitleaks` yourself)
- **Privacy/PII heuristics**: a lightweight repo-local scanner that focuses on strong signals:
  - emails (non-`example.*`, non-`users.noreply.github.com`)
  - absolute home paths (`/Users/<name>/...`, `/home/<name>/...`, `C:\Users\<name>\...`)
  - internal IP ranges (`10.*` / `172.16-31.*` / `192.168.*`)
  - your own local denylist (not committed, never pushed)

Important limitations:

- It is not realistically possible to automatically sanitize "all privacy info" with 100% accuracy. This tool is designed to **block** risky commits/pushes and give actionable remediation.
- For binaries (images/PDF/Office/zip), content scanning is unreliable. The public profile blocks them by default unless you relax the policy.

### Requirements

- `python3`
- `git`
- `gitleaks` (required; missing `gitleaks` will block commit/push)

Install `gitleaks` on macOS:

```bash
brew install gitleaks
```

Optional: install this repository as a CLI (enabled by `pyproject.toml`):

```bash
python3 -m pip install -e "$HOME/Documents/Code/git-privacy-guard"
```

### Initialize A Repo

From inside your target repo:

```bash
git-privacy-guard init --profile public --ci
```

For a private repo (more permissive: PII heuristics warn by default, but secrets + local denylist still block):

```bash
git-privacy-guard init --profile private --ci
```

If you prefer not to install the CLI, you can invoke the script directly:

```bash
python3 "$HOME/Documents/Code/git-privacy-guard/git_privacy_guard.py" init --profile public --ci
```

This will:

- Add committed files:
  - `.privacy_guard.json`
  - `.privacy_guard.denylist.example.txt`
  - `.githooks/` (versioned hooks + scanner)
  - optionally `.github/workflows/gitleaks.yml`
- Append a marked block to `.gitignore` (including `.privacy_guard.denylist.local.txt`)
- Set repo-local `core.hooksPath=.githooks`

### Uninstall (Revert Bootstrap)

From the target repo:

```bash
git-privacy-guard uninstall
```

Default behavior:

- Removes `.privacy_guard.json`, `.privacy_guard.denylist.example.txt`, `.githooks/privacy_guard.py`, `.githooks/pre-commit`, `.githooks/pre-push`
- Removes `.githooks/` when it is empty; keeps it when extra files exist
- Removes the generated privacy-guard block in `.gitignore`
- Unsets `core.hooksPath` when its current value is `.githooks`

To also remove generated CI workflow:

```bash
git-privacy-guard uninstall --remove-ci
```

If `.github/workflows/gitleaks.yml` was modified manually, uninstall skips it by default; use `--force` to remove anyway.

### Configure Your Local Denylist (Most Important)

Create/edit:

```text
.privacy_guard.denylist.local.txt
```

Put exact substrings that must never enter history (one per line). This file is gitignored by default.

Alternative (per-repo local git config, not committed):

```bash
git config privacy.guard.denylist /absolute/path/to/denylist.txt
```

Or via env var:

```bash
export PRIVACY_GUARD_DENYLIST=/absolute/path/to/denylist.txt
```

### Policy Values And Hook Timeouts

`pii_policy` in `.privacy_guard.json` only accepts:

- `block`: block commit/push on PII heuristic hits
- `warn`: warn only on PII heuristic hits
- `allow`: skip PII heuristic blocking/warnings (denylist + secrets still block)

Notes:

- If a line matches local denylist, the scanner emits `[DENYLIST]` once and skips duplicate `[PII]` findings for that same line.
- gitleaks subprocess timeouts are enforced:
  - `pre-commit`: 60s
  - `pre-push`: 120s (per pushed ref range)

### Allow A Line (Use Sparingly)

Add `privacy:allow` or `gitleaks:allow` on a safe example line to skip PII scanning for that line.

### Verify

```bash
git-privacy-guard doctor
./scripts/verify
./scripts/secrets-check
```

Then make a test commit on a throwaway branch and confirm commit/push is blocked or warned as configured.
