# .ai/handoff.md

## 2026-02-27 Phase 5.18-5.19 GPG lane（custom_patterns + config 友好报错）

### Goal / DoD
- Goal: 完成 Phase 5 指定项：
  - `FileNotFoundError` / `JSONDecodeError` 友好提示
  - 支持 `.privacy_guard.json` 的 `custom_patterns`（regex 自定义规则）
- DoD:
  - strict policy stack pass
  - `./scripts/verify` pass
  - `./scripts/secrets-check` pass

### Repo State
- Project: `/Users/Zhuanz/Documents/Code/git-privacy-guard`
- Branch: `ai/20260227-phase0-upgrade`

### Changes
- Modified: `privacy_guard_scanner.py`
  - `load_config()` 对缺失配置文件与 JSON 解析失败给出可读错误信息。
  - 新增 `Config.custom_patterns` 字段并在读取阶段校验 regex 合法性。
  - `check_pii_on_lines()` 支持 `custom_patterns` 命中（输出 `[PII] custom pattern detected`）。
  - 将 `load_config()/read_denylist()` 放入 `main()` 的 `try`，保证统一友好报错输出。
- Modified: `tests/test_privacy_guard_scanner.py`
  - 新增 4 个用例：invalid custom regex、custom pattern 命中、missing config 友好报错、invalid JSON 友好报错。
- Modified: `git_privacy_guard.py`
  - 初始化模板 `.privacy_guard.json` 新增 `custom_patterns: []` 字段。
- Modified: `README.md`
  - 中文 + English 同步更新 `custom_patterns` 配置说明与 config 错误排查说明。

### Verification Commands
- `/Users/Zhuanz/Documents/Code/universal-harness-kit/scripts/agent-policy-stack --tool codex --cwd "$PWD" --strict --strict-profile harness`
- `./scripts/verify`
- `./scripts/secrets-check`

### Key Outputs
- strict: `strict_result=pass`
- verify:
  - `23 passed`
  - `Required test coverage of 60% reached. Total coverage: 77.17%`
  - `[verify] OK`
- secrets-check:
  - `5 commits scanned`
  - `no leaks found`
  - `[secrets-check] OK`

### Next Steps
1. 可选：在临时仓库 smoke 一次 `git-privacy-guard init` + 自定义 `custom_patterns`，确认 pre-commit/pre-push 的终端提示符合预期。
2. 可选：补充一条 doc 示例，展示如何为企业内部 ID（如 `EMP-\d+`）编写 pattern 并避免误报。

## 2026-02-27 Phase 4.4-4.6 GPG lane（tests + scanner 抽离）

### Goal / DoD
- Goal: 完成测试框架、scanner 模块抽离、覆盖率门禁（`>=60%`）。
- DoD:
  - strict policy stack pass
  - `./scripts/verify` pass（含 pytest + coverage gate）
  - `./scripts/secrets-check` pass

### Repo State
- Project: `/Users/Zhuanz/Documents/Code/git-privacy-guard`
- Branch: `ai/20260227-phase0-upgrade`

### Changes
- Added: `privacy_guard_scanner.py`（从嵌入式模板抽离出的独立 scanner）
- Added: `tests/test_privacy_guard_scanner.py`（19 个 pytest 用例）
- Added: `docs/verify.usage.zh-en.md`（`scripts/verify` 双语使用文档）
- Modified: `git_privacy_guard.py`（`_template_repo_scanner_py` 改为读取独立模块）
- Modified: `pyproject.toml`（新增 `privacy_guard_scanner` module + pytest testpaths）
- Modified: `scripts/verify`（接入 pytest-cov，coverage fail-under=60）
- Modified: `README.md`（中英 Verify 章节补充 coverage/secrets-check 说明）
- Modified: `privacy_guard_scanner.py`（新增 config 校验：`profile`/`binary_policy`/`max_diff_bytes`）

### Verification Commands
- `/Users/Zhuanz/Documents/Code/universal-harness-kit/scripts/agent-policy-stack --tool codex --cwd "$PWD" --strict --strict-profile harness`
- `./scripts/verify`
- `./scripts/secrets-check`

### Key Outputs
- strict: `strict_result=pass`
- verify:
  - `19 passed`
  - `Required test coverage of 60% reached. Total coverage: 76.54%`
  - `[verify] OK`
- secrets-check:
  - `4 commits scanned`
  - `no leaks found`
  - `[secrets-check] OK`

### Next Steps
1. 可选：在临时 git 仓库端到端跑 `git-privacy-guard init`，确认生成 `.githooks/privacy_guard.py` 与 `privacy_guard_scanner.py` 一致。
2. 若要继续提高质量门槛，可逐步把 coverage gate 从 `60` 提升到 `80`。

## 2026-02-27 P2-11~13 Packaging + Uninstall

### Goal / DoD
- Goal: 完成 Phase 2 指定项：`pyproject.toml`、`LICENSE(MIT)`、`uninstall` 子命令。
- DoD:
  - strict policy stack pass
  - `./scripts/verify` pass
  - `./scripts/secrets-check` pass

### Repo State
- Project: `/Users/Zhuanz/Documents/Code/git-privacy-guard`
- Branch: `ai/20260227-phase0-upgrade`

### Changes
- Added: `pyproject.toml`
- Added: `LICENSE`
- Modified: `git_privacy_guard.py` (`uninstall` 子命令、`.gitignore` block 移除 helper、console entrypoint)
- Modified: `README.md`（中英 usage 同步，补充 CLI 安装与 uninstall）

### Verification Commands
- `/Users/Zhuanz/Documents/Code/universal-harness-kit/scripts/agent-policy-stack --tool codex --cwd "$PWD" --strict --strict-profile harness`
- `./scripts/verify`
- `./scripts/secrets-check`

### Key Outputs
- strict: `strict_result=pass`
- verify: `[verify] OK`
- secrets-check: `no leaks found` + `[secrets-check] OK`

### Next Steps
1. 可选：在干净测试仓库中跑 `git-privacy-guard init`/`uninstall` 端到端 smoke。
2. 如需发布到 PyPI，再补充 `project.urls`/release workflow 与版本策略。

## 2026-02-26 P2-2 Harness Skeleton 接入

### Goal / DoD
- Goal: 为单文件工具项目 `git-privacy-guard` 补齐 harness strict 所需最小骨架。
- DoD:
  - `agent-policy-stack --strict --strict-profile harness` pass
  - `./scripts/verify` pass

### Repo State
- Project: `/Users/Zhuanz/Documents/Code/git-privacy-guard`
- Parent git root: `/Users/Zhuanz/Documents/Code`
- Branch/Head: `ai/20260221-artifact-finalize` / `1db86c2`

### Changes
- Added: `AGENTS.md`
- Added: `.ai/handoff.md`
- Added: `scripts/verify`
- Added: `.claude/CLAUDE.md`
- Added: `.codex/commands/closeout.md`
- Added: `.gemini/GEMINI.md`

### Verification Commands
- `/Users/Zhuanz/Documents/Code/universal-harness-kit/scripts/agent-policy-stack --tool codex --cwd /Users/Zhuanz/Documents/Code/git-privacy-guard --strict --strict-profile harness`
- `./scripts/verify`

### Key Outputs
- strict: `strict_result=pass`
- verify: `[verify] OK`

### Next Steps
1. 若后续新增脚本/命令，保持双语 usage 文档同步。
2. 进入业务开发前先读取 `AGENTS.md` 并遵守 `scripts/verify` 闭环。

## 2026-02-27 Gate 3 支持 lane（Phase 3 验证证据追加）

### Scope
- 仅执行支持任务：strict + verify + secrets-check。
- 未修改业务代码（`git_privacy_guard.py` / `README.md` / `pyproject.toml` 等均未改动）。

### Verification Commands
- `/Users/Zhuanz/Documents/Code/universal-harness-kit/scripts/agent-policy-stack --tool codex --cwd "$PWD" --strict --strict-profile harness`
- `./scripts/verify`
- `./scripts/secrets-check`

### Key Outputs
- strict (2026-02-27 20:35 CST): `strict_result=pass`
- verify: `[verify] OK`
- secrets-check: `3 commits scanned` + `no leaks found` + `[secrets-check] OK`

### Result
- Gate 3 支持 lane 本轮验证结论：PASS（3/3 命令 exit 0）。

## 2026-02-27 Phase 7 GPG lane（7.3 + 7.10）

### Scope
- 7.3 新增 CI workflow（ruff + verify/pytest）。
- 7.10 README 示例路径参数化（`GPG_ROOT` 环境变量）。

### Changes
- added: `.github/workflows/ci.yml`
- modified: `README.md`

### Verification Commands
- `/Users/Zhuanz/Documents/Code/universal-harness-kit/scripts/agent-policy-stack --tool codex --cwd "$PWD" --strict --strict-profile harness`
- `./scripts/verify`
- `./scripts/secrets-check`

### Key Outputs
- strict: `strict_result=pass`
- verify: `23 passed` + `Total coverage: 77.17%` + `[verify] OK`
- secrets-check: `no leaks found` + `[secrets-check] OK`

### Notes
- `.DS_Store/.coverage` 为本地未跟踪噪音文件，未纳入提交。
- 本 lane 由主线程在 agent thread limit 约束下补齐执行。

## 2026-02-27 Phase 8 GPG（8.3/8.7）
- README 补齐 `uninstall` 相关参数说明（`--force`、`--no-gitignore`）。
- 新增 `CHANGELOG.md`。
- 验证：strict/verify/secrets 全绿（见 `/tmp/phase8-git-privacy-guard.log`）。
