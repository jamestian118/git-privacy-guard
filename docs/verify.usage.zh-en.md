# verify script usage / `scripts/verify` 使用说明

## 中文

### 目的

`scripts/verify` 是本项目的本地质量门禁，执行两类检查：

1. CLI 可用性：`python3 git_privacy_guard.py --help`
2. 测试与覆盖率：`python3 -m pytest --cov=privacy_guard_scanner --cov-fail-under=60`

### 前置条件

- `python3` 可执行
- 已安装 `pytest` 与 `pytest-cov`
- 在项目根目录或任意子目录执行（脚本会自动切回项目根）

### 运行命令

```bash
./scripts/verify
```

### 输出与退出码

- 成功：输出 `"[verify] OK"`，退出码 `0`
- 失败：输出 pytest 或命令报错，退出码非 `0`

### 常见问题

1. `No module named pytest`

```bash
python3 -m pip install pytest pytest-cov
```

2. `Coverage failure: total of XX is less than fail-under=60`

- 补充/修复 `tests/` 用例，覆盖新增逻辑或边界条件。

3. `git_privacy_guard.py --help` 失败

- 先运行：

```bash
python3 git_privacy_guard.py --help
```

- 根据报错修复语法或依赖问题，再重跑 `./scripts/verify`。

## English

### Purpose

`scripts/verify` is the local quality gate for this repository. It runs:

1. CLI smoke check: `python3 git_privacy_guard.py --help`
2. Tests + coverage: `python3 -m pytest --cov=privacy_guard_scanner --cov-fail-under=60`

### Prerequisites

- `python3`
- `pytest` and `pytest-cov` installed
- Run from repo root or any subdirectory (script auto-resolves repo root)

### Command

```bash
./scripts/verify
```

### Output and Exit Code

- Success: prints `"[verify] OK"` and exits `0`
- Failure: prints command/pytest errors and exits non-zero

### Troubleshooting

1. `No module named pytest`

```bash
python3 -m pip install pytest pytest-cov
```

2. `Coverage failure: total of XX is less than fail-under=60`

- Add/fix tests under `tests/` for uncovered behavior and edge cases.

3. `git_privacy_guard.py --help` fails

```bash
python3 git_privacy_guard.py --help
```

- Fix syntax/runtime issues first, then rerun `./scripts/verify`.
