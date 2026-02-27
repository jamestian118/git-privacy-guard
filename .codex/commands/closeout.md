# /closeout

目标：在 milestone / stop / CLI 切换前，按统一证据链完成收尾，避免遗漏 artifacts 清理闸门。

## Checklist
1. 运行 verify gate：
```bash
./scripts/verify
```

2. 生成 artifacts 清理计划（仅 dry-run，不删除）：
```bash
./scripts/finalize-artifacts dry-run
```

3. 明确向用户确认是否清理 artifacts（必须是明确 yes/no）。
- 若用户未明确确认：停止在 dry-run，保留现场。
- 若用户明确确认：继续第 4 步。

4. 生成 confirm 并执行 apply：
```bash
./scripts/finalize-artifacts confirm --approved-by "${USER:-agent}"
TOKEN="$(python3 - <<'PY'
import json
with open('.ai/finalize-artifacts.confirm.json', encoding='utf-8') as f:
    print(json.load(f)['token'])
PY
)"
./scripts/finalize-artifacts apply --token "$TOKEN"
```

5. 运行 gc（抗熵检查）：
```bash
./scripts/gc
```

6. 更新 `.ai/handoff.md`（必须包含）：
- Goal/DoD
- branch/commit + git status 摘要
- 本次执行命令与关键输出
- artifacts 处理结果（plan / confirm / apply 是否执行）
- Next Steps（3-8 条）

7. Lessons Learned 同步：
- 将本次 Lessons Learned 追加到 `/Users/Zhuanz/Documents/Code/universal-harness-kit/.ai/lessons-learned.md`
- 若同类问题出现 ≥2 次，提议升级为 golden principle 或机械化检查

## Pass/Fail 规则
- Pass：`verify` 通过，且 artifacts 处理状态与用户确认一致（确认后清理 / 未确认保留）。
- Fail：`verify` 失败、未确认却执行删除、或 handoff 证据链不完整。
