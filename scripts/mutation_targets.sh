#!/usr/bin/env bash
# 采集"这一笔改动该跑哪些变异目标"。用法：scripts/mutation_targets.sh <library|gates|all> [base]
#
# 抽成脚本而不是留在 ci.yml 里，是为了两件事：
#   · 两个 matrix（库面 / 门脚本面）复用同一条口径 —— 内联两份迟早分叉；
#   · 本地能原样跑一遍验证（改 CI 逻辑不许靠想象，改错了就是整条门静默不跑）。
# 输出口径：stdout 只有 `args=…`（喂 $GITHUB_OUTPUT），其他都走 stderr。
set -euo pipefail
face=${1:?用法: mutation_targets.sh <library|gates|all> [base]}
base=${2:-origin/main}

diff=$(git diff --name-only "$base"...HEAD 2>/dev/null || true)
targets=""

if [ "$face" != "gates" ]; then
  # 库面：产品代码/测试/示例/依赖清单，或直接改这份登记表本身。
  if printf '%s\n' "$diff" | grep -qE '^(src|tests|examples)/|^Cargo\.toml$|^scripts/mutants/trit-vcs\.json$'; then
    targets="trit-vcs"
  fi
fi

if [ "$face" != "library" ]; then
  # 门脚本面：只有带 --self-test 的脚本才算靶子（没自测面的脚本判不动，登记了也是假覆盖）。
  scripts=$(printf '%s\n' "$diff" | grep -E '^scripts/[A-Za-z0-9_.-]+\.py$' \
    | while read -r f; do grep -q -- '--self-test' "$f" 2>/dev/null && echo "$f"; done || true)
  # 登记表按目标拆文件 ⇒ 改 json 就是改那个目标的登记，要把文件名映射回目标本身。
  jsons=$(printf '%s\n' "$diff" | grep -E '^scripts/mutants/scripts__.*\.json$' \
    | sed -E 's#^scripts/mutants/(.*)\.json$#\1#; s#__#/#g' || true)
  targets=$(printf '%s\n%s\n%s\n' "$targets" "$scripts" "$jsons" | sed '/^$/d' | sort -u)
fi

# 靶子消失了就不算「这个目标 0 条变异」：删除型改动仍会被 diff 选中，而门对
# "选中了但没登记"是 fail-closed 判红 —— 那是根本没东西可跑的靶子，不是漏登记。
# 反过来，新加的目标（文件在、登记 0 条）仍会交给门判红，fail-closed 一寸不放松。
targets=$(for t in $targets; do
            if [ -e "$t" ] || [ -e "crates/$t" ] || { [ "$t" = "trit-vcs" ] && [ -d src ]; }; then
              printf '%s\n' "$t"
            fi
          done | sort -u)

args=""
for t in $targets; do args="$args --pkg $t"; done
printf 'selected: %s\n' "${targets:-none}" >&2
printf 'args=%s\n' "$args"
