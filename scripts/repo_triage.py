#!/usr/bin/env python3
"""PR 分诊台：一条命令回答"哪些我今天必须看、哪些不用我管"。

用法：
  python scripts/repo_triage.py                          # 本仓 open PR
  python scripts/repo_triage.py --repo bfxh/trit --limit 30
  python scripts/repo_triage.py --prs prs.json           # 离线：喂 gh 的 JSON（自测/复盘）
  python scripts/repo_triage.py --self-test              # 正例 + 逐项反证

设计口径（治的是"审核被 AI 的 PR 淹掉"和"只能干等"这两件）：
  · **分级复用 change_policy**：同一个 `.github/change_policy.json`，不复制规则 —— 两处判据迟早分叉。
  · 排序按"谁欠这个 PR 一个动作"：要人拍的 > 等 CI 的 > 作者自己能推的。
  · 每条给一行结论 + 一条**可直接执行的下一步**（`gh pr merge --auto` / `gh pr edit --add-label` / …），
    与 trit-vcs 的判决带命令同一条风格：别让读数停在"看看怎么办"。
  · 拿不到数据（未登录、PR 没文件清单）⇒ 大声 SKIP 并说明缺什么，**不静默当成"没有待办"**。
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load_policy_gate():
    """按路径加载 change_policy（同一套分级，两处判据不许分叉）。"""
    path = ROOT / "scripts" / "change_policy.py"
    spec = importlib.util.spec_from_file_location("change_policy", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def repo_from_url(url: str) -> str:
    """从 origin 地址认仓库名。scp 样式（`git@github.com:o/r.git`，本机 origin 就是这个）与
    https 样式都要认 —— 只按 `github.com/` 切会把 scp 样式整条漏掉，等于工具在自己机器上不可用。

    段首/段尾斜杠只由末尾那一次 `strip("/")` 兜（`git@github.com:/o/r` 这种变体也归它）：
    写两道兜底会让其中一道变成杀不死的等价变异。"""
    for marker in ("github.com:", "github.com/"):
        if marker in url:
            tail = url.split(marker, 1)[1]
            return tail.removesuffix(".git").strip("/")
    return ""


def skip_grading(repo: str, local_repo: str, policy_given: bool) -> bool:
    """分级表是**按仓**写的：拿本仓的表去判别仓 = 一眼看不出的假判定。

    显式给了 `--policy` 就算用户知道自己在做什么；没给仓库名（判本 checkout）也不跳过。"""
    if policy_given or not repo:
        return False
    return repo != (local_repo or "")


def origin_repo() -> str:
    done = subprocess.run(["git", "remote", "get-url", "origin"], cwd=ROOT,
                          capture_output=True, text=True, encoding="utf-8", errors="replace")
    return repo_from_url(done.stdout.strip())


def gh_json(args: list[str]) -> object:
    done = subprocess.run(["gh", *args], capture_output=True, text=True, encoding="utf-8", errors="replace")
    if done.returncode != 0:
        raise RuntimeError(f"gh {' '.join(args)} 失败：{done.stderr.strip()[:200]}")
    return json.loads(done.stdout or "null")


def fetch_prs(repo: str, limit: int) -> list[dict]:
    fields = "number,title,author,isDraft,state,url,baseRefName,headRefName,labels,files," \
             "additions,changedFiles,mergeable,mergeStateStatus,reviewDecision,updatedAt"
    raw = gh_json([
        "pr", "list", "--repo", repo, "--state", "open", "--limit", str(limit), "--json", fields,
    ])
    return list(raw or [])


def checks_line(repo: str, number: int) -> tuple[str, list[str]]:
    """返回 (状态摘要, 非绿清单)。取不到就标 unknown，不猜。"""
    done = subprocess.run(
        ["gh", "pr", "checks", str(number), "--repo", repo],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if done.returncode not in (0, 1):
        return "unknown", []
    out = (done.stdout or "").replace("\r\n", "\n")
    rows = [line.split("\t") for line in out.splitlines() if "\t" in line]
    pending = [r[0] for r in rows if len(r) > 1 and r[1] in ("pending", "queuing")]
    failing = [r[0] for r in rows if len(r) > 1 and r[1] in ("fail", "failure", "cancelled")]
    if failing:
        return f"红 {len(failing)}", failing
    if pending:
        return f"跑着 {len(pending)}", pending
    return "全绿" if rows else "无检查", []


def classify(gate, policy: dict, pr: dict) -> dict:
    files = [str(item.get("path", "")) for item in (pr.get("files") or [])]
    labels = [str((label or {}).get("name", "")) for label in (pr.get("labels") or [])]
    body = str(pr.get("body") or "")
    added = [""] * int(pr.get("additions") or 0)
    problems, notes = gate.decide(policy, files, added, [], [], labels, body)
    tier = gate.top_tier(policy, files) if files else "L0"
    state, detail = pr_state(pr)
    return {
        "number": pr.get("number"),
        "title": str(pr.get("title") or "")[:52],
        "author": str((pr.get("author") or {}).get("login") or "?"),
        "tier": tier,
        "files": len(files),
        "changed": int(pr.get("changedFiles") or 0),
        "state": state,
        "problems": problems,
        "notes": notes,
        "next": next_actions(pr, problems, labels, state, detail),
    }


def pr_state(pr: dict) -> tuple[str, list[str]]:
    if pr.get("isDraft"):
        return "draft", []
    merge_state = str(pr.get("mergeStateStatus") or "")
    if merge_state == "DIRTY" or str(pr.get("mergeable")) == "CONFLICTING":
        return "冲突", []
    if merge_state == "BEHIND":
        return "落后", []
    return "待处理", []


def next_actions(pr: dict, problems: list[str], labels: list[str], state: str, detail: list[str]) -> list[str]:
    number = pr.get("number")
    repo_owner = str(pr.get("url") or "").split("github.com/")[-1].split("/pull")[0]
    out: list[str] = []
    if problems:
        joined = chr(10).join(problems)
        if "approved:contract" in joined:
            out.append(f"要人拍板：看完改动再 gh pr edit {number} --repo {repo_owner} --add-label approved:contract")
        else:
            for problem in problems:
                out.append(f"挡着的是这条：{problem.splitlines()[0]}")
    elif state == "冲突":
        out.append(f"作者自己修：在分支上 merge base 后重推（不许 force 别人分支）→ gh pr view {number}")
    elif state == "落后":
        out.append(f"同步基线：git merge origin/main && git push（不 force）")
    elif state == "跑着":
        out.append(f"不用盯：gh pr merge {number} --repo {repo_owner} --squash --auto（绿了就合）")
    else:
        out.append(f"gh pr merge {number} --repo {repo_owner} --squash --auto")
    return out


def render(rows: list[dict], wide: bool) -> str:
    lines = [f"{'PR':>4} {'级':<3} {'文件':>4} {'状态':<6} {'作者':<14} 标题 / 下一步"]
    for row in rows:
        head = f"{row['number']:>4} {row['tier']:<3} {row['files']:>4} {row['state']:<6} {row['author']:<14} {row['title']}"
        lines.append(head)
        for problem in (row["problems"] if wide or row["tier"] == "L3" else []):
            lines.append(f"       · {problem.splitlines()[0]}")
        for action in row["next"]:
            lines.append(f"       → {action}")
    return "\n".join(lines)


def order(rows: list[dict]) -> list[dict]:
    rank = {"冲突": 0, "待处理": 1, "落后": 2, "跑着": 3, "draft": 4, "无检查": 3, "全绿": 5, "unknown": 1}

    def key(row: dict) -> tuple:
        needs_human = 0 if row["problems"] else 1
        return (needs_human, rank.get(row["state"], 3), -(row["number"] or 0))

    return sorted(rows, key=key)


def summarize(rows: list[dict]) -> str:
    human = sum(1 for row in rows if row["problems"])
    waiting = sum(1 for row in rows if row["state"] in ("跑着", "落后", "冲突"))
    green = sum(1 for row in rows if row["state"] == "全绿" and not row["problems"])
    l3 = sum(1 for row in rows if row["tier"] == "L3")
    return (
        f"合计 {len(rows)}：要你拍板 {human}（其中契约面 L3 {l3}）｜"
        f"机器/作者自己的事 {waiting}｜可直接合 {green}"
    )


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--repo", default="")
    parser.add_argument("--limit", type=int, default=40)
    parser.add_argument("--prs", default="")
    parser.add_argument("--policy", default="")
    parser.add_argument("--wide", action="store_true")
    parser.add_argument("--ci", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    args.policy_given = bool(args.policy)
    if not args.policy:
        args.policy = str(ROOT / ".github" / "change_policy.json")
    gate = load_policy_gate()
    policy = json.loads(pathlib.Path(args.policy).read_text(encoding="utf-8"))
    local_repo = origin_repo()
    if args.prs:
        prs = json.loads(pathlib.Path(args.prs).read_text(encoding="utf-8"))
    else:
        repo = args.repo or origin_repo()
        if not repo:
            print("FAIL 认不出仓库名（origin 不是 github 地址）⇒ 用 --repo owner/name")
            return 2
        try:
            prs = fetch_prs(repo, args.limit)
        except (RuntimeError, json.JSONDecodeError) as exc:
            print(f"FAIL 拿不到 PR 列表：{exc}")
            return 2
    graded = not skip_grading(args.repo, local_repo, args.policy_given)
    if not graded:
        print(f"SKIP 分级：本仓策略表管的是 `{local_repo or '本 checkout 的 origin'}`，"
              f"`{args.repo}` 没有它的 change_policy ⇒ 分级表不能串用（串了就是一眼看不出的假判定）。"
              "要判就 --policy <path>；下面只列状态/规模/下一步。")
        policy = dict(policy)
        policy.update({"tiers": [], "frozen_markers": [], "limits": {},
                       "test_evidence": {"watch": [], "test_paths": [], "escape": ""}})
    rows = [classify(gate, policy, pr) for pr in prs]
    if args.ci:
        repo = args.repo or "auto"
        for row, pr in zip(rows, prs):
            line, detail = checks_line(str(pr.get("url", "")).split("github.com/")[-1].rsplit("/pull", 1)[0]
                                       if repo == "auto" else repo, int(row["number"]))
            row["state"] = line
            row["running"] = detail
    if args.json:
        print(json.dumps({"rows": rows, "summary": summarize(rows)}, ensure_ascii=False, indent=1))
        return 0
    if not rows:
        print("没有 open PR（或全部已合）")
        return 0
    print(render(order(rows), args.wide))
    print(summarize(rows))
    return 0


def self_test() -> int:
    """离线自测：喂合成的 PR JSON，逐条钉住"谁欠这个 PR 一个动作"。"""
    total = 0
    failures: list[str] = []

    def check(label: str, actual, expected) -> None:
        nonlocal total
        total += 1
        if actual != expected:
            failures.append(f"FAIL {label}: 期望 {expected!r}，实际 {actual!r}")

    gate = load_policy_gate()
    policy = {
        "approve_label": "approved:contract",
        "big_diff_label": "approved:big-diff",
        "tiers": [
            {"tier": "L3", "paths": ["src/bundle.rs"]},
            {"tier": "L2", "paths": ["src/**", "tests/**"]},
            {"tier": "L1", "paths": [".github/**", "scripts/**"]},
        ],
        "frozen_markers": [],
        "limits": {"max_l2_files": 3, "max_added_lines": 5000},
        "test_evidence": {"watch": ["src/"], "test_paths": ["tests/"], "escape": "NO-TEST-NEEDED:"},
    }

    def pr(**kw):
        base = {
            "number": 1,
            "title": "t",
            "author": {"login": "bot"},
            "url": "https://github.com/o/r/pull/1",
            "isDraft": False,
            "mergeable": "MERGEABLE",
            "mergeStateStatus": "CLEAN",
            "labels": [],
            "files": [],
            "changedFiles": 1,
            "additions": 5,
            "body": "",
        }
        base.update(kw)
        return base

    ci_only = classify(gate, policy, pr(files=[{"path": ".github/workflows/ci.yml"}]))
    check("只改 CI ⇒ 无问题", ci_only["problems"], [])
    check("只改 CI ⇒ 级是 L1", ci_only["tier"], "L1")
    check("只改 CI 的下一步是自动合", "gh pr merge" in ci_only["next"][0], True)

    contract = classify(gate, policy, pr(files=[{"path": "src/bundle.rs"}, {"path": "tests/x.rs"}]))
    check("碰契约面 ⇒ 列问题", len(contract["problems"]), 1)
    check("碰契约面 ⇒ 让人加标签", "--add-label approved:contract" in contract["next"][0], True)

    approved = classify(
        gate,
        policy,
        pr(files=[{"path": "src/bundle.rs"}, {"path": "tests/x.rs"}], labels=[{"name": "approved:contract"}]),
    )
    check("人批后不再是问题", approved["problems"], [])
    check("人批后的下一步是自动合", "--auto" in approved["next"][0], True)

    no_test = classify(gate, policy, pr(files=[{"path": "src/store.rs"}]))
    check("改产品代码不带测试 ⇒ 问题", len(no_test["problems"]), 1)

    conflict = classify(gate, policy, pr(mergeStateStatus="DIRTY", files=[{"path": "scripts/x.py"}]))
    check("冲突 PR 要作者自己修", "作者自己修" in conflict["next"][0], True)

    behind = classify(gate, policy, pr(mergeStateStatus="BEHIND", files=[{"path": "README.md"}]))
    check("落后的下一步不 force", "不 force" in behind["next"][0], True)

    rows = [
        {"number": 1, "problems": ["x"], "tier": "L3", "state": "待处理", "title": "", "author": "",
         "files": 1, "next": ["要人拍板"]},
        {"number": 2, "problems": [], "tier": "L1", "state": "全绿", "title": "", "author": "",
         "files": 1, "next": ["gh pr merge 2 --auto"]},
        {"number": 3, "problems": [], "tier": "L2", "state": "跑着", "title": "", "author": "",
         "files": 1, "next": ["不用盯"]},
        {"number": 4, "problems": ["挡着一条"], "tier": "L2", "state": "全绿", "title": "", "author": "",
         "files": 1, "next": ["要人拍板"]},
        {"number": 5, "problems": [], "tier": "L1", "state": "冲突", "title": "", "author": "",
         "files": 1, "next": ["作者自己修"]},
    ]
    ordered = order(rows)
    check("排序逐位固定：欠人看的先于机器的事", [row["number"] for row in ordered], [1, 4, 5, 3, 2])
    check("要人拍板的一律排在最前（哪怕它 CI 全绿）",
          [bool(row["problems"]) for row in ordered], [True, True, False, False, False])
    text = summarize(ordered)
    check("汇总里三个数都对", ("要你拍板 2" in text, "可直接合 1" in text, "自己的事 2" in text), (True, True, True))
    check("表格不为空", render(ordered, True).count(chr(10)) >= 7, True)

    # 五、origin 样式：本机 origin 是 scp 写法，认不出就等于工具在自己机器上不能用
    check("scp 样式认得出", repo_from_url("git@github.com:bfxh/trit-vcs.git"), "bfxh/trit-vcs")
    check("https 样式认得出", repo_from_url("https://github.com/bfxh/trit-vcs.git"), "bfxh/trit-vcs")
    check("冒号后接斜杠的 scp 变体要切掉段首斜杠", repo_from_url("git@github.com:/bfxh/trit-vcs.git"), "bfxh/trit-vcs")
    check("ssh:// 样式认得出", repo_from_url("ssh://git@github.com/bfxh/trit-vcs.git"), "bfxh/trit-vcs")
    check("结尾多一个斜杠也要切掉", repo_from_url("https://github.com/bfxh/trit-vcs/"), "bfxh/trit-vcs")
    check("非 github 地址不硬猜", repo_from_url("file:///E:/KF/trit-parity"), "")

    # 六、分级表不许串仓用（拿 A 仓的规则判 B 仓 = 一眼看不出的假判定）
    check("判别仓且没给策略 ⇒ 跳过分级", skip_grading("bfxh/trit", "bfxh/trit-vcs", False), True)
    check("判本仓 ⇒ 不跳过", skip_grading("bfxh/trit-vcs", "bfxh/trit-vcs", False), False)
    check("没给仓库名（判本 checkout）⇒ 不跳过", skip_grading("", "bfxh/trit-vcs", False), False)
    check("显式给了策略 ⇒ 视为知情，不跳过", skip_grading("bfxh/trit", "bfxh/trit-vcs", True), False)
    check("认不出 origin 时也不硬分级", skip_grading("bfxh/trit", "", False), True)

    if failures:
        for line in failures:
            print(line)
        print(f"repo-triage self-test: {total - len(failures)}/{total} passed")
        return 1
    print(f"repo-triage self-test: {total}/{total} passed")
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv[1:]:
        sys.exit(self_test())
    sys.exit(main(sys.argv[1:]))
