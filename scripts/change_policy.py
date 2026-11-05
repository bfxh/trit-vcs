#!/usr/bin/env python3
"""改动面分级门：把「哪些能自己改、哪些必须人拍板」变成机器判定。

用法：
  python scripts/change_policy.py                      # 用 origin/main..HEAD 的 diff 判当前分支
  python scripts/change_policy.py --base <sha>         # 换基线
  python scripts/change_policy.py --files a.rs b.rs    # 离线只判一份清单（自测/预演）
  python scripts/change_policy.py --event "$GITHUB_EVENT_PATH"   # CI：从 PR 事件读标签与正文
  python scripts/change_policy.py --self-test          # 正例 + 逐项反证

为什么要这道门（维护者原话级别的痛点）：智能体一天能提十几个 PR，审核方还得逐个点开看
"它到底动了软件本身，还是只动了 CI/CD"。这句话不该由人读 diff 来判断 —— 它是一张表：

  · **L0 文档 / L1 CI 与门脚本**：鼓励 AI 自己动（改 CI/CD 是低门，就该便宜）。
  · **L2 产品代码与测试**：可以改，但必须带证据 —— 改了 `src/` 就得同时带测试改动，
    否则判红（逃生口 `NO-TEST-NEEDED:` 写在正文里，必须给理由）。
  · **L3 契约面**：包格式、哈希链字段、提交对象 schema、依赖正本 pin、**变异台账的删除** ——
    需要标签 `approved:contract`（人批的唯一凭证），没有就判红并列出要人看的清单。

冻结契约不靠"别改"的口头约定：策略里列出**必须逐字存在的行**（如 `pub const SCHEMA: u32 = 1;`）。
它们消失 ⇒ 一律要人批；有标签也大声打印"批准丢掉了哪几行"，让签字的人看得见自己签了什么。
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
POLICY = ROOT / ".github" / "change_policy.json"


def load_policy(path: pathlib.Path) -> dict:
    """策略读不出来就判红 —— "不知道规则"不等于"没有规则"。"""
    if not path.is_file():
        raise SystemExit(f"NO POLICY：找不到 {path} ⇒ 判红（没有分级表就等于允许一切）")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data.get("tiers"), list) or not data.get("frozen_markers"):
        raise SystemExit(f"POLICY SHAPE：{path} 缺 tiers 或 frozen_markers ⇒ 判红")
    return data


def matches(path: str, pattern: str) -> bool:
    """`**` 与 `*` 都按"跨目录的通配"处理（fnmatch 的语义）：`src/**` 要能盖到 `src/bin/x/main.rs`。"""
    return fnmatch.fnmatch(path, pattern)


def tier_of(policy: dict, path: str) -> str:
    for tier in policy["tiers"]:
        if any(matches(path, pattern) for pattern in tier["paths"]):
            return str(tier["tier"])
    return "L1"


def top_tier(policy: dict, files: list[str]) -> str:
    order = [str(t["tier"]) for t in policy["tiers"]]
    ranks = {name: index for index, name in enumerate(order)}
    worst = "L9"
    for path in files:
        current = tier_of(policy, path)
        if ranks.get(current, 99) < ranks.get(worst, 99):
            worst = current
    return worst if worst != "L9" else "L0"


def diff_of(root: pathlib.Path, base: str) -> tuple[list[str], str]:
    """拿改动清单与完整 diff（CI 里 base 由 workflow 传进来）。"""

    def git(*args: str) -> str:
        done = subprocess.run(
            ["git", *args], cwd=root, capture_output=True, text=True, encoding="utf-8", errors="replace"
        )
        if done.returncode != 0:
            raise SystemExit(f"GIT FAILED：git {' '.join(args)} ⇒ {done.stderr.strip()[:160]}")
        return done.stdout.replace("\r\n", "\n")

    files = [line for line in git("diff", "--name-only", f"{base}...HEAD").splitlines() if line.strip()]
    return files, git("diff", f"{base}...HEAD")


def removed_lines(diff: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    current = ""
    for line in diff.splitlines():
        if line.startswith("diff --git "):
            current = line.split(" b/")[-1].strip()
        elif line.startswith("-") and not line.startswith("---"):
            out.setdefault(current, []).append(line[1:].strip())
    return out


def added_lines(diff: str) -> list[str]:
    return [
        line[1:].strip()
        for line in diff.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    ]


def registry_entries(text: str) -> int:
    """变异登记条目数：按 `"name":` 计数（读不成 JSON 也要数得出，防止"格式一变就看不见删除"）。"""
    try:
        data = json.loads(text)
        if isinstance(data, list):
            return len(data)
    except (json.JSONDecodeError, ValueError):
        pass
    return text.count('"name":')


def entry_drops(root: pathlib.Path, base: str, files: list[str]) -> list[str]:
    """台账被删条目 = 门的账本被动过，一律要人批。"""
    drops: list[str] = []
    for path in files:
        if not path.startswith("scripts/mutants/") or not path.endswith(".json"):
            continue
        head = root / path
        after = registry_entries(head.read_text(encoding="utf-8")) if head.is_file() else 0
        try:
            before_text = subprocess.run(
                ["git", "show", f"{base}:{path}"],
                cwd=root,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            ).stdout
        except OSError:
            before_text = ""
        before = registry_entries(before_text) if before_text else 0
        if before and after < before:
            drops.append(f"{path}：登记条目 {before} ⇒ {after}（少了 {before - after} 条）")
    return drops


def missing_markers(root: pathlib.Path, policy: dict, files: list[str]) -> list[str]:
    """冻结行：只在被改过的文件上查（没动的文件不由本次负责）。"""
    gone: list[str] = []
    changed = set(files)
    for item in policy["frozen_markers"]:
        path = str(item["path"])
        if path not in changed:
            continue
        target = root / path
        text = target.read_text(encoding="utf-8") if target.is_file() else ""
        for marker in item["must_contain"]:
            if marker not in text:
                gone.append(f"{path} 里这行没了：{marker}　（{item['why']}）")
    return gone


def decide(
    policy: dict,
    files: list[str],
    added: list[str],
    gone_markers: list[str],
    drops: list[str],
    labels: list[str],
    body: str,
) -> tuple[list[str], list[str]]:
    problems: list[str] = []
    notes: list[str] = []
    tiers = {path: tier_of(policy, path) for path in files}
    top = top_tier(policy, files)
    limits = policy.get("limits") or {}
    approve = str(policy.get("approve_label") or "approved:contract")
    big_ok = str(policy.get("big_diff_label") or "approved:big-diff")

    if not files:
        notes.append("没有改动文件 ⇒ 无事可判")
        return problems, notes

    l2 = sorted(p for p, tier in tiers.items() if tier == "L2")
    l3 = sorted(p for p, tier in tiers.items() if tier == "L3")
    notes.append(f"改动面：{len(files)} 个文件，最高级 {top}")

    contract_hits = list(l3) + list(gone_markers) + list(drops)
    if contract_hits:
        if approve in labels:
            notes.append(f"已有人批（{approve}）：")
            notes.extend(f"  · 契约面 {path}" for path in l3)
            notes.extend(f"  · {line}" for line in gone_markers)
            notes.extend(f"  · 台账 {line}" for line in drops)
        else:
            problems.append(
                chr(10).join(
                    [f"L3 契约面被动到，需要标签 {approve}（AI 不许自己拍板）："]
                    + [f"  · {path}" for path in l3]
                    + [f"  · {line}" for line in gone_markers]
                    + [f"  · 台账 {line}" for line in drops]
                )
            )

    evidence = policy.get("test_evidence") or {}
    watch = tuple(evidence.get("watch") or [])
    touched_src = any(p.startswith(watch) for p in l2) if watch else False
    if touched_src:
        test_paths = tuple(evidence.get("test_paths") or ["tests/"])
        has_test_file = any(p.startswith(test_paths) for p in files)
        has_new_test = any("#[test]" in line or "#[tokio::test]" in line for line in added)
        escape = str(evidence.get("escape") or "NO-TEST-NEEDED:")
        if not (has_test_file or has_new_test or escape in body):
            problems.append(
                "改了产品代码却没带测试改动：动 tests/** 或新增 #[test]，"
                f"或在正文写明「{escape} <理由>」（三种都行，什么都不写不行）"
            )
        elif escape in body and not (has_test_file or has_new_test):
            notes.append(f"按逃生口放行（正文写了 {escape}）—— 维护者请核理由")

    max_files = int(limits.get("max_l2_files") or 0)
    max_lines = int(limits.get("max_added_lines") or 0)
    if max_files and len(l2) > max_files and big_ok not in labels:
        problems.append(f"单 PR 动 {len(l2)} 个 L2 文件（上限 {max_files}）⇒ 拆小一点；确要一次过加标签 {big_ok}")
    if max_lines and len(added) > max_lines and big_ok not in labels:
        problems.append(f"新增 {len(added)} 行（上限 {max_lines}）⇒ 拆小一点；确要一次过加标签 {big_ok}")
    return problems, notes


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--base", default="origin/main")
    parser.add_argument("--policy", default=str(POLICY))
    parser.add_argument("--root", default=str(ROOT))
    parser.add_argument("--files", nargs="*", default=[])
    parser.add_argument("--labels", default="")
    parser.add_argument("--event", default="")
    parser.add_argument("--body-file", default="")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--explain", action="store_true")
    args = parser.parse_args(argv)

    root = pathlib.Path(args.root)
    policy = load_policy(pathlib.Path(args.policy))
    if args.explain:
        for tier in policy["tiers"]:
            print(f"{tier['tier']}：{', '.join(tier['paths'])}\n    {tier['why']}")
        for item in policy["frozen_markers"]:
            print(f"冻结：{item['path']} ⇒ {item['why']}")
        return 0

    labels = [label.strip() for label in args.labels.split(",") if label.strip()]
    body = ""
    if args.event:
        event = json.loads(pathlib.Path(args.event).read_text(encoding="utf-8"))
        pull = event.get("pull_request") or {}
        labels += [str((label or {}).get("name", "")) for label in pull.get("labels", [])]
        body = str(pull.get("body") or "")
    if args.body_file:
        body += pathlib.Path(args.body_file).read_text(encoding="utf-8", errors="replace")

    files = list(args.files)
    added: list[str] = []
    drops: list[str] = []
    if not files:
        files, diff = diff_of(root, args.base)
        added = added_lines(diff)
        drops = entry_drops(root, args.base, files)
        gone = missing_markers(root, policy, files)
    else:
        gone = missing_markers(root, policy, files)

    problems, notes = decide(policy, files, added, gone, drops, labels, body)
    if args.json:
        print(json.dumps({"problems": problems, "notes": notes}, ensure_ascii=False, indent=1))
    else:
        for line in notes:
            print(line)
        for line in problems:
            print(f"FAIL {line}" if not line.startswith("  ") else f"FAIL {line}")
    if problems:
        print(f"⇒ 判红 {len(problems)} 条：L3 要人拍板就加标签 {policy.get('approve_label')}，"
              "别无选择时把 PR 拆小。")
        return 1
    print("OK 改动面在授权范围内")
    return 0


def self_test() -> int:
    """正例 + 逐项反证：每条规则都得能被单独踩红，否则它只是文档。"""
    total = 0
    failures: list[str] = []

    def check(label: str, actual, expected) -> None:
        nonlocal total
        total += 1
        if actual != expected:
            failures.append(f"FAIL {label}: 期望 {expected!r}，实际 {actual!r}")

    policy = {
        "approve_label": "approved:contract",
        "big_diff_label": "approved:big-diff",
        "tiers": [
            {"tier": "L3", "paths": ["src/bundle.rs"]},
            {"tier": "L2", "paths": ["src/**", "tests/**", "Cargo.toml"]},
            {"tier": "L1", "paths": [".github/**", "scripts/**"]},
            {"tier": "L0", "paths": ["**/*.md"]},
        ],
        "frozen_markers": [
            {"path": "src/bundle.rs", "why": "包格式", "must_contain": ['pub const SCHEMA: u32 = 1;']}
        ],
        "limits": {"max_l2_files": 2, "max_added_lines": 3},
        "test_evidence": {"watch": ["src/"], "test_paths": ["tests/"], "escape": "NO-TEST-NEEDED:"},
    }

    def run(files: list[str], *, added: list[str] | None = None, gone: list[str] | None = None,
            drops: list[str] | None = None, labels: list[str] | None = None, body: str = "") -> tuple[list[str], list[str]]:
        return decide(policy, files, added or [], gone or [], drops or [], labels or [], body)

    # 一、分级判定
    check("L1 只是改 CI ⇒ 放行", run([".github/workflows/ci.yml"])[0], [])
    check("文档单独提 ⇒ 放行", run(["README.md"])[0], [])
    check("改产品代码不带测试 ⇒ 判红", len(run(["src/store.rs"])[0]), 1)
    check("改了 src 又动 tests ⇒ 放行", run(["src/store.rs", "tests/store_cli.rs"])[0], [])
    check("新增 #[test] 也算测试证据", run(["src/store.rs"], added=["    #[test]"])[0], [])
    check("逃生口写明理由 ⇒ 放行但要核", run(["src/store.rs"], body="NO-TEST-NEEDED: 纯改名")[0], [])
    check("逃生口放行也要留下可见记录", any("逃生口" in line for line in run(["src/store.rs"], body="NO-TEST-NEEDED: 纯改名")[1]), True)
    check("最高级取最严的一档", top_tier(policy, ["README.md", "src/bundle.rs"]), "L3")
    check("嵌套路径要归到 L2", tier_of(policy, "src/bin/trit-vcs/main.rs"), "L2")
    check("台账按路径只到 L1（加条目不该卡人批）", tier_of(policy, "scripts/mutants/trit-vcs.json"), "L1")

    # 二、契约与账本
    blocked = run(["src/repo.rs", "tests/x.rs"], gone=["src/bundle.rs 里这行没了：pub const SCHEMA: u32 = 1;"])
    check("冻结行消失 ⇒ 判红", len(blocked[0]), 1)
    approved = run(
        ["src/repo.rs", "tests/x.rs"],
        gone=["src/bundle.rs 里这行没了：pub const SCHEMA: u32 = 1;"],
        labels=["approved:contract"],
    )
    check("人批后放行", approved[0], [])
    check("人批也要打印签掉了什么", "冻结" in " ".join(approved[1]) or "没了" in " ".join(approved[1]), True)
    check("删登记条目 ⇒ 判红", len(run(["scripts/mutants/trit-vcs.json"], drops=["台账少 3 条"])[0]), 1)
    check("加条目不算契约面（否则每片都卡人批）", run(["scripts/mutants/trit-vcs.json"], drops=[])[0], [])
    check("删条目的人批后放行", run(["scripts/mutants/trit-vcs.json"], drops=["台账少 3 条"],
                          labels=["approved:contract"])[0], [])

    # 三、规模上限（审核负担的直接来源）
    check("L2 文件数超限 ⇒ 判红", len(run(["src/a.rs", "src/b.rs", "src/c.rs", "tests/t.rs"])[0]), 1)
    check("加批注标签可放行规模", run(["src/a.rs", "src/b.rs", "src/c.rs", "tests/t.rs"], labels=["approved:big-diff"])[0], [])
    check("新增行数超限 ⇒ 判红", len(run(["src/a.rs", "tests/t.rs"], added=["x"] * 4)[0]), 1)

    # 四、diff 解析（判错这里整条门就形同虚设）
    sample = "\n".join(
        [
            "diff --git a/src/a.rs b/src/a.rs",
            "--- a/src/a.rs",
            "+++ b/src/a.rs",
            "-pub const SCHEMA: u32 = 1;",
            "+// 改了",
            "diff --git a/tests/b.rs b/tests/b.rs",
            "--- a/tests/b.rs",
            "+++ b/tests/b.rs",
            "+#[test]",
        ]
    )
    check("改动清单解析出来", removed_lines(sample).get("src/a.rs"), ["pub const SCHEMA: u32 = 1;"])
    check("新增行也算对", added_lines(sample), ["// 改了", "#[test]"])
    check("台账按 JSON 数条目", registry_entries('[{"name":"a"},{"name":"b"}]'), 2)
    check("JSON 坏了也要数得出（防改格式=看不见删除）", registry_entries('[{"name":"a"}, 坏'), 1)
    check("空清单无事可判", "没有改动文件" in run([])[1][0], True)

    # 五、真开文件的三条：策略形状、冻结行、以及"没匹配到任何档"的保守落点
    with tempfile.TemporaryDirectory() as tmp:
        box = pathlib.Path(tmp)
        target = box / "src" / "bundle.rs"
        target.parent.mkdir(parents=True)
        target.write_text("pub const SCHEMA: u32 = 1;" + chr(10), encoding="utf-8")
        check("冻结行还在 ⇒ 不算丢", missing_markers(box, policy, ["src/bundle.rs"]), [])
        target.write_text("// 被改没了" + chr(10), encoding="utf-8")
        check("冻结行没了 ⇒ 点名是哪行", len(missing_markers(box, policy, ["src/bundle.rs"])), 1)
        broken = box / "policy.json"
        broken.write_text('{"tiers": []}', encoding="utf-8")
        try:
            load_policy(broken)
            shape = "没报错"
        except SystemExit as exc:
            shape = str(exc)
        check("策略形状不对 ⇒ 判红（不知道规则不等于没有规则）", "判红" in shape, True)
    check("没匹配到任何档 ⇒ 保守落 L1（不是免检）", tier_of(policy, "LICENSE-MIT"), "L1")

    if failures:
        for line in failures:
            print(line)
        print(f"change-policy self-test: {total - len(failures)}/{total} passed")
        return 1
    print(f"change-policy self-test: {total}/{total} passed")
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv[1:]:
        sys.exit(self_test())
    sys.exit(main(sys.argv[1:]))
