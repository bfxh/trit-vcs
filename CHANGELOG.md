# Changelog

本文件遵循 Keep a Changelog；日期用 ISO 8601。
读数与口径记在这里，机器状态（盘符路径、临时目录）不记 —— `scripts/docs_hygiene.py` 会拦。

## [Unreleased]

### Added
- 旧仓的四道门搬进本仓并改成认"一 crate 在根"的布局：`module_budget.py`（800 行上帝模块棘轮）、
  `test_surface.py`（自测面防空转）、`docs_hygiene.py`（CHANGELOG 形状 + 盘符路径棘轮）、
  `ci_integrity.py`（workflow ↔ `required-checks.txt` ↔ GitHub 保护规则三方对账）。
  四道门共登记 32 条变异；搬运那轮 gates 面全量 101 条 ⇒ 99 断言抓住 + 2 崩溃抓住、存活 0。
  随后给 `ci_integrity`（+3）与 `repo_triage`（+2）补了认仓的刀，两道面复跑 6/6、8/8 全抓（gates 面现共 106 条）。
- 治理面三件套（PR #3，squash `1ba95c3`）：`scripts/change_policy.py` 改动分级门（L0–L3 + 冻结契约行 +
  台账只防改薄）、`scripts/repo_triage.py` PR 分诊台、CI 并发取消 + 变异门按面并行。
  自测 28/28 与 22/22；两道新门登记 17 条变异，复跑全抓。

### Changed
- `ci_integrity.py` 不再把默认仓写死成 `bfxh/trit`：搬仓后它拿别人仓的保护规则比对完照样打印"通过"，
  这是最坏的一种绿（判据跑在错对象上）。现在认不出 origin、或读不到保护 ⇒ rc=2 出声；
  认仓只留 `repo_triage.py` 一份实现，`--self-test` 从 14 条涨到 27 条；顺带收掉 `repo_from_url`
  里两道斜杠兜底（留一道 —— 留两道时另一道就是杀不死的等价变异，实测 SURVIVED 过）。
- 变异门目标采集从 workflow 内联抽成 `scripts/mutation_targets.sh`，并加"改了库面却零目标 ⇒ 判红"的防空跑一步。

## [0.12.0] - 2026-11-06

### Added
- 从单体仓 `bfxh/trit` 的 `crates/trit-vcs` 用 `git subtree split` 带 12 笔历史迁出为独立仓；
  `trit-core` / `trit-orch` 按 rev `2400fb9` git pin，不复制。
- 判决带命令扩到六张面（PR #2，squash `2bd67e2`）：`StoreError` 6 / `BundleError` 7 / `WorktreeError` 4 /
  `CentralError` 3 / `GitError` 6 / `MergeError` 2 各给 kind 与可执行下一步；`Remediable` + `explain_any`
  统一出口；CLI 22 处 typed 的裸 `fail(err.to_string())` 接上。登记 113 条变异，本地全量复跑
  断言抓住 112 + 声明死循环 1、存活 0。
- `crates/trit-vcs/README.md`（迁出后即本仓 README）：逐维度认账 —— 存储三形状 1.06×/2.29×/1.02× **认输**，
  部分拉取 5.05%、重复拉 0 B、伪冲突 0、预检 4.8 ms 写盘 0 对象，并列出六条"明确没做的"。

## [0.12.0-before-split] - 2026-11-01 … 2026-11-05

在 `bfxh/trit` 里落地的部分：M1 内容寻址 + CDC + 哈希链 + 认领门（#269）、status stat 缓存 + Intent（#275）、
witness v0（#273）、M3 传输 v0（#277）、M4 合并 v0（#280）、M5 查询 v0（#282）、M6 Git 双向桥 v0（#284）、
MCP 工具面 v0（#286）、稀疏检出 + 范围内 status（#288）、中央仓 + 按需物化（#292）、写前预检（#295）。
完整历史随迁出保留在本仓 git log 里。
