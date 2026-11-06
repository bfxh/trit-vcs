# Changelog

本文件遵循 Keep a Changelog；日期用 ISO 8601。
读数与口径记在这里，机器状态（盘符路径、临时目录）不记 —— `scripts/docs_hygiene.py` 会拦。

## [Unreleased]

### Added
- `trit-vcs handoff <提交id> --out <包>` 产出自带 `manifest.json` 的交接包：
  commit/tree/parents、intent、claims、冲突面、diff、改动文件的文件映射与内容；
  `trit-vcs handoff-verify <包>` 逐项重算，缺件/篡改/悬空引用一律判红。
  新增 `--bundle` 产出**单文件**形态（`TVHP` 容器，magic 与传输包 `TVBD` 故意不同 ⇒
  `import` 不会误收交接包、`handoff-verify` 不会误收传输包）；`handoff-verify` 认目录或单文件，
  两种形态共用同一套语义判据（包 id / diff / 冲突面 / 悬空），单文件不是"另一套校验"。
  容器收端逐块重算 BLAKE3，坏 magic / 坏 schema / 截断 / 部件数不符 / 载荷被改一律判红。
  测试 `tests/handoff_cli.rs` 12 条 + `src/handoff_bundle.rs` 7 条单测
  （含"删掉包里任意一个部件 ⇒ verify 必红"、语义篡改 diff、悬空引用、根提交无父、
  目录包与单文件包 package_id 一致、TVBD/TVHP 互不误收）；登记 9 条变异，本机 9/9 全抓。
- `intent.accept` 变成可机器验证的判据，**默认关**：`preflight` / `admit --verify-accept --claims FILE`
  才执行；执行前必须 `gate::check` 判 `Allowed`（只跑在效认领范围内的改动）。
  命令按 argv 切分，含 shell 元字符（管道、重定向、`$`、`;`、`&`、反引号、括号）直接拒 ——
  `sh -c` 会把提交内容变成任意脚本；
  单条超时默认 60 s，超时杀进程（Windows `taskkill /T`）且算**没通过**；输出留 2 KB 摘要并给常见 token 前缀打码；
  跑之前后各开一次新句柄体检，仓库被写坏（对象/事件/HEAD 变了）⇒ `accept_mutated_repo`。
  `src/accept.rs` 6 条单测 + `tests/accept_cli.rs` 3 条端到端（含"没给认领表 / 认领没覆盖 / 含元字符 ⇒
  一次都没执行"的 canary 证明，用会落盘的 `init --repo` 当探针而不是读文案）；登记 7 条变异，本机 7/7 全抓。
- CLI 层自己的失败也带上档位与下一步：`cli_usage` / `cli_local_io` / `cli_claims_unreadable` /
  `cli_path_missing` / `cli_path_outside_repo` / `cli_index_bad_tree` / `cli_techmap_unreadable` 七档；
  库层错误由 `CliFail::Repo` **原样透传**（档位与下一步仍归 `src/remediation` 那一份决定，CLI 不重讲规则）。
  新测试 `tests/cli_fail_kinds.rs` 钉的是形状而不是条数：FAIL 行必须以 `（档位）` 收尾、且至少一条 `下一步 1.`；
  登记 8 条变异（本机复跑 8/8 全抓、存活 0）。
- MCP 工具面的失败也带档位与下一步：`McpFail` 有 `mcp_bad_args` / `mcp_unknown_tool` / `mcp_path_missing` /
  `mcp_path_outside_repo` / `mcp_local_io` / `mcp_techmap_unreadable` / `mcp_witness_shape` 七档，
  库层错误经 `from_error` **原样透传**；`_meta.kind` 与 `_meta.next_steps` 可分支，正文里也带编号命令
  （只看 `content` 的客户端同样能用）。工具面里 `.map_err(|err| err.to_string())` 清零：
  13 处库层错误透传、7 处本地 IO、14 个必填参数统一走 `need()`。
  新测试 `tests/mcp_fail_kinds.rs`（7 条失败形状 + 正例反证），登记 6 条变异，本机 6/6 全抓。
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
