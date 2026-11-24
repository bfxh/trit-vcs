# Changelog

本文件遵循 Keep a Changelog；日期用 ISO 8601。
读数与口径记在这里，机器状态（盘符路径、临时目录）不记 —— `scripts/docs_hygiene.py` 会拦。

## [Unreleased]

### Added
- 审计 L2 首批（`docs/AUDIT-STRENGTH.md`）：`trit-vcs audit status/verify/reconcile` 把哈希链日志对账到
  当前 `HEAD`/refs/索引/策略/认领账本/对象闭包，`audit log/show` 可按事件类型与序号查；
  `--json` 输出 `ok/level/chain_ok/events/issues`，有 issue 时退出码非零。新增 `Repo::state_digest`
  （HEAD + refs + index + policy 原始字节 + claims 原始字节，canonical JSON 后 BLAKE3，不把 journal
  算进去避免循环自证）；`stage/ref/adopt/commit/claim_*` 事件带 `state_after`，`adopt/claim` 补
  `path_list`。`Journal::append` 加 `journal.lock` 单写者锁，拿锁后按文件长度重读，8 线程 × 20 条
  并发测试不丢事件/不重 seq；Windows 上锁文件和日志的瞬时 `PermissionDenied` 走退避重试，不把
  杀毒扫描误判成日志损坏。提交落 `ClaimSet` 不可变快照（`Commit.claim_set`），`verify` 校验对象
  摘要；`accept` 执行落 `AcceptReceipt` 对象 + `accept` 事件，记录每条判据 exit/超时/输出摘要；
  `publish/pull` 也进链（publish 记 previous/forced）。`Repo::open_for_audit` 让坏 journal 也能先出结构化
  `journal_broken` 报告，而不是在打开仓库时只剩一句 IO 错误。关键状态变更改为写前协议：
  `Repo::begin_operation` 在 `stage/commit/set_ref/adopt/claim_*/policy` 动手前落 `op_begin`（含 `state_before`），
  `finish_operation` 落 `op_result`（含 `status`/`state_after`）；崩在中间会留下 `op_open` 或
  `op_state_gap`。提交门拒绝也落 `gate` 事件（action/decision/reason/session/state_before/state_after），拒绝不再无账。
  `trit-vcs policy [--json]` 查看策略，`policy set --owner ... [--require-witness] [--require-intent]` 整份替换并落
  `policy` 事件（session/开关/policy_hash/state_before/state_after）；手工改 `policy.json` 仍会被
  `state_drift` 或下一次 `op_state_gap` 抓出来。`merge` CLI 与 MCP 改走 `merge_audited`：合并只写对象库、
  不改状态，但同样落 `op_begin` + `merge`（输入、树、冲突数、state_after）+ `op_result`；有冲突是完成结果，
  不是错误，审计不因此判红。`serve` 的鉴权失败也落 `auth` 事件（decision/reason/method/path/status，
  state_before/state_after 同值；不记 token 与请求头）；只记带 `Authorization` 的失败和 `POST /v1/publish`
  的失败，裸健康探针不进账，避免扫描器刷爆日志。`auth` 事件由审计做字段/401/状态检查。
  服务端 publish 被业务规则拒绝（非快进、对象流坏、ref 非法等）落 `deny` 事件：
  action/decision/reason/message/detail 与同值 state_before/state_after，仍不记 token；
  进入仓库锁之前的请求形状错误（缺 ref、缺 X-Trit-Tip、坏 tip、空/超大 body）也先落
  `deny`（reason=missing_ref/missing_tip/bad_tip/bad_body_size，带 status/length），
  不再“400/413 先回、账本没影”。服务端 pull 的缺 ref/未知 ref/清单不完整也落 `deny`
  （reason=missing_ref/unknown_ref/…，带 ref/prefix/status）；审计新增 `deny_bad` / `deny_no_state`。客户端 `pull` 在应用回执时被拒（脏工作树、
  非快进、清单/历史完整性不通过）也落本地 `deny`，`reason` 用 `worktree_dirty` /
  `non_fast_forward` 等，事件只记 ref/prefix（拿到回执后加 tip），不落路径正文。全量 pull 还会在发请求前
  先扫工作树，脏就不下载对象，避免“拒绝已记账、对象已入中央库”的写前缺口。
  新增受审计信任表 v0：`trit-vcs key add/revoke/list` 读写 `.tritvcs/keys.json`，`add`/`revoke`
  走 `op_begin/op_result` 并落 `key` 事件（action/key_id/principal/role/session/keystore_hash/
  state_before/state_after）；重复 key、未知 key、已吊销 key 明确拒绝，不静默覆盖。`state_digest`
  在 `keys.json` 存在时纳入其原始字节：首次 add 的 state_before 是“文件不存在”的摘要，
  state_after 是“文件已存在”的摘要；之后手改/删 keyset 会被 `state_drift` 抓出。当前只做
  key 元数据信任（重复/未知/已吊销 key 拒绝）；信任表本身不做签名，验签由下面的签名层负责。
  新增 Ed25519 提交签名：`key init --out <私钥文件>` 生成 `trit-key-v1` JSON，`key add --key-file`
  只把公钥和 `ed25519:<BLAKE3(公钥)>` 指纹写进信任表；`commit --sign-key FILE` 对提交 canonical 对象字节
  做 `verify_strict` 可验的签名，落 `signature` 事件（commit/key_id/algorithm/signature/signed_at_ms/
  state_before/state_after），签名是 sidecar，不改变提交 id，也不改提交事件。`audit` 新增
  `signature_bad` / `signature_commit_missing` / `signer_untrusted` / `signer_revoked` / `signature_invalid`；
  吊销按 `signed_at_ms` 判断，吊销前的历史签名仍可验。私钥不进 argv、不进日志、不进仓库事件。
  测试：`src/audit.rs` / `src/audit/extra_tests.rs` 15 条、`tests/audit_cli.rs` 5 条、`tests/policy_cli.rs` 1 条、`tests/merge_cli.rs` 2 条、`tests/key_cli.rs` 3 条、`src/signing.rs` 2 条（干净仓 L2、删日志 L0、坏 JSON 仍可审计、手改
  ref/HEAD 判红、accept 回执进链、开放操作/拒绝事件/失败操作改状态、策略变更进链与手改策略判红、合并事件与冲突后审计、错误 token 留 auth 事件、auth/deny 字段语义、非快进 publish 留 deny、publish 请求形状留 deny、脏工作树 pull 留 deny、服务端 pull 拒绝留 deny、key add/revoke 进链与手改 keyset 判红、重复/未知 key 拒绝、Ed25519 key init/add --key-file/commit --sign-key 进链与坏签名判红）；新增 12 条变异（policy 事件不落链 / merge 事件不落链 / auth 事件不落链 / auth 不看 401 状态 / publish 拒绝不落 deny / deny 不看 reason / pull 拒绝不落 deny / publish 形状拒绝不落 deny / 服务端 pull 拒绝不落 deny / keyset 不进状态摘要 / signature 事件不落链 / 审计不验签），本机 auth 2/2、policy/merge/deny/pull/keyset/signature 各自抽跑均抓住；
  上一批 5 条写前/gate/失败状态变异仍保持 5/5，早先 3 条审计/锁变异仍全抓。尚未做：claim/witness/checkpoint 签名、key 轮换、Merkle/仓外锚。
- 跨机传输与鉴权（网络 v0）：`trit-vcs serve --dir <中央仓> --bind 127.0.0.1:7878 --token-file <文件>`，
  客户端 `publish/pull --remote http://host:port --token-file <文件>`。协议是自写的 HTTP/1.1 子集
  （`GET`/`POST`、`Content-Length`、一请求一连接、拒 `chunked`），只用 `std`；对象流 `TVOB`
  （magic + schema + 对象数，逐条 id/长度/载荷），收端**逐块重算 BLAKE3** 再入库。
  鉴权是 Bearer token（16–256 字节，常量时间比较，只从 `--token-file`/`TRIT_VCS_TOKEN` 进、不进 argv）。
  服务端发布要过三道闸：ref 名合法、tip 是提交且树闭包齐全（文件映射与所有块都在）、
  `merge_base(tip, current)==current` 才移动 ref；退历史回 409。
  边界：明文 HTTP 无 TLS（跨机套 SSH 隧道/反代）；对象数 100 万、单对象 32 MiB、body 256 MiB、
  连接 8、读写超时 30 s，超限回 413/503；网络面**不开放 force**。
  测试：`src/net` + `src/wire.rs` + `src/remote.rs` 单测 14 条、`tests/remote_cli.rs` 端到端 1 条
  （起 serve、发布、全量/前缀 pull、错 token 401、非快进 409、CLI 拒 force）；
  登记 4 条变异（token 比较恒真 / 对象流不看 magic / 收端不重算哈希 / 服务端不判快进），本机 4/4 全抓。
  401 提前拒绝时先排空 ≤1 MiB 请求体再回，避免 Windows 上带未读数据关连接发 RST、客户端连回执都读不到；
  客户端写 body 失败也先尝试读响应（401/413 以回执为准）。
- 跨仓认领账本：认领写在中央仓 `.tritvcs/claims.json`，多个工作树共享；`claims add/release/list/export`
  直接改它，`commit/preflight --claims <中央仓>/.tritvcs/claims.json` 即可用同一张表。
  `add` 做路径归一与在效相交检查（`claims_conflict` 并点名）、同 id 换 owner 拒绝（`claims_id_taken`）、
  `release` 只有 owner 本人能做（`claims_owner_mismatch`）；单写者 `claims.lock`；变更追加
  `claim_add`/`claim_release` 进中央仓哈希链。测试 `src/claims.rs` 7 条 + `tests/claims_cli.rs` 1 条
  （两个工作树共用账本、冲突阻断提交、导出快照可直接用于 `--claims`、审计链有记录）；登记 2 条变异（认领不查相交 / release 不核 owner），本机 2/2 全抓。
- 持久 sparse 索引：`.tritvcs/sparse.json` 记住前缀与基准树，前缀 `pull`/`checkout` 自动写、全量自动清；
  `status` 只扫该范围、只跟这棵树比，范围外没检出的文件不再被算成删除。新增 `sparse [--json]` /
  `sparse --clear`。测试 `src/sparse.rs` 3 条 + worktree/CLI/网络前缀 pull 各一条断言；登记 1 条变异（不采用持久范围），本机 1/1 抓到。
- `pull` 全量时把 HEAD 与索引一起落到被拉的提交（`Repo::adopt`），pull 完 `status` 立刻干净；
  拉之前先判快进与暂存区脏（`Repo::staged_paths`），不过就报 `NonFastForward` / `worktree_dirty`。
  带 `--prefix` 的 pull 仍不动 HEAD，避免范围外文件被算成删除。
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
