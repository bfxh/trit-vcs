# trit-vcs 审计强度路线图

> 状态：P0 首批与单文件离线审计包 TVAB v1 已落地（L2 对账、认领快照、判据回执、信任表 v0、Ed25519 提交/认领/witness sidecar、双签轮换、仓内签名 Merkle 检查点 v0、单事件 inclusion proof、检查点间 consistency proof v0、仓内文件锚 v0、调用方钉住外部公钥的独立外锚 v1、`audit bundle` / `audit verify-bundle`）；跨机同一视图尚未实现
> 日期：2026-11-26
> 目标：审计面做到“第三方可以离线复算”，不是“再加一条日志”
> 一句话：现在有**链**、有**对账**、有**提交/认领/witness 签名及双签轮换**、有**仓内签名 Merkle 检查点**、有**单事件 inclusion proof**、有**检查点间一致性证明**、有**仓内文件锚、独立外锚与单文件离线审计包**；仓内文件锚仍只是受信副本，独立外锚只认调用方从仓外钉住的公钥，真实独立性取决于外部密钥保管与部署；有**认领**、有**授权快照**；有 `verify`、也有 `audit`。下一步不是把日志写长，而是补跨机同一视图与完整操作覆盖。

## 0. 先给结论

### 0.1 当前真实水平：L2 首批，L3 机制部分落地

按审计能力分五级：

| 级别 | 定义 | 当前 |
|---|---|---|
| L0 | 有日志，能看发生过什么 | 有 |
| L1 | 链内改一条会被发现 | 有，但只能防中间改写；删尾巴、换整条链仍要靠检查点/锚 |
| L2 | 日志能重放成当前状态，漏账/假账会被抓 | **已实现首批**：`audit status/verify/reconcile` 对账 HEAD/refs/对象/claim_set/回执/state_digest；尚未覆盖所有会改状态的操作 |
| L3 | 每条关键事件能证明到签名检查点，检查点有仓外锚 | **部分**：仓内签名 Merkle 检查点、inclusion/consistency proof、仓内文件锚、独立外锚 v1 与 TVAB 离线复核已落；提交、认领变更与 witness 已有可选 Ed25519 sidecar。独立外锚不读仓内信任表，但公钥必须由调用方从仓外钉住，实际独立性取决于密钥保管与部署；跨机同一视图仍无 |
| L4 | 跨机同一视图，服务端回滚/分裂视图能被抓 | **没有** |

所以现在能说“有可对账、可签名、可锚定、可单文件离线复核的审计面”，还不能说“审计最强”。L2 的骨架已经能跑：删整本日志、手改 ref、状态漂移、回执/认领快照缺失都会红；TVAB 可在无仓库目录中重建并复验，但“所有操作都记账”、外部密钥的独立保管与跨机同一视图仍未完成。

### 0.2 顺序不能反

先做 L2（对账 + 全操作覆盖 + 授权/证据快照），再做 L3（签名 + Merkle + 锚），最后做 L4（跨机透明）。

原因很直接：**给一份可能漏账的账本盖公章，只会让假账更可信。** 签名必须建立在“日志能解释状态”之上，否则只是把不完整的历史签死。

### 0.3 做完之后能硬气的那句话

不是“所有维度都第一”——那是营销，不可复算。可以硬气的是这一句：

> 在同一份版本库对象图里，同时给出**谁做的、被谁授权、证据由谁产生、日志没有被截断、当前状态能由日志重放、跨机没有第二个版本**，而且第三方可以离线复算。

Git / GitHub / in-toto / Sigstore 分别有其中一两项，但它们不在同一个 VCS 对象图里，也不能用一份离线包全部复核。这个组合是 trit-vcs 真正能建立差异化的地方。

### 0.4 本轮已经落地的（可复算，不是 PPT）

| 能力 | 入口 | 事实 |
|---|---|---|
| 日志对账 | `audit status` / `audit verify` / `audit reconcile` | 比对日志文件是否存在/可读、HEAD、refs、对象闭包、`claim_set`、`accept` 回执、`op_begin/op_result` 配对、最新 `state_after`；`open_ops` 单独报 |
| 状态摘要 | `Repo::state_digest` | HEAD + refs + index + policy 原始字节 + claims 原始字节；存在 `keys.json` 时再加 keyset 原始字节；canonical JSON 后 BLAKE3；不把 journal 算进去，避免循环自证 |
| 共享状态锁 | `claims.lock` / `Repo::lock_state` | 认领、策略、信任表 add/revoke/rotate、提交签名、检查点、普通仓库状态写（stage/commit/ref/adopt）、中央仓 publish/pull、merge、公开 `append_audit`/`begin_operation`/`finish_operation` 和独立审计事件写入共用一把跨进程锁；已持锁的内部调用走显式 `*_locked` 核心，不递归抢锁。提交预检与写入不分开抢锁，快进检查、物化、ref/HEAD/索引更新与事件追加在同一临界区内；拿不到锁明确报 `state_locked`，不删锁、不静默覆盖，也不与账本写入并发撕裂状态摘要或错开检查点前缀 |
| 单写者链 | `Journal::append` | `journal.lock` 跨进程锁；拿锁后按文件长度决定是否重读，避免两个进程拿同一个 `seq` |
| 写前协议 | `Repo::begin_operation` / `finish_operation` | 状态变更前先写 `op_begin`（含 `state_before`），写后写 `op_result`（含 `status`/`state_after`）；崩溃留下开放操作，`audit` 报 `op_open`/`op_state_gap` |
| 策略变更 | `trit-vcs policy set` / `Repo::set_policy` | 整份写入 `policy.json` 也走 `op_begin/op_result`；新 `policy` 事件带 `schema: trit-policy-v1`、`session`、四个开关、`policy_hash`、`state_before`/`state_after`；版本化事件缺 `require_signed_claims` / `require_signed_witness` 或显式非布尔值均判红，并按开启重放；旧无版本事件缺字段仍按关闭重放 |
| 授权快照 | `ClaimSet` 对象 + `Commit.claim_set` | 提交时按 path 覆盖集合生成不可变快照；`verify`/`audit` 校验对象存在且摘要对得上 |
| 认领变更签名 v0 | `claims add/release --sign-key` / `add_signed/release_signed` | `trit-claim-sign-v1` 绑定 action、`op_begin` 哈希、完整 `ClaimSpec`、前后状态、key_id/principal/owner/签名时间；落 `claim_signature` sidecar。授权按操作时点重建：key 必须在 `op_begin` 前已有 `key add/rotate` 信任，且到成功 `op_result` 前未被吊销/轮换；公钥、角色、principal/owner 必须一致，签名 `state_after` 同时绑定认领事件与 `op_result.state_after`，不采信签名者回填的 `signed_at_ms`。`--require-signed-claims` 可强制新操作签名，审计按事件重放策略并检查已签事件确有 sidecar；`trit-policy-v1` 缺签名字段时 fail-closed，旧无版本事件与历史未签名操作保持兼容。未签的 `policy` 事件不是独立信任根，整链重写仍需签名检查点/锚来钉住 |
| 判据回执 | `AcceptReceipt` 对象 + `accept` 事件 | 记录树、基线、session、认领 id、每条判据的 exit/超时/输出摘要/是否截断；回执摘要进链 |
| 提交签名 | `trit-vcs key init/add` / `commit --sign-key` | 生成/加载 Ed25519 key；`signature` 事件记录 commit/key_id/algorithm/signature/signed_at_ms，审计用信任表公钥 `verify_strict` 提交字节；签名是 sidecar，不改提交 id |
| Witness 签名 | `trit-vcs attest` / `admit --signed` / MCP `admit({signed:true})` | `trit-attestation-v1` sidecar 绑定 commit、原始 witness 摘要、树、实际第一父树、key_id、会话与签名时间；默认未签名兼容，`require_signed_witness` 可强制。审计核事件/对象、op_begin/成功 op_result、重复、信任/指纹/角色/信任时点/吊销/签名；签署与验签都按签名时间拒绝吊销后的回填，同毫秒吊销不追溯 |
| 独立外锚 v1 | `audit external-anchor` / `audit verify-external-anchor` | 外部钥签检查点事件哈希、高度、head、Merkle 根、previous、外部 key_id 与签名时间；验证只认调用方钉住的仓外公钥，不读 `keys.json`，重算当前前缀与较新检查点一致性；输出拒绝覆盖 |
| 密钥添加审计 | `trit-vcs key add` / `audit verify` | 新 `key add` 事件带 `public_key`；显式非空公钥必须是合法 Ed25519 公钥、指纹等于 `key_id`，且与信任表记录一致。显式空串、非字符串、非法编码和指纹/信任表不符判红；历史缺字段或 `null` 保持兼容 |
| 密钥轮换 | `trit-vcs key rotate` | 旧钥和新钥对 `trit-key-rotate-v1` 声明各签一次，旧记录吊销、新记录继承 principal/role 并记 `rotated_from`；审计复验双签、指纹和信任表谱系 |
| 签名检查点 v0 | `trit-vcs audit checkpoint` / `audit proof` | 对包含当前 `op_begin`、但不含 `checkpoint` 事件本身的前缀做 Merkle 根，事件记 height/head/merkle_root/previous/key_id/signature；审计重算根、核高度和前一条检查点、验签；`audit proof` 输出单事件 inclusion proof，严格核对叶数、下标和每层路径，拒绝幽灵叶与畸形路径 |
| 一致性证明 v0 | `trit-vcs audit consistency` / `audit verify-consistency` | 针对现有“奇数末节点复制”的 Merkle 树证明旧前缀是新根的前缀；节点坐标必须规范升序且不重复，独立重算两侧根；穷举 1–65 叶全前缀，1 万叶/旧前缀 4,321 叶的证明少于 64 个节点 |
| 文件锚 v0 | `trit-vcs audit anchor` / `audit verify-anchor` / `audit verify --anchor` | 把完整检查点事件包成 schema=1 文件；导出前先核对检查点匹配当前仓库前缀，复验事件哈希、签名、信任/角色/吊销、同高当前事件、锚定前缀 head/previous/root 和到较新检查点的一致性；输出拒绝覆盖。文件锚是受信副本，不是独立 CA/透明日志/可信时间戳 |
| 独立外锚 v1 | `trit-vcs audit external-anchor` / `audit verify-external-anchor` | 单独的 `trit-external-anchor-v1`；签名/验签密钥来自调用方明确钉住的仓外公钥，验锚不读仓内信任表；仍重算仓库前缀和一致性。公钥渠道与外部私钥保管决定真实独立性 |
| 离线审计包 TVAB v1 | `audit bundle` / `audit verify-bundle` | 单文件封闭容器封装完整 journal、HEAD/index/policy/claims/keys/refs、独立外锚与日志/状态独立推导的精确证据对象闭包；拒绝 sparse 状态；验证不打开现有仓库、不联网、不执行 witness 或 shell，在独占临时目录重建后核对对象 ID 集合、复算状态摘要并重跑 L2 审计；同目录临时文件同步后以不覆盖方式原子发布 |
| 请求身份关联 v2 | `serve --actor` / `X-Trit-Request-Id` / `auth` / `deny` | 每个成功解析的请求由服务端生成独立 request id；成功/失败鉴权都落 `trit-auth-v2`，响应回传同一 `X-Trit-Request-Id`。成功 actor 只取服务端配置，省略时为 `bearer:unidentified`，不采信客户端 actor 头；publish/pull 的请求形状或业务拒绝详情也带 request id/actor。旧的无版本拒绝事件保持兼容；未知 schema、新版缺合法 request id、放行缺 schema 或合法 actor 都判红。actor 是部署配置，不是按用户验证的密码学身份；来源地址未记录 |
| 成功同步关联 v1 | `trit-sync-v1` / `op_id` / `X-Trit-Op-Id` | 客户端生成恰好 64 个 ASCII 十六进制字符、不做首尾裁剪的 op id，publish 经头、pull 经查询参数发送；HTTP 成功响应回传 request id/op id，由客户端核对。source/central/client 事件按同一组关联号、transport/side/stage 记录操作与前后状态；本地事件只有 op id。审计拒绝畸形字段、非法阶段、同侧重复 op id，以及中央 HTTP 成功缺同 request id 的前置放行鉴权。旧客户端缺 op id 由服务端补生成，旧无版本事件保持兼容；新版客户端反向要求旧服务端成功响应带合法且匹配的关联头，否则拒绝；同步闭包携带提交引用的 claim_set/witness 证据对象 |
| 操作事件 | `stage` / `commit` / `ref` / `adopt` / `claim_*` / `claim_signature` / `publish` / `pull` / `accept` / `gate` / `deny` / `policy` / `key` / `signature` / `attestation` / `checkpoint` / `merge` / `auth` | 带 `state_after` 的事件能被状态摘要校验；`publish` 记 `previous`/`forced`，`pull` 记 prefix/force，`gate` 记拒绝原因与 `state_before`/`state_after`，`deny` 记业务拒绝的入口/原因/消息/请求细节（含 publish 请求形状、服务端 pull 的缺 ref/未知 ref、本地 pull 的脏工作树/非快进），`policy` 记开关与策略摘要，`key` 记 action/key_id/principal/role/keyset 摘要（带公钥的 add 另记 public_key，rotate 另记 old_key_id、双签和指纹），`signature` 记提交签名并用 trust store 验签，`attestation` 记 witness sidecar 并核操作/提交/树/父树/信任/签名，`claim_signature` 记认领变更签名并核操作/ClaimSpec/前后状态/授权，`checkpoint` 记前缀高度/根/前一条检查点并用 trust store 验签，`merge` 记两个输入/树/冲突数，`auth` 记成功/失败的方法/路径/request id/actor（不记 token）；失败另记原因/401，放行不预报端点最终状态；版本化 `publish`/`pull` 另记 op id、transport/side/stage、HTTP request id 与前后状态 |
| 查询面 | `audit log` / `audit show` / `--json` | 审计员不必用眼睛翻 JSONL；`audit status --json` 可直接分支 |
| 坏日志容错 | `Repo::open_for_audit` | journal 是坏 JSON 时仍能打开审计入口，输出 `journal_broken`，而不是在 `Repo::open` 阶段只丢一句 IO 错 |
| 失败即非零 | `audit status` | 有 issue 时退出码 1；`--json` 仍输出结构化报告，便于 CI 消费 |

已经落地、但不能假装完整的：Ed25519 提交、认领变更与 witness sidecar 签名及双签轮换、仓内签名 Merkle 检查点 v0、单事件 inclusion proof、检查点间 consistency proof v0、仓内文件锚 v0、独立外锚 v1、单文件离线审计包 TVAB v1；witness 签名默认可选，导出的 `ClaimSpec` 快照仍未签名，跨机 journal 互链仍未做。提交/检查点/witness 签名里的 `signed_at_ms` 是签名者自报时间，不是可信时间戳，相关吊销判断不能防刻意回填；认领签名授权按 `op_begin` 到 `op_result` 的事件顺序重建，witness 签名拒绝早于信任加入时间的签名。仓内文件锚能验证“当前仓库扩展了保留的检查点”，但不能证明从未见过的后续事件存在，也不能抗仓库、锚副本与信任表被同一管理域整体改写。独立外锚在验证时不读仓内信任表，只认调用方从仓外钉住的公钥；但代码不能替代外部私钥保管、公钥指纹核对与独立部署，同一管理域内的外锚仍不构成抗整机篡改。TVAB 证明包内字节、外锚前缀、对象与状态彼此一致，不证明签者意图诚实、墙钟可信、外部服务事实为真或公钥保管独立。**这些没做完之前，L3 不能完整宣称。**

---

## 1. 审计到底要回答什么

不要从“加什么功能”开始，从审计员的问题开始。一个审计员拿到仓库、中央仓和一份离线包，要能回答 7 个问题：

| 编号 | 问题 | 需要的证明 |
|---|---|---|
| A1 | 谁，在什么时候，用什么身份，改了什么？ | 操作事件 + 身份签名 + 可信时间 |
| A2 | 这次改动被授权了吗？授权范围是什么？ | 认领/策略的**当时快照**，不是现在的账本 |
| A3 | “测试通过/构建成功”是谁说的？真的绑在这棵树上吗？ | 执行者签名的 attestation + 环境/材料摘要 |
| A4 | 日志有没有被删尾、改写、换整条？ | Merkle 检查点 + 仓外锚 + 一致性证明 |
| A5 | 当前 HEAD/refs/账本/策略，能不能由日志重放出来？ | 状态摘要 + `reconcile` |
| A6 | 另一个机器看到的，是不是同一个历史？ | 客户端 pin + 服务端检查点 + 分裂视图检测 |
| A7 | 不联网、不信任服务端，能验吗？ | 单文件 audit bundle + 离线 verifier |

只要有一问答不了，“审计强”就只是形容词。

---

## 2. 现在的审计面：事实盘点

### 2.1 已经成立的

| 面 | 现在有什么 | 代码位置 |
|---|---|---|
| 事件链 | `Journal` 追加式 JSONL；校验 `seq`/`prev`/`hash`；坏链拒绝继续追加 | `src/journal.rs` |
| 对象完整性 | `Repo::verify` 跑对象库 `fsck`，检查 HEAD 可达提交和 witness 绑定 | `src/repo.rs` |
| 提交语义 | 提交里带 `session`/`claims`/`evidence`/`tags`/`witness`/`intent` | `src/model.rs` |
| 认领 | 中央仓账本、单写者锁、冲突点名、`add/release` 进哈希链 | `src/claims.rs` |
| 证据 | in-toto Statement 形状绑定树摘要；可选 Ed25519 `attestation` sidecar 绑定提交/树/实际父树/原始见证/签者；`admit --signed` 验签，默认 `admit` 保持旧兼容 | `src/witness.rs` / `src/attestation.rs` |
| 跨机 | Bearer token、收端重算 BLAKE3、只准快进 | `src/net` / `src/remote.rs` |
| 交接 | 包内 commit/tree/parents/intent/claims/diff/文件，逐项重算 | `src/handoff.rs` |

这些不是白做的。问题在于它们是**七个分散的“面”**，还没有连成一条审计员能走的“链”。

### 2.2 结构性缺口

按优先级排，不按模块排。

| 编号 | 缺口 | 现状事实 | 会导致什么 | 优先级 |
|---|---|---|---|---|
| G1 | 日志不能解释状态 | `Repo::verify` 仍只统计事件数、跑对象 fsck、走第一父链；但 `audit status` 已比对 journal 与 refs/HEAD/claims/policy/state_digest | `verify` 单独跑仍可能绿；用 `audit` 才会抓删日志/手改 ref/漏记 commit | P0，**部分关闭** |
| G2 | 链可截断、可换整条 | 仓内签名 Merkle 检查点、单事件 inclusion proof、检查点间 consistency proof、仓内文件锚与独立外锚 v1 已落；独立外锚只认调用方钉住的仓外公钥，但公钥渠道/私钥保管仍须独立 | 保留较新锚时可发现其后的删尾；旧到新换链会被一致性证明拒绝；仓库、锚副本和信任表被同一管理域整体改写仍可能验不出 | P0，**机制关闭，部署信任根未关闭** |
| G3 | 身份不可验证 | `session` 是自由字符串；提交已有可选 Ed25519 `signature` sidecar；`claims add/release --sign-key` 已有 `claim_signature` sidecar 并核完整 `ClaimSpec`/操作/状态/授权；`key rotate` 要求旧/新钥双签；`checkpoint` 由 auditor/release 钥签名；witness 已有可选 `attestation` sidecar 并核提交/树/父树/信任/签名 | 提交、已签认领变更、检查点与已签 witness 是谁做的可验证；轮换有双钥同意；未签操作和证据仍可能被自称的主体替换 | P0，**部分关闭** |
| G4 | 操作覆盖不全 | 状态变更已走 `op_begin/op_result`（`stage`/`commit`/`ref`/`adopt`/`claim_*`），提交门拒绝落 `gate`，策略变更落 `policy`，合并落 `merge`，成功/失败鉴权落 `trit-auth-v2`（服务端 actor + 独立 request id），成功 publish/pull 落 `trit-sync-v1`（op id + HTTP request id + side/stage），publish 业务/请求形状拒绝、服务端 pull 拒绝、本地 pull 业务拒绝落 `deny`，信任表 add/revoke/rotate 落 `key`，提交与认领变更签名分别落 `signature`/`claim_signature` | 鉴权、成功同步与响应已可按请求/操作关联，但 actor 仍是部署配置；两本 journal 没有互链或共同锚，来源地址未记录，跨仓仍无原子事务 | P0，**部分关闭** |
| G5 | 并发与崩溃会撕裂日志 | `Journal::append` 已有 `journal.lock` 单写者链；认领/策略/信任/提交签名/检查点、普通仓库状态写、中央仓 publish/pull、merge 与独立审计事件共用 `claims.lock` 状态锁；提交预检和写入在同一临界区；关键状态变更前有 `op_begin.state_before`、后有 `op_result.state_after` | 锁住并发写，检查点快照与追加不会插入其他事件；写前协议让“操作开始”有账，但仍不能阻止进程死在中间，只能让审计抓到 | P0，**部分关闭** |
| G6 | 授权不可事后复核 | 已落 `ClaimSet` 不可变快照，claim 事件补 `path_list` 和完整 `ClaimSpec`，可选 `claim_signature` 证明中央账本变更；账本 TTL 过后原条目仍会消失 | 快照能证明当时授权；已签账本变更有签名历史；未签历史与导出的 `ClaimSpec` 快照仍不能抗替换 | P0，**部分关闭** |
| G7 | 证据不可验证 | witness 已有可选签名 `attestation` sidecar，绑定 commit/树/实际父树/原始 witness/签者/会话；`accept` 结果已落 `AcceptReceipt` 对象/事件；handoff 仍不携带 witness/accept/attestation | 已签 witness 可复核“谁说了通过并绑哪棵树”；未签 witness 与回执仍可被替换，离线 handoff 证据链未闭合 | P1，**部分关闭** |
| G8 | 跨机没有同一视图 | 客户端 journal 与中央仓 journal 是两本账；成功 publish/pull 已用 op id/request id 关联，但两本账不互链、不共享锚；单 token 的 actor 是部署配置；ref 是普通文件 | 关联号能对账一次操作，不能证明服务端没有回滚/改写 ref 和账本；客户端没有 pin，仍发现不了第二个历史 | P1，未关闭 |
| G9 | 时间与策略变更不可信 | HLC 只给本地全序；ref/stage 用墙钟毫秒；`policy set` 已有事件与状态对账，但 `policy.json` 仍可被直接改，且无签名 | 可回填时间；绕过 CLI 直接改策略仍只能靠 `state_digest` 漂移/接续抓到，不能证明谁改的 | P1，**部分关闭** |
| G10 | 离线审计查询与证明入口 | `audit status/log/show/verify/reconcile/proof/consistency/verify-consistency/anchor/verify-anchor/external-anchor/verify-external-anchor/bundle/verify-bundle` 已可用；TVAB v1 可单文件离线重建并复验 | 审计员能查账、验 inclusion/consistency、验锚并用单个离线包复核；包内信任表仍不是独立信任根，包格式升级须新 schema | P2，**机制关闭，持续加固** |
| G11 | Git 桥会丢审计信息 | import 只走 `--first-parent`，丢掉 merge 图、作者签名；session 被合成；export 只加尾注 | Git 侧的信任无法映射到 trit；审计链在桥接处断掉 | P2 |
| G12 | 规模与隐私没有预算 | `Journal::open` 每次全量读；无增量校验/归档/脱敏/保留策略 | 事件上百万后打开变慢；日志可能把密钥/客户数据带出去 | P2 |

### 2.3 最刺眼的三个具体事实（以及现在的边界）

1. **删掉 `.tritvcs/journal.jsonl`，`trit-vcs verify` 仍可能报绿。**
   它验的是对象库和 HEAD 可达提交，不是“日志是否完整记录了这些状态变化”。
   **现在**：`trit-vcs audit status` 会报 `journal_missing` / `head_unlogged` 并退出非零；但审计员必须知道要跑 `audit`，不能只看 `verify` 的一行绿。

2. **`set_ref` 先 `fs::write` 再 `journal.append`。**
   两次系统调用之间崩溃，ref 已经动了，账上却没有这一笔。审计日志不是写前日志（WAL）。
   **现在**：`op_begin/op_result` 已落到 `stage/commit/ref/adopt/claim_*`，`audit` 能抓 `op_open` 与 `op_state_gap`；但抓到不等于阻止，进程死在写盘中间仍会留下半截状态，下一次合法操作会把 `state_before` 对出来，而不是自动回滚。

3. **认领事件只记 `paths.len()`。**
   旧事件里审计员只看到“某个 owner 认领了 3 条路径”，看不到是哪 3 条，也看不到当时的账本摘要；TTL 到期后，原始条目可能被清掉。
   **现在**：新 `claim_add` 事件已补 `path_list` 与完整 `ClaimSpec`，提交落 `ClaimSet` 对象；`--sign-key` 可追加独立 `claim_signature`，把认领字段、操作和前后状态签进历史。旧事件仍只能按语义对账，不能补出路径，导出的 `ClaimSpec` 快照也仍未签名。

---

## 3. 目标：L4 审计闭环

### 3.1 一张图

```text
写操作（commit / ref / claim / accept / publish / policy / key）
        │
        │  单写者锁 + op_id + before/after 状态摘要
        ▼
AuditEvent v2 ── hash chain ──► Merkle tree ──► signed checkpoint ──► anchors
        │                              │
        ├─ actor / key / role          ├─ inclusion proof（事件/提交）
        ├─ action / subject            └─ consistency proof（旧→新）
        ├─ before / after digest
        ├─ policy digest
        └─ result / evidence digest
        │
        ▼
audit reconcile：用事件重放到 refs / HEAD / claims / policy
        │
        ├─ 一致 → 绿
        └─ 不一致 → 具体 kind（漏账 / 假账 / 悬空状态）
```

### 3.2 一条事件链，两级检查点

- **事件链**：每次状态变化一条，负责“发生了什么”。
- **检查点**：每 N 条事件（或每次 publish）把事件哈希做成 Merkle 根，签名，负责“这段历史没被换”。
- **锚**：把检查点放到仓库之外，负责“连检查点也没被换”。

只有事件链，没有检查点，等于只有账本没有封条；只有检查点，没有对账，等于封条贴在一本可能缺页的账上。

### 3.3 三类证明

| 证明 | 回答 | 大小 |
|---|---|---|
| inclusion proof | 某个事件/提交确实在这棵 Merkle 树里 | O(log n) 个哈希 |
| consistency proof | 新树是在旧树后面追加的，不是换了一棵 | O(log n) 个哈希 |
| audit bundle TVAB v1 | 第三方离线复算容器完整性、外锚前缀、对象闭包与 L2 状态一致性 | journal + 封闭状态文件 + 独立推导的精确证据对象闭包 + 独立外锚；最大 256 MiB |

### 3.4 信任根

- **身份**：Ed25519 密钥；`key_id` = 公钥摘要；principal 由 trust store 映射，不由 `session` 字符串自封。
- **签名**：commit / claim 请求 / checkpoint / attestation 分开签；签名域分开，防止跨协议重放。
- **信任**：TOFU 起步，`trust.json` 记录 principal、角色、有效期、吊销；密钥轮换由旧钥签新钥。
- **策略**：`policy.json` 加 `audit` 段，整个文件签名；策略变更本身是一条事件。
- **锚**：至少一个**不同管理域**的锚；同一个 `.tritvcs` 目录里的锚只算方便，不算安全。

---

## 4. 最小数据模型

### 4.1 `AuditEvent v2`

不再用自由 `payload: Value` 兜一切。每条事件至少要有：

```json
{
  "schema": 2,
  "seq": 42,
  "op_id": "01J...",
  "at": { "wall_ms": 1760000000000, "hlc": [1760000000000, 1], "source": "local" },
  "actor": { "principal": "qoder:s1", "key_id": "ed25519:...", "role": "author" },
  "action": "commit",
  "subject": { "kind": "commit", "id": "blake3:..." },
  "before": "blake3:...",
  "after": "blake3:...",
  "policy": "blake3:...",
  "result": { "status": "allowed", "error_kind": null },
  "evidence": ["blake3:..."],
  "prev": "blake3:...",
  "hash": "blake3:..."
}
```

关键点：

- `before`/`after` 是**状态摘要**，不是随便的对象 id。状态摘要至少覆盖：HEAD、refs 映射、index 树、claims 账本摘要、policy 摘要、keyset 摘要。
- `op_id` 让“begin/result”两条事件、跨机 publish 与本地 commit 能对上。
- `result.status` 必须能表达 `allowed` / `denied` / `failed` / `incomplete`；拒绝也要留账。
- `hash` = BLAKE3(域分隔前缀 + 除 `hash` 外的 canonical JSON + prev)，域分隔避免和其它协议共用哈希输入。

### 4.2 写前日志协议

每个会改状态的操作：

1. 拿仓库级单写者锁；
2. 算 `before` 摘要，分配 `seq`/`op_id`；
3. 追加 `op_begin` 并 `sync_data`；
4. 执行状态变化；
5. 追加 `op_result`（含 `after`、`result`）并 `sync_data`；
6. 释放锁。

崩溃在 3–4 之间：`reconcile` 看到悬空 begin，标 `incomplete`，不假装成功。
崩溃在 4–5 之间：状态已变、result 缺失，`reconcile` 标 `dangling_state`，要求人工/自动补齐，而不是静默续写。

这比“先写状态再补日志”多一次 fsync，但审计买的就是这个顺序。

### 4.3 提交里的授权快照

`claims: Vec<String>` 保留，兼容旧提交；新增：

```json
{
  "claim_set": "blake3:...",
  "accept_receipt": "blake3:...",
  "signatures": [ { "key_id": "ed25519:...", "sig": "..." } ]
}
```

签名覆盖**除 `signatures` 外的全部字段**（避免“签名里包含签名”的循环），提交 id 覆盖包含签名的完整对象；
老 v1 提交不加这个字段，序列化与 id 都不变。多签只是在同一份 body 上追加不同 key 的签名，不改变已验证的语义。

> 当前落地的是兼容旧 id 的 **sidecar**：签名放在 `signature` 事件里，不塞进提交对象；上面的
> `signatures` 字段是后续把签名纳入提交 id 的目标形态。两者都签同一份提交字节，不能混为一谈。

`ClaimSet` 是不可变对象，至少含：

```json
{
  "schema": 1,
  "ledger_digest": "blake3:...",
  "resolved_at": 1760000000000,
  "claims": [
    { "id": "c1", "owner": "qoder:s1", "paths": ["src/a.rs"], "acquired_at": 1760000000000, "expires_at": 1760000900000 }
  ]
}
```

这样账本之后怎么变、TTL 怎么过期，都不影响“提交当时被谁授权改哪些路径”的复核。

### 4.4 证据回执

`witness` 保持 in-toto Statement 的 `subject`/`predicate` 形状，v0 默认未签名以兼容旧仓；已落地的
`attestation` 是独立 sidecar，而不是 DSSE envelope：

- `trit-attestation-v1` 绑定 commit id、原始 witness 字节摘要、树、实际第一父树、key_id、会话与签名时间；
- sidecar 放对象库并落 `attestation` 事件，不改 `Commit`、witness、提交 id、bundle 或既有 journal 事件形状；
- `attest` 写入时验证 witness/树/退出码/父树、信任成员、公钥、角色、信任加入时间与吊销；
- `admit --signed`、MCP `admit({signed:true})` 与 `require_signed_witness` 策略要求有效 sidecar；
- 审计复核事件/对象一致性、`op_begin` 参数、成功 `op_result`、重复 sidecar、信任/角色/指纹/时点/吊销与签名；
- 旧 witness 可不声明 `predicate.base`；一旦声明就必须等于真实第一父树，attestation 始终绑定真实父树。

`accept` 的每条命令结果仍落成 `AcceptReceipt` 对象：argv、exit、stdout/stderr 摘要、耗时、超时、截断。
当前 receipt 本身未签名，handoff 也尚未携带 witness/accept/attestation，因此证据闭环只完成签名准入这一段。
没有签名的 witness 只能叫“证据草稿”，不能叫“通过证明”。

### 4.5 检查点与证明

当前 v0 为兼容既有检查点根，**没有**采用 RFC 6962 的奇数节点上提，而是每层复制最后一个节点：

- 叶子：`BLAKE3("trit-checkpoint-leaf-v1:" || event_hash_hex)`
- 节点：`BLAKE3(0x01 || left_raw_32 || right_raw_32)`
- 空前缀根：`BLAKE3("trit-checkpoint-empty-v1")`

检查点事件记 `height/head/merkle_root/previous/key_id/algorithm/signature/signed_at_ms`，
`height` 是根覆盖的事件数，检查点事件本身不在根里；签名覆盖
`trit-checkpoint-v1` 声明。文件锚 v0 直接包住完整事件：

```json
{ "schema": 1, "event": { "seq": 42, "kind": "checkpoint", "payload": { "...": "..." } } }
```

独立外锚 v1 不复用仓内信任表，形状为：

```json
{
  "schema": "trit-external-anchor-v1",
  "checkpoint": "<64-hex>",
  "height": 42,
  "head": "<64-hex-or-null>",
  "merkle_root": "<64-hex>",
  "previous": "<64-hex-or-null>",
  "key_id": "ed25519:...",
  "algorithm": "ed25519",
  "signature": "<128-hex>",
  "signed_at_ms": 1760000000000
}
```

`checkpoint` 是检查点**事件哈希**，不是前缀根；声明还覆盖高度、head、Merkle 根、previous、外部 key_id
与签名时间。导出时外部私钥必须与调用方钉住的公钥匹配，签名时间不得早于被锚检查点的签名时间。
验证时先验外部签名，再要求当前同高事件哈希一致、事件确为 checkpoint、摘要一致，并重算锚定前缀与到
较新检查点的一致性。验证过程不读取 `repo.keys()`；调用方必须从仓库外的信任渠道取得并核对公钥指纹。
只有旧外锚时，较短但一致的前缀仍是合法扩展，不能证明从未见过的后续事件不存在。该机制不是透明日志、
CA 或可信时间戳，真实独立性取决于外部私钥保管与部署。

检查点间 consistency proof v0 的形状：

```json
{
  "schema": 1,
  "from_size": 100,
  "to_size": 1234,
  "old_root": "<64-hex>",
  "new_root": "<64-hex>",
  "subtrees": [{ "level": 0, "index": 0, "hash": "<64-hex>" }],
  "siblings": [{ "level": 1, "index": 0, "hash": "<64-hex>" }]
}
```

验证器不信调用方自报的根：它先核对所选检查点的 size/root，再严格检查坐标集合（额外、缺失、重复、
越界或换位都拒绝，且坐标必须按 `(level, index)` 规范升序），最后用同一组节点独立重建旧根与新根。
单事件 inclusion proof 则先核 `leaf_count`、事件下标和路径长度，再逐层确认当前节点存在，幽灵叶和
错路径不能只靠最终哈希相等蒙过去。文件锚导出前会先对当前仓库前缀执行完整核对，之后才重算锚定前缀的
`head`/`previous`/Merkle 根；签名正确但前缀摘要对不上的检查点不会落成锚。未来多签检查点/独立审计
bundle 可以升 schema=2，但不能悄悄换掉 v0 的树规则或让旧锚失效。

### 4.6 策略

不要另造配置语言。沿用 `.tritvcs/policy.json`，加 `audit` 段：

```json
{
  "require_witness": true,
  "require_intent": true,
  "audit": {
    "require_signed_commits": true,
    "require_claim_snapshot": true,
    "require_accept_receipt": true,
    "checkpoint_interval_events": 256,
    "anchor": "central",
    "protected_refs": ["main"],
    "required_cosigners": 1
  }
}
```

目标（尚未落地）：策略文件整体签名；每次变更产生 `policy_change` 事件，带旧/新摘要和签名者。默认全关的旧行为保留，逐项目 opt-in。当前已落地的是未签名的 `policy` 事件与 `trit-policy-v1` 重放规则，不能把它当独立信任根。

### 4.7 离线审计包 TVAB v1

`audit bundle` 与 `audit verify-bundle` 已落地。TVAB 是新的单文件容器，不改变冻结的
`TVBD`、提交 id、witness 或 journal 格式。二进制布局固定为：`TVAB`、schema `u32 LE`、
manifest 长度 `u32 LE`、manifest JSON、部件数 `u32 LE`，随后每件依次写 32 字节 BLAKE3 id、
长度 `u32 LE` 和原始字节。所有整数都是小端；拒绝尾字节、截断、重复部件名、未排序部件、
未知字段、unsafe ref、摘要/长度不符和不支持的 schema。

v1 上限：整包 256 MiB、manifest 4 MiB、单件 64 MiB、100,000 件、1,000,000 条事件；外锚文件
1 MiB。manifest 记录 schema、事件数、状态摘要、独立外锚和按名字严格升序的 `PieceRef`
（name/hash/bytes）。封闭部件集合是 `journal.jsonl`、`HEAD`、`index.json`、`policy.json`、
`claims.json`、`keys.json`、`refs/<合法 ref>` 与 `object:<64位摘要>`；manifest 必须恰好含一个
journal。`sparse.json` 不在集合内。部件路径由验证器映射，不采用包内任意路径，也不执行包内命令。

导出先锁仓，要求独立外锚匹配当前前缀、没有未收口操作、L2 审计全绿；再从日志里的
stage/commit/ref/adopt/pull/publish/signature/accept/attestation/merge 引用，以及 HEAD、refs、index
独立推导证据对象集合。提交闭包包含提交、树、文件映射、块、全部父提交、witness、claim_set 与
intent 父树；merge 同时纳入结果树及 ours/theirs/base 提交；回执和 attestation 也递归纳入其结果树与父树。**只有被当前状态或已锚日志证明的对象才进包**，
对象索引里未被任何状态或事件引用的孤立对象不导出。验证时独立重算同一集合并与包内对象 ID 做精确
双向比较，因此不是“重导后数同一个清单”的自证。包内含完整 journal、认领、策略、信任表及
witness/receipt 等原始内容，应按敏感审计材料保管；BLAKE3 只提供完整性，不提供保密性。

`sparse.json` 不属于 `Repo::state_digest`，现有写入路径也没有统一提供可由已签日志重建的 sparse
历史。为避免封入外部锚无法证明的范围/树状态，TVAB v1 在源仓存在 sparse 索引时拒绝导出，在包内
出现 `sparse.json` 时拒绝验证；先全量检出或运行 `trit-vcs sparse --clear`。`--out` 先写同目录唯一
临时文件并 `sync_all`，再用 `hard_link` 做目标存在即失败的原子发布；随后清理临时链接，失败会显式
报告，已有目标不会被替换。

外锚指向 `checkpoint` 事件，而正常检查点操作在其后还有一个 `op_result`。TVAB 恰好允许这一条
确定的成功收口：其 `op/begin/begin_hash/status/result/state_after`、时间戳必须与已锚的
`op_begin`/`checkpoint` 一致，四个状态字段都必须是合法哈希且等于重建仓库的实际
`state_digest`。不能再带其他尾巴，也不能靠重算事件哈希绕过这一检查。

验证不打开调用方现有仓库、不联网、不执行 witness 或 shell：先用调用方钉住的仓外公钥验外锚，
再在随机独占临时目录重导对象、恢复封闭状态文件、重开仓库、复算状态摘要、核对事件数与独立推导的
对象 ID 集合并重跑 L2 审计；报告字节数由已解码的头部、manifest 与部件长度计算，不再重读原路径。
包内 `keys.json` 只作为历史状态，绝不是独立信任根。TVAB 与外锚入口先拒绝目录、符号链接、FIFO 等
非普通文件，避免在格式/大小检查前阻塞。临时目录正常/失败路径都会清理，清理失败会带路径显式报告。
主要失败 kind 有 `audit_bundle_bad`、`audit_bundle_io`、`audit_bundle_repo`、
`audit_bundle_journal`、`audit_bundle_exists`、`audit_bundle_hash_mismatch`、
`audit_bundle_truncated`、`audit_bundle_trailing`、`audit_bundle_too_large`、
`audit_bundle_incomplete`，以及外锚的 `anchor_*`。

**证明边界**：TVAB 证明包内完整性、已锚前缀与重建状态一致，不证明签者意图诚实、墙钟时间可信、
外部服务事实为真或公钥保管真正独立。它也不是透明日志、CA 或可信时间戳服务。只有旧外锚时，
较短的一致前缀仍是合法扩展；包描述的是封包时可见的历史，不证明从未见过的后续事件不存在。

---

## 5. CLI / API 应该长什么样

审计不是给库内部用的，必须有一条审计员能直接走的命令面：

```sh
# 总览：当前级别、检查点、锚、覆盖缺口
trit-vcs audit status --json

# 对账：日志能不能重放成当前状态
trit-vcs audit reconcile --central ./central --json

# 验链 + 验签名 + 验锚（默认 quick，--deep 才碰对象库全量）
trit-vcs audit verify --deep --anchor ./anchors/latest.json --json

# 查事件，不查 commit message
trit-vcs audit log --kind denied --actor qoder:s1 --path src --from-seq 100 --json
trit-vcs audit show 42 --json

# 给第三方 inclusion proof（叶下标、兄弟路径由 audit proof 重算）
trit-vcs audit proof --checkpoint <检查点事件 seq> --event <事件 seq> --json

# 打仓内签名检查点（v0；文件锚由下面的 anchor 命令单独导出）
trit-vcs audit checkpoint --key-file ~/.trit/keys/audit.ed25519 --owner qoder:audit --json
# 给某个事件生成 inclusion proof（证明它在已签名前缀 root 下）
trit-vcs audit proof --checkpoint <检查点事件 seq> --event <事件 seq> --json
# 证明新检查点的前缀扩展了旧检查点，不是换了一棵
trit-vcs audit consistency --from <旧检查点事件 seq> --to <新检查点事件 seq> --out consistency.json --json
trit-vcs audit verify-consistency --from <旧检查点事件 seq> --to <新检查点事件 seq> --proof consistency.json --json
# 导出并复验文件锚；锚文件必须由调用方独立保管
trit-vcs audit anchor --checkpoint <检查点事件 seq> --out ./anchors/latest.json --json
trit-vcs audit verify-anchor --anchor ./anchors/latest.json --json

# 离线包：不依赖仓库、不依赖网络；公钥必须从仓外独立渠道钉住
trit-vcs audit bundle --out repo.audit.tvab --anchor external-anchor.json --anchor-public-key <仓外公钥hex> --json
trit-vcs audit verify-bundle repo.audit.tvab --anchor-public-key <仓外公钥hex> --offline --json

# 身份（已落地）
trit-vcs key init --out ~/.trit/keys/author.key
trit-vcs key add --key-file ~/.trit/keys/author.key --principal qoder:s1 --role author --owner qoder:s1
trit-vcs key rotate --old-key-file ~/.trit/keys/author.key --new-key-file ~/.trit/keys/author-2027.key --reason "年度轮换" --owner qoder:s1
trit-vcs key revoke --key-id ed25519:<指纹> --reason "离职" --owner qoder:s1
trit-vcs commit -m "..." --owner qoder:s1 --sign-key ~/.trit/keys/author.key
trit-vcs claims add --central ./central --id c1 --owner qoder:s1 --path src --ttl 900 --sign-key ~/.trit/keys/author.key
trit-vcs claims release --central ./central --id c1 --owner qoder:s1 --sign-key ~/.trit/keys/author.key
trit-vcs policy set --owner qoder:s1 --require-signed-claims
trit-vcs policy set --owner qoder:s1 --require-signed-witness

# Witness 签名 sidecar（已落地；默认未签名兼容，严格策略/--signed 强制）
trit-vcs attest <提交id> --witness witness.json --key-file ~/.trit/keys/witness.key --owner qoder:s1 --json
trit-vcs admit <提交id> --witness witness.json --signed

# 独立外锚（已落地；公钥必须从仓外信任渠道钉住）
trit-vcs audit external-anchor --checkpoint <检查点事件 seq> --key-file external.key --anchor-public-key <仓外公钥hex> --out external-anchor.json --json
trit-vcs audit verify-external-anchor --anchor external-anchor.json --anchor-public-key <仓外公钥hex> --json
```

MCP 面保持 13 个工具，不新增独立 attestation/anchor 工具；`admit` 增加可选 `signed` 参数，审计查询仍走
`audit_status`、`audit_log`、`audit_verify`、`audit_prove`，外锚写入仍走 CLI，避免扩大智能体写审计账的面。

命令的失败必须是机器可读的 `kind`，例如：

- `journal_missing`
- `journal_truncated`
- `journal_broken`
- `head_mismatch`
- `ref_mismatch`
- `state_drift`
- `op_open`（warning：有 `op_begin` 没收口）
- `op_state_gap`（`op_begin.state_before` 接不上上一条 `state_after`）
- `event_state_gap`（带 `state_before` 的非 op 事件接不上上一条 `state_after`）
- `op_result_unknown` / `op_result_mismatch` / `op_result_bad`
- `op_failed_state_change`（操作标 failed，但 `state_after` 已经不等于动手前状态）
- `gate_bad`
- `auth_bad`（旧拒绝事件缺 reason/method/path 或 status 不是 401；schema 非空且不受支持；`trit-auth-v2` 缺合法 request id；放行缺 schema 或合法 actor；decision 不是 denied/allowed）
- `auth_no_state`（warning：`auth` 事件缺 `state_after`）
- `sync_bad`（版本化 publish/pull 的 schema/action/op id/transport/side/stage/request id/actor/name/commit/前后状态不合法）
- `sync_auth_missing`（中央 HTTP 成功同步之前没有同 request_id、actor、方法与路径的放行鉴权）
- `sync_duplicate`（同一 journal 内同侧复用 op id，跨 publish/pull 也算重复）
- `deny_bad`（`deny` 事件缺 action/reason/message 或 decision 不是 denied）
- `deny_no_state`（warning：`deny` 事件缺 `state_after`）
- `policy_bad`
- `policy_no_state`（warning：`policy` 事件缺 `state_after`）
- `key_bad`（`key` 事件缺 action/key_id/principal/role/session 或 `keystore_hash`）
- `key_no_state`（warning：`key` 事件缺 `state_after`）
- `key_rotation_mismatch`（rotate 的 old/new 指纹、双签、吊销时间、`rotated_from` 或信任表谱系对不上）
- `signature_bad`（`signature` 事件缺 commit/key_id/signature/signed_at_ms 或算法不是 ed25519）
- `signature_commit_missing`
- `signature_no_state`（warning：`signature` 事件缺 `state_before`/`state_after`）
- `signature_invalid`（信任表公钥验不过提交字节）
- `signer_untrusted`（key 不在信任表 / 无公钥 / 指纹不匹配）
- `signer_revoked`（签名时间晚于吊销时间；同毫秒按历史签名放过，避免同秒操作假红）
- `attestation_bad`（缺字段/算法/schema/operation/对象/事件绑定不合法）
- `attestation_revoked`（签名时间晚于吊销时间；同毫秒不追溯）
- `attestation_invalid`（Ed25519 验签或 commit/tree/base/witness 绑定失败）
- `attestation_duplicate`（同一 commit 出现重复 sidecar）
- `attestation_state_mismatch`（缺合法 `state_before`/`state_after`，或分别与 `op_begin`/`op_result` 对不上）
- `attestation_missing`（严格见证策略生效后的提交缺 witness，或带 witness 但没有 attestation）
- `claim_signature_bad`（缺字段/算法不是 ed25519/ClaimSpec 不合法）
- `claim_signature_missing`（当时策略要求签名但事件未签，或标记已签却在收口前缺 sidecar；缺字段的旧策略事件按关闭处理）
- `claim_signature_operation`（操作、claim 事件、action、成功收口、顺序或状态绑定对不上）
- `claim_signature_untrusted`（key 不在信任表 / 无公钥 / 指纹不匹配 / principal、owner、角色不匹配，或签名之前没有该 key 的 add/rotate 信任事件）
- `claim_signature_revoked`（签名时间晚于吊销时间；同毫秒不追溯）
- `claim_signature_invalid`（重建 `trit-claim-sign-v1` 声明后 Ed25519 验签失败）
- `checkpoint_bad`（checkpoint 缺 height/root/签名/key_id，或高度/序号不贴前缀）
- `checkpoint_head_mismatch`
- `checkpoint_merkle_mismatch`（重算前缀根对不上）
- `checkpoint_chain_mismatch`（previous 不是前缀里最后一条检查点）
- `checkpoint_signature_invalid`
- `checkpoint_untrusted`（签者不在信任表 / 无公钥 / 角色不是 auditor/release）
- `checkpoint_revoked`（签名时间晚于吊销时间）
- `checkpoint_no_state`（warning：缺 state_before/state_after）
- `checkpoint_state_change`（检查点标记不改状态，但两个摘要不同）
- `anchor_bad`（schema/事件类型/事件哈希/检查点字段不合法）
- `anchor_untrusted`（签者不在信任表 / 无公钥 / 指纹不匹配 / 角色不是 auditor/release）
- `anchor_revoked`（签名时间晚于吊销时间）
- `anchor_signature_invalid`（文件锚里的检查点签名验不过）
- `anchor_missing`（导出时指定的检查点事件不存在或不是 checkpoint）
- `anchor_ahead`（锚高超过当前日志，尾巴被删）
- `anchor_mismatch`（当前同高事件不是锚住的检查点）
- `anchor_consistency_failed`（旧锚无法作为较新检查点的一致前缀）
- `audit_consistency_failed`（size/root/坐标/证明复算不通过）
- `claim_snapshot_missing`
- `claim_snapshot_mismatch`
- `checkpoint_mismatch`
- `attestation_tree_mismatch`
- `remote_rollback`
- `remote_equivocation`
- `audit_bundle_incomplete`

每个 `kind` 都要有可执行的下一步，沿现有 `remediation` 风格，不要只报“验证失败”。

---

## 6. 分阶段落地

### P0：审计地基（必须先做）

**范围**

- `AuditEvent v2` 类型化 + schema 版本；
- 仓库级单写者锁 + `op_begin`/`op_result` 写前协议；
- 全操作覆盖：commit/ref/adopt/stage/claim/accept/merge/publish/pull/auth/policy/key/force/deny；
- `audit reconcile`：状态摘要 + 日志重放 + 不一致 kind；
- claim set 快照进提交；
- accept receipt 落对象 + 事件；
- `audit status/log/show/verify --json`。

**本轮已落地**：仓级 `journal.lock` 单写者链，以及认领/策略/信任/提交签名/检查点、普通仓库状态写、中央仓 publish/pull、merge 与独立审计事件共用的 `claims.lock` 状态锁（拿不到锁报 `state_locked`，提交预检与写入同锁，publish/pull 的快进检查到事件追加同锁，merge 从 `op_begin` 到 `op_result` 同锁）；`state_digest` + `audit status/verify/reconcile`；`op_begin/op_result` 写前协议（`stage`/`commit`/`set_ref`/`adopt`/`claim_*`/`policy`/`key`/`sign_commit`/`merge`/`checkpoint`）；提交门拒绝的 `gate` 事件；策略变更的 `policy` 事件；信任表 add/revoke/rotate 的 `key` 事件（rotate 要旧/新双签并核 `rotated_from`）；Ed25519 `key init`、`commit --sign-key` 与 `signature` 事件（审计用信任表公钥验签，签名是 sidecar，不改提交 id）；`claims add/release --sign-key`、库面 `add_signed/release_signed` 与 `claim_signature` 事件（绑定 action/op_begin/完整 ClaimSpec/前后状态/主体，审计复验顺序、成功收口、此前的 key add/rotate、信任、角色、吊销与签名）；`policy set --require-signed-claims`（默认关，历史未签名兼容）；合并的 `merge` 事件；服务端成功/失败鉴权的 `trit-auth-v2` 事件（服务端 actor + request id，响应回传同一 request id）；publish 业务/请求形状、服务端 pull 与本地 pull 业务拒绝的 `deny` 事件；全量 pull 在请求前检查脏工作树；`ClaimSet` 快照；`AcceptReceipt`；版本化 `publish`/`pull`/`accept` 事件（成功同步按 op id/request id 关联并核 side/stage/前置鉴权/同侧唯一性）；`audit log/show` 与 `--json`；`audit checkpoint` 的前缀 Merkle 根/`previous` 链/验签；`audit proof` 的严格单事件 inclusion proof；`audit consistency/verify-consistency` 的规范坐标旧→新前缀一致性证明；导出前核对当前前缀的 `audit anchor/verify-anchor` 与 `audit verify --anchor` 文件锚闭环；`audit` 对 `op_open` / `op_state_gap` / `event_state_gap` 的检查。

**仍未落地**：`AuditEvent v2` 类型化、请求来源地址、按用户验证的密码学 actor、跨机同一视图、完整 proof bundle。提交、认领变更与 witness 已有可选 Ed25519 sidecar 并由审计验签，密钥轮换有双签，检查点有仓内签名 Merkle v0、单事件 inclusion proof、检查点间 consistency proof v0、仓内文件锚 v0 与独立外锚 v1；但签名不进提交 id，认领签名不覆盖导出的 `ClaimSpec` 快照，receipt/handoff 证据链未闭合。仓内文件锚不是独立信任根；独立外锚只认调用方钉住的仓外公钥，实际独立性取决于外部私钥保管与部署，也不是 CA/透明日志/可信时间戳。只有旧锚时，无法证明从未见过的后续事件存在。`auth` 现已记录成功/失败的服务端 actor 与 request id，但 actor 来自 `serve --actor` 部署配置，未配置时记 `bearer:unidentified`；它不是每用户密码学身份，成功 `auth` 也不代表端点最终成功。`deny` 目前覆盖服务端 publish（含请求形状）、服务端 pull 和客户端 pull 应用回执时的业务拒绝。这也是为什么现在只能算 L2 首批、L3 机制部分落地，不能算 P0/P1 完成。

**完成定义**

- 删 journal、删尾、改中间、手改 ref、删对象、崩在两次写之间、10 进程并发写，7 类夹具全部按预期 kind 判红。
- 每个改状态的本地 CLI 路径都有 `op_begin` 和 `op_result`；提交门拒绝路径有 `gate` 事件；鉴权成功/失败都有带服务端 actor/request id 的 `auth` 事件，响应回传同一 request id；成功 publish/pull 有带 op id 的 `trit-sync-v1` 事件，HTTP 两侧另带同一 request id，中央事件能对上前置放行鉴权；服务端 publish（含请求形状）、服务端 pull 与本地 pull 的业务拒绝有 `deny` 事件；信任表 add/revoke/rotate 有 `key` 事件（rotate 双签并核谱系）；提交与已签认领变更分别有 `signature`/`claim_signature` 事件并由 `audit` 验签。仍缺来源地址与按用户验证的密码学 actor；中央 `response_sent` 不代表客户端应用成功，跨仓 journal 追加也没有原子事务。
- `audit reconcile` 在干净仓上零告警，在任意一类篡改上失败闭合。
- 验签只依赖本地 `ed25519-dalek` 和信任表，不依赖外部 CA/网络服务。

**这一步的产出不是“更强的加密”，而是“账能对上”。**

### P1：不可否认

**范围**

- Ed25519 key init（已落）、key rotate（已落：旧/新双签声明）；trust add/revoke 已落；
- commit 签名（已落，sidecar）；密钥轮换（已落，双签）；claim add/release 签名 v0（已落，sidecar，可选策略强制）；witness attestation 签名 v1（已落，sidecar，默认兼容/严格策略强制）；checkpoint 签名 v0 已落；
- Merkle 检查点 v0 已落（仓内前缀根 + `previous` 链 + 单事件 inclusion proof）；检查点间 consistency proof v0 已落；
- 仓内文件锚 v0 已落（导出/复验完整检查点事件、同高事件核对、旧→新一致性）；独立外锚 v1 已落（调用方钉住仓外公钥，验锚不读仓内信任表）；central 锚与 HTTP 时间戳/OpenTimestamps/RFC3161 未落；
- `audit prove/verify-proof/anchor` 中 `anchor` 已落，独立 proof bundle 未落；
- `audit verify --anchor` 已支持旧检查点到较新检查点的一致性。

**完成定义**

- 换提交内容、换认领字段/操作/状态、换 witness 退出码、换检查点、换签名者、吊销密钥、旧钥签新钥，逐项判红。
- 旧锚在 10 万条新事件后仍能验；旧→新 consistency proof 通过；保留较新锚时删尾会红。只有旧锚时，较短但一致的前缀仍是合法扩展，不能据此断言从未见过的后续事件存在。
- 签名域分离有测试；跨协议重放失败。
- 私钥不进入 argv、不进入日志；权限/密钥文件有明确边界。

### P2：证据闭环

**范围**

- witness 签名 attestation 已落；仍缺环境/材料/产物摘要与 DSSE 兼容 envelope；
- `admit --signed` 已核签名、信任、树/父树与退出码；环境/材料/策略扩展仍未落；
- handoff 包携带 witness/accept receipt/签名/证明；
- Git 桥显式标记 `provenance: lossy`，保留原 SHA 映射；能导入作者签名摘要就导入，不能就如实标缺；
- 证据查询：按 commit/路径/actor 反查“当时的通过证明”。

**完成定义**

- 伪造 `exit=0`、换 stdout、换树、换执行者 key，全部判红。
- 离线 handoff 包不接仓库也能验：commit → tree → diff → claim set → witness → receipt → 签名。
- Git 导入的提交在 `audit show` 中明确显示 `provenance_lossy: ["merge_graph","author_signature"]`，不假装完整。

### P3：跨机透明

**范围**

- 中央仓审计账本：publish/pull/auth/ref/force 全记；
- 每 actor 独立 token（或签名 challenge），token 轮换/吊销进审计；
- 客户端记录每个 remote/ref 的 last-seen checkpoint；
- 服务端提供 `checkpoint`/`proof`/`consistency` 接口；
- 受保护 ref 支持 N 个独立 cosigner（注意：这里的 cosigner 不是现有 `witness` 测试见证）；
- 服务端回滚、分裂视图、静默改写 ref 的告警。

**完成定义**

- 服务端返回旧检查点 → 客户端 `remote_rollback`。
- 同一 ref 两个不同检查点 → `remote_equivocation`，并给出两边 root/size。
- 鉴权失败有事件（actor 可未知，request id 已与响应关联；来源地址与每用户密码学身份仍未落地）。
- 本地 `publish`/`pull` 两侧事件能用 `op_id` 对上；HTTP 还用 `request_id` 关联响应、鉴权与中央事件。

### P4：运营与体验

- `audit blame`：按路径/行追到提交、认领、证据、签名者；
- 审计时间线/告警/保留策略/归档；
- 日志脱敏与敏感等级；
- 增量验证索引，避免每次 `Journal::open` 全读；
- dashboard/CI 集成；
- GitHub 桥的审计锚：每天/每次发布把检查点根写进一个专用 ref，作为外部锚；不追求每条事件都上传。

---

## 7. 验收矩阵：红队先写，功能后写

| 编号 | 攻击/故障 | 期望 kind | 由哪期覆盖 |
|---|---|---|---|
| R1 | 删掉整个 `journal.jsonl` | `journal_missing` / `state_drift` | P0 |
| R2 | 删最后 N 条事件并重算链 | `journal_truncated` / `checkpoint_mismatch` | P1 |
| R3 | 改中间一条事件并重算后面 | `checkpoint_mismatch` / `proof_invalid` | P1 |
| R4 | 用旧的有效链替换整条 | `anchor_consistency_failed` | P1 |
| R5 | 手改 `.tritvcs/refs/main` | `state_drift` | P0 |
| R6 | 删一个被引用的对象 | `object_missing` | P0 |
| R7 | 伪造 `session=qoder:s1` 的提交 | `signer_untrusted` / `signature_missing` | P1 |
| R8 | 把 witness 的 `exit` 改成 0 | `attestation_invalid` / `attestation_bad` | P1，**v1 已落** |
| R9 | 提交后改 claim 账本，缩小/删除原认领 | `claim_snapshot_mismatch` | P0 |
| R10 | 服务端把 ref 回滚到旧提交 | `remote_rollback` | P3 |
| R11 | 服务端对不同客户端返回不同历史 | `remote_equivocation` | P3 |
| R12 | 鉴权失败但服务端不留痕 | 单测断言 `auth` 事件存在；`auth_event_missing` 尚未做成审计 kind | P3 |
| R13 | 崩在 ref 写入与事件追加之间 | `dangling_state` | P0 |
| R14 | 10 个进程同时 commit | 链完整、事件不丢、seq 不重 | P0 |
| R15 | 10 万事件后验一个老事件 | inclusion proof 通过，旧锚仍成立 | P1 |
| R16 | 换认领字段/操作/状态、删 sidecar、绕过强制策略、重放 sidecar、伪造授权、吊销后签名、删掉此前的 key add/rotate | `claim_signature_bad` / `claim_signature_missing` / `claim_signature_operation` / `claim_signature_untrusted` / `claim_signature_revoked` / `claim_signature_invalid` | P1，**v0 已落** |
| R17 | 改 attestation 的 commit/tree/base/key/session/签名，或重复/跨提交重放 sidecar | `attestation_bad` / `attestation_invalid` / `attestation_duplicate` | P1，**v1 已落** |
| R18 | 用错外部公钥、改外锚摘要、删尾、换链或伪造较新检查点 | `anchor_untrusted` / `anchor_signature_invalid` / `anchor_mismatch` / `anchor_ahead` / `anchor_consistency_failed` | P1，**v1 已落** |

每条红队夹具都要进 `tests/`，并在 `scripts/mutants/trit-vcs.json` 登记“关掉对应检查后测试必须变红”。没有变异条目的审计控制，不算控制。

---

## 8. 性能与成本目标

下面是**目标值，不是已达成读数**；实施后必须用 benchmark 填实测，再写进 README。没有实测前不许写“更快/更强”。

| 指标 | 目标 |
|---|---|
| 事件追加 p99（含 fsync） | ≤ 5 ms，本机 SSD |
| `audit verify --quick` 10 万事件 | ≤ 1 s（不碰对象内容） |
| `audit verify --deep` 10 万事件 | ≤ 10 s（含对象 fsck 与证据） |
| 单条 inclusion proof | ≤ 1 KB（1 万–100 万事件量级） |
| 证明验证 | ≤ 2 ms/条 |
| 检查点生成 | 10 万事件 ≤ 200 ms |
| 审计日志体积 | 典型提交的日志增量中位数 ≤ 2 KB；压缩后 ≤ 对象库的 1% |
| 打开仓库 | 不再全量读 journal；有检查点缓存/增量索引 |

审计不能靠“每次都全量扫”赢。全量扫是正确性基线；增量验证才是产品能力。

---

## 9. 和现有工具比，强在哪、不强在哪

| 能力 | Git | GitHub/GitLab | in-toto/SLSA + Sigstore/Rekor | trit 现在 | trit 目标 |
|---|---|---|---|---|---|
| 提交身份签名 | GPG/SSH 可选，默认不强制 | 平台账号，不绑定提交字节 | 制品签名强，不管 VCS 提交 | 可选 Ed25519 sidecar，策略尚未强制 | 策略可强制，commit 自包含签名 |
| 操作日志 | reflog 本地、可改写、会过期 | 服务端审计日志，平台私有 | 无 VCS 操作日志 | 本仓哈希链，`op_begin/op_result` + gate | 全操作 + 拒绝事件 + 可重放 |
| 截断/换链检测 | 无 | 依赖服务端 | Rekor 透明日志强 | 链内能查，仓内检查点 + 文件锚 v0 | Merkle 检查点 + 独立锚 + 一致性证明 |
| 授权/认领快照 | 无 | 分支保护/审批，不绑定内容 | 策略在 CI，不绑 VCS | 认领门 + ClaimSet 快照 + 已签账本变更 | ClaimSet 签名 + 事后复核 |
| 证据绑定 | notes/CI 外挂 | checks 外挂 | in-toto 强，需外部系统 | witness 绑树，可选签名 attestation | 签名 attestation + 环境/材料 + 离线 |
| 跨仓一致视图 | 无 | 平台内 | Rekor 可审计 | 客户端/中央两本账 | 中央账本 + 客户端 pin + 分裂检测 |
| 离线第三方验证 | 只能看对象 | 不行 | 部分，依赖 Rekor 数据 | 手工验对象 | 单文件 audit bundle，零网络 |
| 查询/解释 | log/blame | UI 强，不可导出证明 | 工具链分裂 | `audit status/log/show`，机器可读 | audit log/show/prove，机器可读 |

**要诚实：**

- Git 的 commit signing 比我们现在的“可选 sidecar、未强制”强；GitHub 的服务端审计日志比我们现在的“本地一条链”强；Rekor 的公开透明日志比我们现在的“仓内文件锚 + 可选独立外锚”强。独立外锚只解决“验证不读仓内信任表”，不提供公共透明日志、独立时间戳或外部密钥托管。
- 我们不是要在每一项上超过它们；我们要在一个它们没有的位置上赢：**VCS 内建、授权/证据/历史/状态同图、离线可复算**。
- 如果只做签名不做对账，我们只是“给 Git 补一个签名”，没有结构性优势。

---

## 10. 不做什么 / 诚实边界

1. **不把 BLAKE3 当签名。** 哈希链证明“内容没变”，不证明“谁做的”。
2. **不把 `session` 当身份。** 字符串谁都能填；身份必须来自密钥和 trust store。
3. **不把日志当备份。** 日志是审计面，不是对象库的副本；对象丢了要能发现，不是靠日志恢复。
4. **不在明文 HTTP 上分发私钥/token。** 网络 v0 只绑回环或套 SSH/反代；签名密钥不上网。
5. **不追求每个读操作都上链。** 读操作不改变状态，全记会淹没真正的变更；只记安全相关的读取（如导出审计包）可选。
6. **不承诺抵抗 root/内核级攻击。** 如果攻击者能改内核、内存和所有锚，任何本地审计都有限；目标是在“文件可被改、服务端可能不诚实”的威胁模型下可发现。
7. **不承诺“所有维度世界第一”。** 只承诺可复算的维度：完整性、授权快照、证据绑定、对账、离线证明、跨机一致。
8. **不引入必需的外部 SaaS。** 外部锚/时间戳是可选增强；核心审计必须能离线跑。
9. **不让审计日志泄露秘密。** 日志/证据要脱敏、可保留、可删除敏感字段；删除本身也要留审计事件（只记摘要，不记内容）。

---

## 11. 如果现在只动一次手，先做哪五件事

按依赖顺序，不要并行堆功能：

1. **`Journal` 加锁 + `op_begin/op_result` 写前协议**，先把并发/崩溃撕裂堵住。
2. **`audit reconcile` + 状态摘要**，让 `verify` 能回答“日志是否解释了当前状态”。
3. **全操作事件覆盖 + 拒绝事件**，把 gate/accept/publish/pull/auth/policy/key/signature/attestation/checkpoint/force 都记账；`auth`、publish（含请求形状）、服务端 pull 与本地 pull 的 `deny` 已落；成功/失败鉴权绑定服务端 actor 与响应 request id，成功 publish/pull 另用 `trit-sync-v1` 绑定 op id、HTTP request id、side/stage 与前后状态；信任表 add/revoke/rotate 的 `key`、提交 `signature`、认领变更 `claim_signature`、witness `attestation`、仓内 `checkpoint`、单事件 `audit proof`、检查点间 consistency proof、仓内文件锚与独立外锚已落；force 仍未单独成事件。
4. **ClaimSet 快照 + accept receipt 落对象**，让授权和证据事后可复核。
5. **`audit status/log/show/verify --json`**，把审计从内部 JSONL 变成可用的产品面。

这五件的地基已经落地；Ed25519、Merkle、仓内文件锚与独立外锚也已接上，剩下的是跨机透明、完整审计包与外部密钥的独立运营。

---

## 12. 第三方从 GitHub 来：默认路径不是读文档

### 12.1 先承认现实

第三方从 GitHub 认识你、从 GitHub 下载，默认会看：

- README 首屏；
- Releases 里的资产和 release note；
- 代码树、commit 列表、CI 状态；
- 安装/运行命令。

他**不会**默认点进 `docs/AUDIT-STRENGTH.md`，也不会为了验一个下载先装 Rust 工具链。更关键的是：本仓 `.tritvcs/` 在 `.gitignore` 里，所以 GitHub 的 clone / source zip **天然没有 journal、检查点和审计包**。第三方从 GitHub 下到的只是源码 + Git 历史；不附 audit bundle，他就算想验也无从验。

所以要把两个角色分开：

> **GitHub 是分发层和社交层，不是信任根。**
> 它负责“让人找到你、下载你”，不负责“证明这份下载没被换过”。

审计证明必须跟下载物一起走，不能藏在文档里。

### 12.2 三类第三方，三种入口

| 对象 | 他真正想要的 | 默认入口 | 证明强度 |
|---|---|---|---|
| 普通下载者 | 下到的不是被换过的恶意包 | Release 资产里的 checksum + 签名 + 一条验证命令 | 完整性、来源 |
| 安全审计员 | 历史、授权、证据、状态都能复算 | `audit.tvab` 离线包 + `AUDIT.txt` + 深度文档 | 全链证明 |
| 合作者 / 智能体 | 自动判断能不能接 | CLI/MCP 的 `audit verify`，失败给 kind | 可编程 |

不要把三类人塞进同一份长文档。长文档给审计员；普通下载者只该看到**一行状态 + 一条命令 + 一个预期输出**。

### 12.3 三层入口：10 秒、1 分钟、深度

#### 10 秒：README 首屏

README 第一屏放一个固定区块，不写原理，只写“是什么、怎么验、验完看到什么”。示例（数字和指纹在发布时填，不是现在写死）：

```text
审计状态：L3 · 检查点 #1234 · root blake3:...
签名公钥指纹：ed25519:...
本 Release 审计包：trit-vcs-0.12.0.audit.tvab
验证（不需要 clone，不需要联网）：
  trit-audit-verify trit-vcs-0.12.0.audit.tvab --trust trit-vcs-release.pub
预期最后一行：
  audit ok: 1 checkpoint, 1234 events, 0 warnings
```

要点：

- 命令必须**可复制运行**，不能是“参见文档”；
- 预期输出必须写死到可对照，不能只说“会通过”；
- 验证器要能独立分发：一个静态二进制，或 `trit-vcs` 自带子命令；不能让第三方先装 Rust；
- 首屏只放这一块，深度内容放后面链接。

#### 1 分钟：Release 资产

每个 GitHub Release 至少附：

| 资产 | 作用 |
|---|---|
| `trit-vcs-<ver>-src.tar.zst` | 从 tagged commit 构建的自定义源码包，不是 GitHub 自动生成的 zip |
| `trit-vcs-<ver>.audit.tvab` | 审计包：事件、检查点、inclusion/consistency proof、公钥、策略、必要对象、manifest |
| `trit-vcs-<ver>.audit.tvab.sig` | 对审计包的分离签名 |
| `SHA256SUMS` / `BLAKE3SUMS` | 所有资产的摘要 |
| `SHA256SUMS.sig` | 对摘要清单的签名 |
| `AUDIT.txt` | 一页纸：证明什么、不证明什么、怎么验、预期输出、密钥指纹 |
| `trit-audit-verify` | 独立验证器（Windows/Linux/macOS），不依赖仓库和网络 |

`AUDIT.txt` 不是 README 的复制品，它只回答四个问题：

1. 这份包绑定了哪个 commit/tree；
2. 哪个 key 签的，指纹是什么；
3. 运行哪条命令，预期看到什么；
4. 它**不**证明什么（例如：不证明构建机没被 root、不证明作者主观意图）。

#### 深度：`docs/AUDIT-STRENGTH.md`

这份文档是给审计员、贡献者和未来的自己看的，不是默认入口。它负责解释威胁模型、格式、阶段和验收，不负责让普通下载者“第一眼就信”。

### 12.4 Release 发布流程：没有审计包就不发布

把审计变成发布闸门，而不是发布后的说明：

1. **打签名 tag**：tag 指向的 commit 必须有签名；CI 先验 tag 签名。
2. **跑 `audit verify --deep`**：日志对账、对象闭包、claim 快照、witness/accept receipt、策略全部过。
3. **生成 `audit.tvab`**：包含发布 commit 的 inclusion proof、最近检查点、旧→新 consistency proof、信任根、策略、必要对象。
4. **签 bundle 和 checksums**：release key 只签“发布物摘要”，不签任意用户内容。
5. **生成 `AUDIT.txt`**：填入 tree_size、root、key fingerprint、验证命令、预期输出、边界。
6. **上传到 GitHub Release**：release body 里重复 10 秒区块；不要只把链接丢在 docs。
7. **CI 反向验证**：下载刚上传的资产，按 README 里的命令原样跑一遍；不通过就不发布。README 的命令和资产必须由同一条流水线生成，防止文档腐烂。
8. **可选外部锚**：如果平台有 immutable release / artifact attestation，打开它；再把检查点 root 发到 OpenTimestamps / Rekor / 专用 audit ref。外部锚是加分项，不是根。
9. **记录失败**：发布验证失败也要留审计事件；不要“删掉这次发布假装没发生”。

没有第 7 步，README 里的命令迟早会失效；没有第 2 步，Release 里的包只是“看起来有审计”。

### 12.5 信任根不在 GitHub 账号

第三方“从 GitHub 认识你”是**社交信任**，不是密码学信任。GitHub 账号被盗、repo 被改、release 资产被替换，都是现实威胁。

因此：

- 公钥指纹要出现在**至少两个独立通道**：README/Release、个人站点/域名、签名邮件、会议 slides、社交 profile。第三方只要从其中一个通道核对过指纹，后面的签名链就能接上。
- 第一次下载只能 TOFU（首次使用即信任）：包里有 key，后续 release 必须由同一 key 或旧钥签名的 rotation statement 接续。TOFU 不能防“第一次就拿到假包”，只能防“之后被悄悄换”。
- 密钥轮换必须是**旧钥签新钥**的明确 statement；吊销要能离线查。
- GitHub 的 star/fork/verified badge 是平台信号，不是审计证明；不要在文案里混为一谈。

一句话：

> 账号是“认识你”的入口，指纹是“验证你”的根。
> 前者可以被盗，后者必须能离线核对。

### 12.6 如果他仍然不验

不能强制任何人验证。能做的是把“默认路径”改掉：

- 安装脚本/包管理器在安装前校验 checksum + 签名；**不要**用 `curl | sh` 这种先执行后验证的形态；
- Release body 第一行就是审计状态和验证命令；
- CI 把 `audit verify` 做成可见的 check；失败时 release 不存在；
- 下载页明确写“不验证也能跑，但等于只信任 GitHub 账号”；
- 对高价值发布，提供**可复现构建**和独立验证器，让“不装 Rust”不再是借口。

审计只对愿意验的人有用；产品设计要做的是把“愿意验”的成本降到一条命令，把“不验”的风险说清楚。剩下的，不能靠文档解决。

---

一句话收束：

> 先把账记全、把账对上；再盖章、再放到别人手里。
> 这样“审计强”才是可复算的事实，不是一句宣传语。
