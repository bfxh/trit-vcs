# trit-vcs 审计强度路线图

> 状态：P0 首批已落地（L2 对账、认领快照、判据回执）；签名 / Merkle / 仓外锚尚未实现
> 日期：2026-11-24  
> 目标：审计面做到“第三方可以离线复算”，不是“再加一条日志”  
> 一句话：现在有**链**、有**对账**，但还没有**签名锚**；有**认领**、有**授权快照**；有 `verify`、也有 `audit`。下一步不是把日志写长，而是把剩余操作补全、把链签死。

## 0. 先给结论

### 0.1 当前真实水平：L1 局部，不是“审计强”

按审计能力分五级：

| 级别 | 定义 | 当前 |
|---|---|---|
| L0 | 有日志，能看发生过什么 | 有 |
| L1 | 链内改一条会被发现 | 有，但只能防中间改写；删尾巴、换整条链仍要靠检查点/锚 |
| L2 | 日志能重放成当前状态，漏账/假账会被抓 | **已实现首批**：`audit status/verify/reconcile` 对账 HEAD/refs/对象/claim_set/回执/state_digest；尚未覆盖所有会改状态的操作 |
| L3 | 每条关键事件能证明到签名检查点，检查点有仓外锚 | **没有** |
| L4 | 跨机同一视图，服务端回滚/分裂视图能被抓 | **没有** |

所以现在能说“有可对账的审计面”，还不能说“审计最强”。L2 的骨架已经能跑：删整本日志、手改 ref、状态漂移、回执/认领快照缺失都会红；但“所有操作都记账”和“链被整段替换”仍分别是 P0/P1 的未完成项。

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
| 状态摘要 | `Repo::state_digest` | HEAD + refs + index + policy 原始字节 + claims 原始字节，canonical JSON 后 BLAKE3；不把 journal 算进去，避免循环自证 |
| 单写者链 | `Journal::append` | `journal.lock` 跨进程锁；拿锁后按文件长度决定是否重读，避免两个进程拿同一个 `seq` |
| 写前协议 | `Repo::begin_operation` / `finish_operation` | 状态变更前先写 `op_begin`（含 `state_before`），写后写 `op_result`（含 `status`/`state_after`）；崩溃留下开放操作，`audit` 报 `op_open`/`op_state_gap` |
| 策略变更 | `trit-vcs policy set` / `Repo::set_policy` | 整份写入 `policy.json` 也走 `op_begin/op_result`；`policy` 事件记 `session`、两个开关、`policy_hash`、`state_before`/`state_after` |
| 授权快照 | `ClaimSet` 对象 + `Commit.claim_set` | 提交时按 path 覆盖集合生成不可变快照；`verify`/`audit` 校验对象存在且摘要对得上 |
| 判据回执 | `AcceptReceipt` 对象 + `accept` 事件 | 记录树、基线、session、认领 id、每条判据的 exit/超时/输出摘要/是否截断；回执摘要进链 |
| 操作事件 | `stage` / `commit` / `ref` / `adopt` / `claim_*` / `publish` / `pull` / `accept` / `gate` / `policy` / `merge` / `auth` | 带 `state_after` 的事件能被状态摘要校验；`publish` 记 `previous`/`forced`，`pull` 记 prefix/force，`gate` 记拒绝原因与 `state_before`/`state_after`，`policy` 记开关与策略摘要，`merge` 记两个输入/树/冲突数，`auth` 记被拒方法/路径/原因（不记 token） |
| 查询面 | `audit log` / `audit show` / `--json` | 审计员不必用眼睛翻 JSONL；`audit status --json` 可直接分支 |
| 坏日志容错 | `Repo::open_for_audit` | journal 是坏 JSON 时仍能打开审计入口，输出 `journal_broken`，而不是在 `Repo::open` 阶段只丢一句 IO 错 |
| 失败即非零 | `audit status` | 有 issue 时退出码 1；`--json` 仍输出结构化报告，便于 CI 消费 |

尚未完成、不能假装完成的：密钥/deny 事件、Ed25519 签名、Merkle 检查点、仓外锚、跨机 journal 互链。**这些没做完之前，L3 不能宣称。**

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
| 证据 | in-toto Statement 形状，绑定树摘要；`admit` 校验文件摘要/树/退出码 | `src/witness.rs` |
| 跨机 | Bearer token、收端重算 BLAKE3、只准快进 | `src/net` / `src/remote.rs` |
| 交接 | 包内 commit/tree/parents/intent/claims/diff/文件，逐项重算 | `src/handoff.rs` |

这些不是白做的。问题在于它们是**七个分散的“面”**，还没有连成一条审计员能走的“链”。

### 2.2 结构性缺口

按优先级排，不按模块排。

| 编号 | 缺口 | 现状事实 | 会导致什么 | 优先级 |
|---|---|---|---|---|
| G1 | 日志不能解释状态 | `Repo::verify` 仍只统计事件数、跑对象 fsck、走第一父链；但 `audit status` 已比对 journal 与 refs/HEAD/claims/policy/state_digest | `verify` 单独跑仍可能绿；用 `audit` 才会抓删日志/手改 ref/漏记 commit | P0，**部分关闭** |
| G2 | 链可截断、可换整条 | 没有检查点、没有 Merkle 根、没有仓外锚；`verify` 只验当前文件 | 删最后 N 条并重算，或整链替换，仍验不出 | P0，未关闭 |
| G3 | 身份不可验证 | `session` 是自由字符串；提交/认领/见证都没有签名 | 谁都能自称 `qoder:s1`，伪造“谁做的” | P0，未关闭 |
| G4 | 操作覆盖不全 | 状态变更已走 `op_begin/op_result`（`stage`/`commit`/`ref`/`adopt`/`claim_*`），提交门拒绝落 `gate`，策略变更落 `policy`，合并落 `merge`，鉴权失败落 `auth`；仍缺密钥变更与 deny 事件 | 密钥轮换/吊销与显式 deny 仍可能不留账 | P0，**部分关闭** |
| G5 | 并发与崩溃会撕裂日志 | `Journal::append` 已有 `journal.lock` 单写者锁；关键状态变更前有 `op_begin.state_before`、后有 `op_result.state_after`；崩在中间会留下 `op_open` 或 `op_state_gap` | 锁住并发写；写前协议让“操作开始”有账，但仍不能阻止进程死在中间，只能让审计抓到 | P0，**部分关闭** |
| G6 | 授权不可事后复核 | 已落 `ClaimSet` 不可变快照，claim 事件补 `path_list`；账本 TTL 过后原条目仍会消失 | 快照能证明当时授权；账本原始条目仍需归档策略 | P0，**部分关闭** |
| G7 | 证据不可验证 | witness 不签名；`accept` 结果已落 `AcceptReceipt` 对象/事件；handoff 仍不携带 witness/accept | 回执可复核“跑了什么”，但回执本身没签名，仍可被替换 | P1，**部分关闭** |
| G8 | 跨机没有同一视图 | 客户端 journal 与中央仓 journal 是两本账；`publish`/`pull` 已有事件但两本账不互链；单 token 无 actor 身份；ref 是普通文件 | 服务端可回滚/改写 ref 和账本；客户端没有 pin，发现不了第二个历史 | P1，未关闭 |
| G9 | 时间与策略变更不可信 | HLC 只给本地全序；ref/stage 用墙钟毫秒；`policy set` 已有事件与状态对账，但 `policy.json` 仍可被直接改，且无签名 | 可回填时间；绕过 CLI 直接改策略仍只能靠 `state_digest` 漂移/接续抓到，不能证明谁改的 | P1，**部分关闭** |
| G10 | 没有审计查询/证明入口 | `audit status/log/show/verify/reconcile` 已可用；仍没有 inclusion proof / bundle | 审计员能查账，但还不能给第三方数学证明 | P2，**部分关闭** |
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
   **现在**：新 `claim_add` 事件已补 `path_list`，提交落 `ClaimSet` 对象；旧事件仍只能按语义对账，不能补出路径。

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
| audit bundle | 第三方离线复核上述全部 | 事件 + 证明 + 公钥 + 策略 + 必要对象 |

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

`witness` 从“未签名 Statement”升级为“签名 attestation”：

- 保留 in-toto Statement 的 `subject`/`predicate` 形状；
- 外面包一层 DSSE 兼容 envelope，或新增 `signatures` 字段；签名覆盖 canonical payload；
- predicate 增加：`tool`、`rustc`、`target`、`os`、`features`、`env_allowlist`、`materials`（依赖锁文件摘要）、`products`（构建产物摘要）；
- `accept` 的每条命令结果落成 `AcceptReceipt` 对象：argv、exit、stdout/stderr 摘要、耗时、超时、截断、执行者 key、仓库状态前后摘要；
- `admit` 在严格策略下必须验：签名 → 信任链 → 树绑定 → 退出码 → 环境/材料 → 策略。

没有签名的 witness 只能叫“证据草稿”，不能叫“通过证明”。

### 4.5 检查点与证明

```json
{
  "schema": 2,
  "tree_size": 1234,
  "root": "blake3:...",
  "prev_checkpoint": "blake3:...",
  "created_at": 1760000000000,
  "signatures": [
    { "key_id": "ed25519:...", "alg": "ed25519", "sig": "..." }
  ]
}
```

- 叶子：`BLAKE3("trit/audit/leaf" || event.hash)`
- 节点：`BLAKE3("trit/audit/node" || left || right)`
- 空树根固定；奇数节点按 RFC 6962 方式上提。
- inclusion/consistency proof 都带 `from_size`/`to_size`/`root`，验证器只信公钥和锚，不信服务端自报。

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

策略文件整体签名；每次变更产生 `policy_change` 事件，带旧/新摘要和签名者。默认全关的旧行为保留，逐项目 opt-in。

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

# 给第三方 proof
trit-vcs audit prove --event 42 --out event-42.proof.json
trit-vcs audit verify-proof event-42.proof.json --trust ./trust.json

# 打检查点 / 放锚
trit-vcs audit checkpoint --sign ~/.trit/keys/audit.ed25519 --out checkpoint.json
trit-vcs audit anchor --checkpoint checkpoint.json --to central

# 离线包：不依赖仓库、不依赖网络
trit-vcs audit bundle --out repo.audit.tvab --trust ./trust.json
trit-vcs audit verify-bundle repo.audit.tvab --offline

# 身份
trit-vcs key init --algorithm ed25519 --out ~/.trit/keys/audit.ed25519
trit-vcs key trust --key ./audit.pub --principal qoder:s1 --role author
trit-vcs key rotate --old ... --new ... --statement rotation.json
trit-vcs key revoke --key ... --reason "..."
```

MCP 面只暴露只读审计工具：`audit_status`、`audit_log`、`audit_verify`、`audit_prove`；写操作仍走 CLI，避免智能体一上来就改审计账。

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
- `auth_bad`（`auth` 事件不是 denied / 缺 reason、method、path / status 不是 401）
- `auth_no_state`（warning：`auth` 事件缺 `state_after`）
- `policy_bad`
- `policy_no_state`（warning：`policy` 事件缺 `state_after`）
- `claim_snapshot_missing`
- `claim_snapshot_mismatch`
- `checkpoint_mismatch`
- `anchor_missing`
- `signature_invalid`
- `signer_untrusted`
- `signer_revoked`
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

**本轮已落地**：仓级 `journal.lock` 单写者锁；`state_digest` + `audit status/verify/reconcile`；`op_begin/op_result` 写前协议（`stage`/`commit`/`set_ref`/`adopt`/`claim_*`/`policy`/`merge`）；提交门拒绝的 `gate` 事件；策略变更的 `policy` 事件；合并的 `merge` 事件；服务端鉴权失败的 `auth` 事件；`ClaimSet` 快照；`AcceptReceipt`；`publish`/`pull`/`accept` 事件；`audit log/show` 与 `--json`；`audit` 对 `op_open` / `op_state_gap` / `event_state_gap` 的检查。

**仍未落地**：`AuditEvent v2` 类型化、key / deny 事件、签名与密钥审计。`auth` 事件目前有方法/路径/原因/401，但没有请求 id、来源地址和经过认证的 actor；这也是为什么现在只能算 L2 首批，不能算 P0 完成。

**完成定义**

- 删 journal、删尾、改中间、手改 ref、删对象、崩在两次写之间、10 进程并发写，7 类夹具全部按预期 kind 判红。
- 每个改状态的本地 CLI 路径都有 `op_begin` 和 `op_result`；提交门拒绝路径有 `gate` 事件；鉴权失败路径有 `auth` 事件，但缺请求 id/来源与已认证 actor。
- `audit reconcile` 在干净仓上零告警，在任意一类篡改上失败闭合。
- 不引入签名依赖也能先交付。

**这一步的产出不是“更强的加密”，而是“账能对上”。**

### P1：不可否认

**范围**

- Ed25519 key init/trust/rotate/revoke；
- commit/claim/checkpoint/attestation 签名；
- Merkle 检查点 + inclusion/consistency proof；
- 仓外锚：central 锚 + 可选外部锚（文件/HTTP 时间戳/OpenTimestamps/RFC3161，做成插件，不做硬依赖）；
- `audit prove/verify-proof/anchor`；
- `audit verify --anchor` 支持旧检查点一致性。

**完成定义**

- 换提交内容、换 witness 退出码、换检查点、换签名者、吊销密钥、旧钥签新钥，逐项判红。
- 旧锚在 10 万条新事件后仍能验；旧→新 consistency proof 通过；删尾被旧锚抓。
- 签名域分离有测试；跨协议重放失败。
- 私钥不进入 argv、不进入日志；权限/密钥文件有明确边界。

### P2：证据闭环

**范围**

- witness v1：DSSE 兼容签名 + 环境/材料/产物；
- `admit` 严格模式：签名、信任、树、退出码、环境、策略全过才收；
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
- 鉴权失败有事件（actor 可未知，但请求 id/来源/结果必须有）。
- `publish` 的本地事件与中央事件能用 `op_id` 对上。

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
| R8 | 把 witness 的 `exit` 改成 0 | `signature_invalid` / `attestation_mismatch` | P1 |
| R9 | 提交后改 claim 账本，缩小/删除原认领 | `claim_snapshot_mismatch` | P0 |
| R10 | 服务端把 ref 回滚到旧提交 | `remote_rollback` | P3 |
| R11 | 服务端对不同客户端返回不同历史 | `remote_equivocation` | P3 |
| R12 | 鉴权失败但服务端不留痕 | 单测断言 `auth` 事件存在；`auth_event_missing` 尚未做成审计 kind | P3 |
| R13 | 崩在 ref 写入与事件追加之间 | `dangling_state` | P0 |
| R14 | 10 个进程同时 commit | 链完整、事件不丢、seq 不重 | P0 |
| R15 | 10 万事件后验一个老事件 | inclusion proof 通过，旧锚仍成立 | P1 |

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
| 提交身份签名 | GPG/SSH 可选，默认不强制 | 平台账号，不绑定提交字节 | 制品签名强，不管 VCS 提交 | 无 | 策略可强制，commit 自包含签名 |
| 操作日志 | reflog 本地、可改写、会过期 | 服务端审计日志，平台私有 | 无 VCS 操作日志 | 本仓哈希链，`op_begin/op_result` + gate | 全操作 + 拒绝事件 + 可重放 |
| 截断/换链检测 | 无 | 依赖服务端 | Rekor 透明日志强 | 链内能查，链外不能 | Merkle 检查点 + 锚 + 一致性证明 |
| 授权/认领快照 | 无 | 分支保护/审批，不绑定内容 | 策略在 CI，不绑 VCS | 认领门，commit 只存 id | ClaimSet 对象 + 签名 + 事后复核 |
| 证据绑定 | notes/CI 外挂 | checks 外挂 | in-toto 强，需外部系统 | witness 绑树但不签名 | 签名 attestation + 环境/材料 + 离线 |
| 跨仓一致视图 | 无 | 平台内 | Rekor 可审计 | 客户端/中央两本账 | 中央账本 + 客户端 pin + 分裂检测 |
| 离线第三方验证 | 只能看对象 | 不行 | 部分，依赖 Rekor 数据 | 手工验对象 | 单文件 audit bundle，零网络 |
| 查询/解释 | log/blame | UI 强，不可导出证明 | 工具链分裂 | `audit status/log/show`，机器可读 | audit log/show/prove，机器可读 |

**要诚实：**

- Git 的 commit signing 比我们现在的“无签名”强；GitHub 的服务端审计日志比我们现在的“本地一条链”强；Rekor 的公开透明日志比我们现在的“无锚”强。
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
3. **全操作事件覆盖 + 拒绝事件**，把 gate/accept/publish/pull/auth/policy/key/force 都记账；`auth` 已落失败事件，key/deny 仍待补。
4. **ClaimSet 快照 + accept receipt 落对象**，让授权和证据事后可复核。
5. **`audit status/log/show/verify --json`**，把审计从内部 JSONL 变成可用的产品面。

这五件做完，才轮到 Ed25519、Merkle、锚、跨机透明。

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
