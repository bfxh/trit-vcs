# trit-vcs

内容寻址的协作版本库：BLAKE3 逐块寻址 + 内容定义分块 + 打包压缩 + 哈希链事件日志，
外加 Git 没有的那一面 —— **写之前先判**（认领门）、**判了就把解锁命令一起给你**、**每次 ref 移动都进哈希链**。

定位是"替代 Git 的候选"，不是 Git 的兼容层。`Cargo.toml` 里 `publish = false` 且描述写明
**不属于稳定 API**：接口还在动，别按发布库依赖它。

## 逐维度的账

下表每个读数都能用本节末尾的命令复算。同机对照 `git`，除注明外均为 `--release`。
**没有读数的维度一律不写"更强"。**

| 维度 | 结论 | 读数 |
|---|---|---|
| 对象存储体积 | **认输** | 三形状 A `1.06×` / B（共享块）`2.29×` / C `1.02×`（×>1 就是比 git 大）；第一版每块一文件时 4.87×，靠打包+zlib 才追到现在这个位置 |
| 大仓 status | 更快 | 10k 文件热改动 **24–32 ms** vs git 34–35 ms（**0.7–0.9×**）；靠 `(size, mtime_ns)` 内容缓存 + 范围内 status |
| 部分拉取 | 更强 | 200 文件 / 20 目录：全量 publish **163,208 B / 403 对象**，单目录 pull **8,580 B ⇒ 5.26%**；重复 pull 实传 **0 B**（23 个对象全跳过） |
| 传输断点 | 更强 | 截断的包再导入续传，结果**逐字节相同**；导入跳过目标已有对象 |
| 合并产物 | 更强 | 300 行单点争用：结构化冲突对象 **381 B** vs 两侧全文 7,780 B ⇒ **4.90%**；只差行尾空白的"伪冲突"**0** 条 |
| 写前准入 | Git 无对应面 | 未认领的提交默认拒；认领有 TTL、同名 id 判红；判决是三态（True/Unknown/False），"不知道"不等于"过" |
| 被拒之后 | 更强 | 每条判决附**能直接跑的下一步命令**：`unclaimed` 负载 329→455 元（3 条命令）、`claim_conflict` 18→88 元、`witness_required` 26→73 元 |
| 预检成本 | 有读数 | 60 文件 / 121 对象 / 9,400 字节的预检 **4.8 ms**，**写盘 0 个对象**（对象数、哈希链长度、HEAD 三样分别断言） |
| 审计 | 有面，P0 首批已落地（L2 对账；缺口与路线见 [`docs/AUDIT-STRENGTH.md`](docs/AUDIT-STRENGTH.md)） | 关键状态变更前写 `op_begin`、后写 `op_result`（含 `state_before`/`state_after`），提交门拒绝落 `gate`，策略变更走 `policy set` 并落 `policy`，合并落 `merge`，服务端鉴权成功/失败落 `auth`，publish（含请求形状）、服务端 pull 与本地 pull 业务拒绝落 `deny`，信任表 add/revoke/rotate 落 `key`，`commit --sign-key` 落 `signature` 并由 `audit` 用信任表公钥验提交字节，`claims add/release --sign-key` 落 `claim_signature` 并复验操作/完整 ClaimSpec/前后状态/操作时点授权，审计按 `op_begin` 到 `op_result` 的日志顺序拒绝操作前吊销和操作中吊销/轮换，并核对 `op_result.state_after`；`trit-policy-v1/v2` 缺签名字段时 fail-closed，旧策略事件保持兼容，审计重放强制签名策略并检查 sidecar 缺失，`key rotate` 由旧/新两把钥双签声明并由 `audit` 复验，`audit checkpoint` 落签名 Merkle 检查点并复验前缀根/链，`audit consistency` 证明旧前缀是新根的前缀（1 万叶、旧前缀 4,321 叶的证明少于 64 个节点），`audit anchor` 导出可离线复验的仓内文件锚，`audit external-anchor/verify-external-anchor` 用调用方从仓外钉住的独立公钥签/验检查点与前缀摘要；`attest` 给已提交 witness 追加 Ed25519 sidecar，`admit --signed` 与 MCP `admit({signed:true})` 强制验签，策略 `require_signed_witness` 可要求新见证必须带 attestation；`trit-vcs audit status/verify` 把日志对账到 HEAD/refs/对象/认领快照/判据回执，漏账、状态漂移、开放操作会报；`git-import` / `git-export` 默认保留完整多父图，`--first-parent` 才线性化；两个方向都落 `git_bridge` v2 事件（action、成功/失败、first_parent、提交数、文件数、merge 数、元数据数、标签数、跳过的标签数、map digest）。`publish --force` 的非快进改写与 `pull --force` 成功应用后落独立 `force` 事件（`trit-force-v1`，绑定 op_id、previous、commit、reason，并核同 op_id/side 的同步事件与 `forced=true`）。`checkout --force` 放行并覆盖未提交改动时落独立 `checkout` 事件（`trit-checkout-v1`，绑定目标提交、前缀、脏改动数量/样本/完整摘要与前后状态，审计要求 `force=true`、`dirty>0` 且前后状态相等）。`log --all` / MCP `log({all:true})` 可看全图。成功 publish/pull 的 `trit-sync-v1` 事件按 op_id/request_id 跨仓关联并核阶段、前置鉴权与同侧唯一性；提交可带 `evidence`/`tags` |
| 时间 | 有面 | HLC（混合逻辑时钟）而非裸墙钟 |
| 上下文预算 | 有面 | `--budget <元>` 对所有读数生效：只丢整行、从尾部丢，`truncation` 元数据自己算进预算；ASCII 4 字 = 1 元、非 ASCII 4 元 |
| Git 生态 | 薄 | `git-export` / `git-import` 默认保留完整多父图，`--first-parent` 才线性化；保留作者/提交者/时间/父链元数据，并落 `git_bridge` v2 审计事件（map digest、merge 数、标签数、成功/失败）；标签名可往返（附注标签导出降级为轻量标签并记账），submodule 仍不搬，也不把 Git 签名信任映射进来 |

## 明确没做的（别当成已具备）

- **网络只有 v0：明文 HTTP、无 TLS、多 bearer token**。`serve` 只该绑回环；跨机请套 SSH 隧道或反代，
  鉴权只是"若干条 Bearer token"，每条可映射一个审计 actor；没有多租户隔离、没有按路径授权，也没有证书。
  服务端 token 文件逐行写 `<token> [actor]`，同一个 token 只出现一次；未逐行写 actor 的条目退回
  `serve --actor` 的全局身份，仍未配置时如实记 `bearer:unidentified`。成功与失败鉴权都落 `auth`
  事件，带服务端生成的 request id；客户端的 `X-Trit-Actor` 不被采信；响应通过 `X-Trit-Request-Id`
  回传同一关联号。鉴权与 HTTP 拒绝事件另记 `source`：TCP 对端 IP，不记临时端口、不采信
  `X-Forwarded-For`；反代部署时这里只是反代地址，旧事件可缺。带 `source` 的 HTTP `deny` 审计时还要
  对上前面同 `request_id` 的 `allowed` 鉴权，`source`/`actor` 必须一致；旧无 `source` 的拒绝事件不追溯。该 actor 是 bearer token 对应的部署配置，不是按用户验证的密码学身份；所有 token
  仍拥有同样的仓库读写权限。失败事件另记原因/401，成功事件不抢报端点最终状态；
  成功 publish/pull 另落 `trit-sync-v1`，用客户端 `op_id` 与服务端 `request_id` 关联源/中央/客户端事件；
  本地同步只有 `op_id`，HTTP 成功响应同时回传 `X-Trit-Request-Id` 与 `X-Trit-Op-Id`。
  token 与请求头不落账。publish 被业务规则拒绝或请求形状错误会落 `deny`（入口/原因/
  消息/请求细节，不记 token）；服务端 pull 缺 ref/未知 ref 也落 `deny`；客户端 pull 在应用回执时被拒
  （脏工作树、非快进等）也落本地 `deny`；全量 pull 在发请求前先检查工作树，脏就不下载对象；裸健康探针
  不记账，避免扫描器刷爆日志。
- **视图 pin 只覆盖单个客户端见过的历史**：能发现服务端回滚、同高换根、换掉已落账前缀；两个客户端
  各自没见过对方的 pin，所以互相之间的分裂视图仍要靠签名检查点/gossip/共享锚（未做）。
- **Git 桥已保真到多父图 + 元数据 + 标签名**：默认导入/导出完整 DAG，作者/提交者/时间/原始
  parents/签名状态写进提交证据，导出时恢复作者与时间；`--first-parent` 仍可显式降级。Git 标签
  名会作为证据导入并在导出时重建为轻量标签，附注标签的 message/签名不保留且计
  `annotated_tags_degraded`；Git 签名信任仍未映射，submodule 仍未搬。
- `pull` 全量时会把 HEAD 与索引落到被拉的提交；**带 `--prefix` 时不动 HEAD**（否则范围外会被算成删除），
  两种形态都不删本地多余文件。
- 认领账本放在**中央仓目录**里，多个工作树共享；但账本**没有走网络**：远程克隆仍要能读到同一个
  `--central` 目录，或 `claims export` 后把快照传给 `--claims FILE`。认领、策略、信任表、提交签名、
  检查点、普通仓库状态写（stage/commit/ref/adopt）、中央仓 publish/pull、merge、公开
  `append_audit`/`begin_operation`/`finish_operation` 和独立审计事件写入共用同一把 `claims.lock`，
  避免它们并发撕裂 `state_before`/`state_after` 或让检查点前缀与追加位置错开；拿不到锁明确报
  `state_locked`，不静默覆盖，也不教人删锁。
- v0 的 witness 本体仍保持 in-toto Statement 形状；默认准入不要求签名，以兼容旧仓。`attest` 可追加
  Ed25519 `attestation` sidecar，绑定提交 id、witness 摘要、树、实际第一父树、签者、会话与签名时间，
  不改变提交 id、对象格式或 bundle。`commit --sign-key` 的签名覆盖提交对象字节；`claims add/release --sign-key`
  同样以 sidecar 证明中央账本变更，但导出的 `claims.json` 仍只是未签名 `ClaimSpec` 数组。
  检查点已有仓内签名 v0、仓内文件锚 v0、检查点间 consistency proof 和独立外锚 v1；仓内文件锚只是
  调用方保管的已签检查点副本，**不是独立信任根**。独立外锚只认调用方从仓库外信任渠道钉住的公钥，
  不读仓内 `keys.json`；但实际独立性取决于外部私钥保管与部署，不能自动抵抗整机或同一管理域被攻陷。
  两者都不是透明日志、CA 或可信时间戳；签名里的 `signed_at_ms` 也是签名者自报时间，不能防刻意回填。
  认领签名授权按 `op_begin` 到 `op_result` 的事件顺序重建；见证签名允许同毫秒吊销不追溯，但拒绝签名早于
  签者加入信任表的时间。
- sparse 索引只记**一个前缀**（没有 git 的多前缀/cone 模式）；换范围就等于换一次前缀 checkout。
- 三值逻辑只用在裁决处：全仓 `src` 实测三值 **4.5%**、二值 2.2%、中性 93.4%（`scripts/parity_scan.py`）。

## 网络 v0（跨机 + 鉴权）

没有读数的维度不写"更强"：这一节只写**边界**和**怎么用**。协议是自写的 HTTP/1.1 子集
（`GET`/`POST`、`Content-Length`、一请求一连接、拒 `chunked`），不引 HTTP 框架，理由和
"对象格式自己写"一样——多一层框架就多一层"它的行为谁保证"。

```sh
# 服务端：tokens.txt 每行 `<token> [actor]`；空行与 # 注释忽略，最多 256 条
# 例：0123456789abcdef alice
#     fedcba9876543210 bob
trit-vcs serve --dir ./central --bind 127.0.0.1:7878 --actor qoder:fallback --token-file tokens.txt

# 客户端：只接受单 token 文件（可带 actor，但客户端不会用它覆盖服务端审计主体）
trit-vcs publish main --remote http://127.0.0.1:7878 --token-file token.txt
trit-vcs pull main --remote http://127.0.0.1:7878 --token-file token.txt
trit-vcs pull main --remote http://127.0.0.1:7878 --token-file token.txt --prefix gen/d00
```

- 每个成功解析的 HTTP 请求都有服务端生成的 64 位十六进制 request id；鉴权放行/拒绝事件与
  JSON/二进制响应通过 `X-Trit-Request-Id` 对上。放行事件的 actor 先取命中 token 行里的 actor，
  没有则退回 `serve --actor`（1–128 字节、无控制字符）；两者都没有时记 `bearer:unidentified`，
  不把客户端声明的身份当已认证主体。服务端对每条 token 都做常量时间比较且扫完整个表，再取命中
  条目的主体；客户端 token 文件含多条时直接拒绝，避免把服务端 token 表误当客户端凭据。
  publish/pull 的
  请求形状或业务拒绝详情也带 request id/actor。成功 publish/pull 落 `trit-sync-v1`：客户端生成
  恰好 64 个 ASCII 十六进制字符、不做首尾裁剪的 `op_id`，publish 用 `X-Trit-Op-Id` 头、pull 用查询参数发送，服务端在成功响应回传同一值，由客户端核对；
  source/central/client 各侧事件因此可按 `(op_id, request_id)` 关联，审计拒绝同侧重复 `op_id`、
  非法阶段组合，以及中央 HTTP 成功事件缺同 request_id 的前置放行鉴权。旧客户端不带 op id 仍被接受，
  由服务端补生成；旧的无版本 publish/pull 事件仍按历史语义审计。反向不兼容：新版客户端要求成功响应
  带这两个关联头，连接旧服务端会明确报响应关联字段缺失/不匹配，不会把无关联同步误报为成功。
- 同步闭包包含提交引用的 `claim_set`/`witness` 证据对象；pull 物化前检查证据齐全，缺对象即拒绝，
  不改冻结的提交或 bundle 格式。跨仓没有原子事务：中央 HTTP pull 的 `response_sent` 只证明响应体
  已写出，不证明客户端已应用；远端状态改变后本地 journal 追加失败，命令仍可能报失败。
- 服务端收发布时先逐块重算 BLAKE3 再入库，再查“tip 是提交、树闭包齐全、`merge_base(tip, current)==current`”，
  三条都过才移动 ref；退历史一律 409。快进检查与 ref/事件更新在同一把仓库状态锁内完成。
- 全量 `pull` 先判快进与暂存区脏，再物化，最后把 HEAD/索引落到被拉的提交；
  `--prefix` 只补范围内文件，不擅动 HEAD。快进检查、物化与 HEAD/索引/稀疏索引保存共用同一把状态锁。
- 上限：对象数 100 万、单对象 32 MiB、body 256 MiB（`--max-body-mb` 可调）、连接 8（`--max-conn`）、
  读写超时 30 s（`--read-timeout`），超限回 413/503 而不是把线程堆爆。
- 已知边界：401 会先排空 ≤1 MiB 的请求体再回（更大的 body 直接关，可能被 RST）；服务端 `shutdown`
  只停 accept，不等处理线程。

### 视图固定与回滚/改写检测（v0 客户端 pin + 可选服务端签名）

`serve` 另开只读 `GET /v1/view?ref=main`，回中央仓当前 journal 高度/头/Merkle 根与 ref tip。客户端每次
publish/pull 成功后把这次视图写进 `trit-sync-v1` 事件；下一次同步先用 `from_height`/`from_root` 要一条
旧前缀→新前缀的 consistency proof，验过才继续。服务端可用 `--view-key` 对视图做 Ed25519 签名：

```sh
trit-vcs serve --dir central --token-file token.txt --view-key server-key.json
trit-vcs view main --remote http://127.0.0.1:7878 --token-file token.txt --json
trit-vcs view main --remote http://127.0.0.1:7878 --token-file token.txt --expect-view-key ed25519:...
trit-vcs publish main --remote http://127.0.0.1:7878 --token-file token.txt
# 明确降级（旧服务端/排障）：不读也不写视图，也就没有回滚检测
trit-vcs pull main --remote http://127.0.0.1:7878 --token-file token.txt --no-pin
```

- 首次同步是 TOFU：没有旧 pin 可对，成功后落第一条视图与签名者；之后同 `(remote, ref)` 的高度只能不减，
  同高必须同根/同头，否则 `remote_equivocation`；服务端历史比 pin 短即 `remote_rollback`。
- 视图签名覆盖 `trit-view-sig-v1` 域内的 ref/高度/头/根/tip；客户端每次都用响应里的公钥复算，
  并把签名者写进 pin。已签名的 pin 再遇到无签名服务端报 `remote_view_unsigned`，换钥报
  `remote_signer_changed`；从无签名升级到签名是允许的单向收紧。
- 预检失败在发 publish / 收对象之前就返回，并落本地 `deny`；成功后视图与回执 tip 不一致报
  `remote_view_mismatch`。`--no-pin` 只留 `remote` 字段，审计把这类同步标成"有远端、无视图"。
- 视图签名证明"持有该私钥的人确认了这个视图"，不是可信时间戳，也不自动建立身份信任：第一次仍只能
  TOFU，公钥指纹要从独立渠道核对。跨客户端分裂视图/整链替换仍需签名检查点 + 外部锚/gossip，未做。

## Git 桥

`git-import` / `git-export` 默认保留**完整多父图**，不会再悄悄只搬第一父链；`--first-parent`
只在明确接受线性化时使用：

```sh
trit-vcs git-import ./some-git-repo
trit-vcs git-export ./some-git-repo
trit-vcs git-import ./some-git-repo --first-parent   # 显式降级为第一父链
```

导入按 `git rev-list --reverse --topo-order` 重建全部父，导出用 `git commit-tree -p` 复原 merge；
`log --all` 可按全图查看（默认 `log` 仍只走第一父链）。导入时把 Git 作者/提交者/时间/原始
parents/签名状态写进提交证据（`git-author:`、`git-committer:`、`git-author-at:`、`git-parents:`
等），导出时从这些证据恢复作者与提交时间。`refs/tags` 里指向提交的轻量/附注标签名也会写进证据
（`git-tag:` / `git-tag-annotated:`），导出时统一重建为轻量标签；附注标签的 message/签名丢失，
按 `annotated_tags_degraded` 显式记账，不假装保真。两个方向都落 `git_bridge` v2 事件，记录成功/失败、
`first_parent`、提交数、文件数、merge 数、元数据数、标签数、跳过的标签数和映射表摘要；失败的
import 也会留下失败事件。
Git 签名信任和 submodule 仍未搬；不在导入图里的标签不会凭空出现。

- 导出到**已有历史**的 Git 仓时，trit 根提交会挂到旧 HEAD 上以保留旧历史，根因此不再是真根；
  detached HEAD 会报错。
- 物化以 trit 提交树为准：树外文件会被删除，最后用 `reset --hard` 同步分支与工作树/索引。
  不要把含未提交或未跟踪文件的目录当导出目标；需要保留的内容先备份。

## 跨仓认领账本

认领写在中央仓里（`.tritvcs/claims.json`），多个工作树共享同一张表；每次变更都追加进中央仓的
哈希链（`claim_add` / `claim_release`），不是只改一个 JSON 文件。

```sh
trit-vcs claims add --central ./central --id c1 --owner qoder:s1 --path src --ttl 900
trit-vcs claims list --central ./central --json
trit-vcs claims release --central ./central --id c1 --owner qoder:s1
trit-vcs claims export --central ./central --out claims.json
trit-vcs commit -m "…" --owner qoder:s1 --claims ./central/.tritvcs/claims.json

# 可选：用中央仓信任表里的 author 钥签账本变更
trit-vcs claims add --central ./central --id c2 --owner qoder:s1 --path tests --sign-key ~/.trit/keys/author.key
trit-vcs claims release --central ./central --id c2 --owner qoder:s1 --sign-key ~/.trit/keys/author.key
trit-vcs policy set --owner qoder:admin --require-signed-claims
```

- `add` 只写合法路径（相对、无 `..`，反斜杠归一成 `/`）；别的 owner 在效且相交 ⇒ `claims_conflict` 并点名。
- 同一 id + 同一 owner 是续期；同一 id 换 owner ⇒ `claims_id_taken`；`release` 只有 owner 本人能做。
- 单写者：`claims.lock`（`create_new`），抢不到报 `claims_locked`，不静默覆盖。
- `--sign-key` 要求钥匙在操作开始前已经由 `key add/rotate` 写入信任表、principal 等于 owner、
  角色为 `author`，且从 `op_begin` 到成功 `op_result` 之间没有被吊销或轮换；签名绑定
  `op_begin` 哈希、完整 `ClaimSpec`、认领事件的实际操作前后状态、key_id/principal/owner 和签名时间，
  并核对 `op_result.state_after`，落 `claim_signature` sidecar，不改 `claims.json` 形状。
  `--require-signed-claims` 开启后，新的 add/release 必须签名；历史未签名事件仍保持可审计。

## 仓库策略变更

门禁开关也走受审计的写入，不再靠手改 `policy.json` 留不下记录：

```sh
trit-vcs policy --json
trit-vcs policy set --owner qoder:s1 --require-witness --require-intent --require-signed-claims --require-signed-witness --require-signed-policy --policy-threshold 2 --policy-role auditor --policy-role release --sign-key ~/.trit/keys/auditor.key --sign-key ~/.trit/keys/release.key --json
```

`policy set` 的语义是**整份替换**：没带的开关归 false，不沿用旧 true。每次变更落 `op_begin` +
`policy` + `op_result`，新事件带 `schema: trit-policy-v2`（默认只有 `auditor` 角色）或
`trit-policy-v3`（自定义角色集合）、`session`、五个开关、`policy_threshold`、`policy_roles`、
`previous_policy_hash`、`policy_hash`、`state_before`/`state_after`；版本化事件缺 `require_signed_claims` /
`require_signed_witness` 或显式非布尔值都会判红，并在重放时按强制签名处理；无该字段的旧事件仍按关闭处理。
`--sign-key FILE` 可重复，每把 key 用 Ed25519 签旧/新摘要、五个开关、阈值、角色集合、session、时间与自己的
key_id；事件记 `algorithm` 与 `signatures[]`（每项 `key_id`/`signature`/`signed_at_ms`）。`v1`/`v2`
单签与阈值多签事件仍可审计。
`require_signed_policy` 打开后，后续策略变更必须签名，开启这条的事件自身也必须签名；签名数必须达到
当前与新策略阈值的较大者，并且覆盖当前与新策略要求的**并集**角色，每个角色至少一把不同 key。
`--policy-role` 只支持 `auditor`/`release`，可重复，`policy_threshold` 必须不小于角色数。调低阈值或删除
角色也必须先满足旧阈值/旧角色，不能单钥把 3-of-N 或多角色策略降成单签；重复 key 报
`policy_signature_duplicate`，有效签名不足报 `policy_signature_insufficient`，角色未被覆盖报
`policy_role_missing`。审计验信任表、公钥指纹、签名时点吊销、角色、每份规范载荷和
`previous_policy_hash` 链。`require_signed_witness` 开启后，新提交必须先带 witness，普通 `admit` 也会要求
有效 attestation。绕过 CLI 直接改文件会被 `audit` 的 `state_drift`、`op_state_gap` 或
`policy_bad`/`policy_unsigned` 抓出来。

信任表也走同一套写前协议（表里存公钥/主体/角色；实际验签由下面的 `signing` 层负责）：

```sh
trit-vcs key add --key-id ed25519:<指纹> --principal qoder:s1 --role author --owner qoder:s1
trit-vcs key revoke --key-id ed25519:<指纹> --reason "离职" --owner qoder:s1
trit-vcs key rotate --old-key-file old.key --new-key-file new.key --reason "年度轮换" --owner qoder:s1
trit-vcs key list --json
```

`key add/revoke/rotate` 落 `op_begin` + `key` + `op_result`；`keys.json` 存在时其原始字节进入
`state_digest`，手改信任表会报 `state_drift`。重复 key、未知 key、已吊销 key 明确拒绝。
`rotate` 要求旧钥和新钥对同一份 `trit-key-rotate-v1` 声明各签一次；旧记录按 `revoked_at_ms` 吊销，
新记录继承 principal/role 并记 `rotated_from`。两个签名只证明两把私钥都参与，不把 `keys.json`
本身变成可信根。

Ed25519 提交签名（私钥不出仓、不进事件）：

```sh
trit-vcs key init --out ~/.trit/keys/author.key --json
trit-vcs key add --key-file ~/.trit/keys/author.key --principal qoder:s1 --role author --owner qoder:s1
trit-vcs commit -m "..." --owner qoder:s1 --sign-key ~/.trit/keys/author.key
```

`commit --sign-key` 签提交对象字节，落 `signature` 事件（commit/key_id/algorithm/signature/signed_at_ms）；
`audit status` 用信任表公钥逐条 `verify_strict`，签名坏报 `signature_invalid`，未信任报 `signer_untrusted`，
吊销后签的报 `signer_revoked`。签名是 sidecar，不改变提交 id。

Witness 签名使用独立域 `trit-attestation-v1`，不改 witness 或提交对象：

```sh
trit-vcs key add --key-file ~/.trit/keys/witness.key --principal qoder:s1 --role author --owner qoder:s1
trit-vcs attest <提交id> --witness witness.json --key-file ~/.trit/keys/witness.key --owner qoder:s1 --json
trit-vcs admit <提交id> --witness witness.json --signed
```

签者角色可为 `author`/`auditor`/`release`；签名绑定提交 id、原始 witness 摘要、树、实际第一父树、
key_id、会话与签名时间。旧 witness 可不声明 `predicate.base`，但一旦声明就必须与真实父树一致。
默认 `admit` 保持未签名兼容；`--signed`、MCP `admit({signed:true})` 或策略 `require_signed_witness`
要求有效 attestation。严格策略下 MCP 即使省略 `signed` 也按已签名准入，并返回 `signed:true` 与
`attestation`。审计检查事件/对象一致性、操作收口、重复 sidecar、信任成员、公钥指纹、角色、
信任加入时间、吊销与 Ed25519 签名；attestation 的 `state_before`/`state_after` 必须分别等于
`op_begin`/`op_result`，严格策略下的无 witness 提交也判红；吊销只追溯
`signed_at_ms > revoked_at_ms` 的签名。

认领签名使用独立域 `trit-claim-sign-v1`：`claims add/release --sign-key` 签 action、`op_begin` 哈希、
完整 `ClaimSpec`、操作前后状态、key_id/principal/owner 和签名时间，落 `claim_signature` 事件。
`audit` 重建同一声明并核对事件顺序、成功收口、信任/角色/吊销与 Ed25519 签名；授权按操作时点重放，
不信任签名者自报的 `signed_at_ms`：key 必须在 `op_begin` 前已有 `key add/rotate` 信任事件，且在
`op_begin` 到成功 `op_result` 之间不能被吊销或轮换；签名的 `state_after` 必须同时等于认领事件和
`op_result` 的状态。带公钥的 `key add` 新事件记录公钥，旧事件缺公钥时才回退到最终 `keys.json`，两者不一致仍拒绝。
`audit` 按事件重放 `require_signed_claims` 策略，缺该字段的旧策略事件按关闭处理；新
`trit-policy-v1`/`trit-policy-v2`/`trit-policy-v3` 事件缺字段则判红并按开启处理，同时要求标记为已签的认领事件在收口前确有 sidecar。
坏签名、换操作、换认领字段、换状态、重复签名、缺 sidecar、绕过当时策略或授权时点不符分别报
`claim_signature_invalid` / `claim_signature_operation` / `claim_signature_bad` /
`claim_signature_missing` / `claim_signature_untrusted` / `claim_signature_revoked`。
策略重放不是独立信任根：`require_signed_policy` 未开启时，`policy` 事件仍可不签名；开启后也必须由
信任表里达到阈值数量、并覆盖 `policy_roles` 中每个角色的不同 key 签名（当前角色集合只开放
`auditor`/`release`，支持 1..16 的阈值与每个角色至少一把 key；尚不支持任意角色、顺序审批或外部审批系统）。
能重写整条 journal 与状态、并绕过外部签名检查点/锚的攻击者仍可绕过这段历史，需要保留的签名检查点/文件锚才能把它钉住。

签名检查点 v0（仓内 Merkle + 检查点链）与文件锚 v0：

```sh
trit-vcs key add --key-file ~/.trit/keys/auditor.key --principal qoder:audit --role auditor --owner qoder:audit
trit-vcs audit checkpoint --key-file ~/.trit/keys/auditor.key --owner qoder:audit --json
trit-vcs audit proof --checkpoint <检查点事件 seq> --event <事件 seq> --json
trit-vcs audit consistency --from <旧检查点事件 seq> --to <新检查点事件 seq> --out consistency.json --json
trit-vcs audit verify-consistency --from <旧检查点事件 seq> --to <新检查点事件 seq> --proof consistency.json --json
trit-vcs audit anchor --checkpoint <检查点事件 seq> --out anchor.json --json
trit-vcs audit verify-anchor --anchor anchor.json --json
trit-vcs audit external-anchor --checkpoint <检查点事件 seq> --key-file external.key --anchor-public-key <仓外独立公钥hex> --out external-anchor.json --json
trit-vcs audit verify-external-anchor --anchor external-anchor.json --anchor-public-key <仓外独立公钥hex> --json
trit-vcs audit verify --anchor anchor.json --json
```

`audit checkpoint` 把包含当前 `op_begin`、但不含 `checkpoint` 事件本身的事件前缀做成 Merkle 根，记录
`height`、`head`、`previous`、`key_id` 和签名；下一个检查点用 `previous` 接住上一个检查点事件哈希。审计重算前缀根、
核对高度/前一条检查点、用信任表公钥验签，坏根、坏链、坏签名分别报
`checkpoint_merkle_mismatch` / `checkpoint_chain_mismatch` / `checkpoint_signature_invalid`。
`audit proof` 生成某条事件的 Merkle inclusion proof（兄弟路径），严格核对叶数、事件下标和每层路径，
拒绝幽灵叶、错叶数或错路径长度。导出文件锚前也会先核对检查点确实匹配当前仓库前缀；签名正确但
`head`/`previous`/Merkle 根对不上的检查点不会被落成锚。

`audit consistency` 针对现有“奇数末节点复制”的 Merkle 树生成旧→新前缀一致性证明；验证器严格核对
节点坐标并独立重算旧根与新根，不接受额外、缺失、重复或换位的节点。规模测试里 1 万叶、旧前缀
4,321 叶的证明少于 64 个节点。`--out` 用 `create_new`，已存在就拒绝，不静默覆盖。

`audit anchor` 把完整检查点事件包成 `{"schema":1,"event":...}` 文件。`verify-anchor` 复核事件哈希、
检查点字段与签名、签者信任/角色/吊销时间，再要求仓库同高事件完全一致，重算锚定前缀的
`head`/`previous`/Merkle 根，并验证它到较新检查点的一致性；`audit verify --anchor` 则把同一检查
接在完整审计报告后面。坏锚会让 JSON 报告带具体 `anchor_*` kind 并非零退出。

`audit external-anchor` 使用单独的 `trit-external-anchor-v1`：外部私钥必须与 `--anchor-public-key`
是同一把钥，签名覆盖检查点事件哈希、高度、head、Merkle 根、previous、外部 key_id 与签名时间。
`verify-external-anchor` 只认调用方明确传入的公钥，不读取仓内信任表；导出前和验证时都重算当前仓库前缀，
较新检查点必须构成一致扩展。输出文件同样拒绝覆盖。**公钥必须从仓库外的信任渠道取得并核对指纹**；
把仓库里的 `keys.json` 当外部公钥来源不构成独立性。

**边界要说清**：文件锚能发现“保留的锚之后被换链或删到锚高以下”，也能在保留较新锚时发现它之后
被删尾；但只有旧锚时，较短而一致的前缀仍是合法扩展，无法证明从未见过的后续事件不存在。锚必须由
调用方放到独立保管位置；同一台机器/同一管理域里的副本不构成抗整机篡改的外部信任根。独立外锚提供
“只认仓外公钥”的密码学边界，但真实独立性仍取决于外部密钥保管与部署；它不是透明日志、CA 或可信
时间戳服务。

## 离线审计包 TVAB

```sh
trit-vcs audit bundle --out repo.audit.tvab --anchor external-anchor.json --anchor-public-key <仓外公钥hex> --json
trit-vcs audit verify-bundle repo.audit.tvab --anchor-public-key <仓外公钥hex> --offline --json
```

TVAB v1 把完整 journal、HEAD/index/policy/claims/keys/refs、独立外锚，以及由日志事件和
HEAD/refs/index 独立推导出的**精确证据闭包**封成一个文件；未被任何状态或历史事件引用的孤立对象
不会进包。验证不需要已有仓库，不联网、不执行 witness 或 shell，而是在独占临时目录重建后核对
对象 ID 集合、复算状态摘要并重跑 L2 审计。导出要求检查点成功收口且审计全绿；`--out` 先写同目录
临时文件并 `sync_all`，再用不覆盖目标的原子链接发布。包内 `keys.json` 不是信任根，公钥仍必须从仓外
独立渠道钉住。

`sparse.json` 不进入历史状态摘要，也没有统一的已签重建规则，因此 TVAB v1 拒绝导入或从带 sparse
索引的仓库导出；先全量检出或运行 `trit-vcs sparse --clear`。完整 journal 可能含敏感
witness/receipt/认领内容，应按敏感材料保管。TVAB 只证明内部完整性、已锚前缀与状态一致，不证明签者
意图、可信时间、外部服务事实或真正的独立密钥保管。格式与上限见
[审计强度路线图](docs/AUDIT-STRENGTH.md)。

## 持久 sparse 索引

前缀 `pull` / `checkout` 会把范围与基准树写进 `.tritvcs/sparse.json`；下一次 `status` 只扫这个范围、
只跟这棵树比，范围外没检出不算删除。

```sh
trit-vcs pull main --central ./central --prefix gen/d00
trit-vcs status --json      # 干净：不会再报“范围外全被删了”
trit-vcs sparse --json      # 看当前范围与基准树
trit-vcs sparse --clear     # 清掉索引，退回全量判定
```

索引本身坏了/丢了只会退化成全量扫描，判定仍由对象库里的树保证；全量 `pull`/`checkout` 会自动清掉它。
`checkout --force` 实际放行未提交改动时，会把目标提交、前缀、脏改动数量/样本/完整集合摘要与前后状态落
`checkout` 事件（`trit-checkout-v1`），不静默覆盖。

## 复算

```sh
cargo run --release -p trit-vcs --example vcs_bench -- --central   # 存储 / status / 传输 / 合并 / 中央仓
cargo run --release -p trit-vcs --example agent_ergonomics         # 被拒负载与预检读数
cargo test                                                     # 21 个集成测试二进制 / 352 条 crate 测试（2026-11-27 实测，含 MSRV 1.88）
python scripts/test_surface.py                                 # 11 个单位 / 439 条测试 / 拦 0（2026-11-27 实测）
python scripts/mutation_check.py --pkg trit-vcs                    # 408 条登记（视图 pin 14 / 见证签名 13 / 检查点外锚 5 / 审计与 CLI/MCP 接线 8 / checkout 强制检出 3 / 请求来源 4 / deny 鉴权绑定 2 / 策略签名 4 / 策略签名角色 2 / 策略阈值多签 5 / 策略角色集合 9 / TVAB 20）
python scripts/mutation_check.py --pkg scripts/agent_claims.py --pkg scripts/change_policy.py --pkg scripts/ci_integrity.py --pkg scripts/docs_hygiene.py --pkg scripts/module_budget.py --pkg scripts/mutation_check.py --pkg scripts/repo_triage.py --pkg scripts/test_surface.py  # 脚本面 111 条
```

最后一条在本仓就能跑（`scripts/mutation_check.py` + `scripts/mutants/` 已随拆分一起搬过来，
路径口径改成新仓根：`src/…`）。门自身的自测面在镜像仓会 SKIP 掉只对单体仓成立的 7 条夹具，并大声打 SKIP。
变异登记的口径：每条 = 一个单点文本改动 + 点名的那条测试；测试必须变红，否则算存活。
408 条 Rust 变异全部声明最小 Cargo 目标，门会拒绝目标不存在
或过滤后零测试的条目，不再为每条变异重编整包。

## 库面

| 模块 | 一句话 |
|---|---|
| `store` / `chunk` / `hash` | 内容寻址的对象库、CDC 分块、BLAKE3 id |
| `bundle` | `TVBD` 包 + 过滤后的**树清单** + 范围内传输（export 与 pull 共用同一条路） |
| `claims` | 中央仓跨仓认领账本（单写者锁、冲突点名、`add/release/list/export`）；变更进哈希链，可选 Ed25519 sidecar 签名，审计按操作时点信任/吊销重建授权，支持强制签名策略 |
| `policy` | `policy set` 整份写入门禁开关，默认 `auditor` 角色写 `trit-policy-v2`，自定义角色集合写 `trit-policy-v3`；事件记 session/五个开关/`policy_threshold`/`policy_roles`/旧新摘要/前后状态与 `signatures[]`；`--sign-key` 可重复，`require_signed_policy` 要求达到当前与新阈值较大者、并覆盖当前/新角色并集的不同 key 签名；`--policy-role auditor/release` 可重复，`policy_threshold` 不得小于角色数；重复 key/不足/角色缺失分别报 `policy_signature_duplicate`/`policy_signature_insufficient`/`policy_role_missing`；`v1`/`v2` 事件保持兼容 |
| `keys` | 受审计信任表：`key add/revoke/rotate/list` 写 `.tritvcs/keys.json`，每次变更落 `key` 事件；带公钥的 add 由审计复验 Ed25519 形状、key_id 指纹和信任表一致，rotate 要求旧/新双签并记 `rotated_from` |
| `signing` | Ed25519 私钥文件、公钥指纹、提交/认领/见证声明签名；`commit/claims --sign-key` 与 `attest --key-file` 落 sidecar 事件，`audit` 用信任表公钥复验 |
| `attestation` | witness 的 Ed25519 sidecar：绑定提交/树/父树/原始见证/签者/会话，不改提交 id；支持严格策略、操作收口与重复/信任/吊销审计 |
| `checkpoint` | 事件前缀的 Merkle 根与签名检查点、旧→新 consistency proof、仓内文件锚和独立外锚；外部锚只认调用方钉住的仓外公钥 |
| `audit_bundle` | `TVAB` v1 单文件离线审计包：完整 journal/状态/独立推导的证据闭包 + 独立外锚；无仓、无网重建复验，拒绝覆盖，包内信任表不作信任根 |
| `central` | 命名 ref（`.tritvcs/refs/<name>`）、`publish`（闭包 + 全部父图 + 只准往前推）、`pull`（稀疏物化，脏则拒；全量落 HEAD+索引） |
| `net` / `wire` / `remote` | 自写 HTTP/1.1 子集 + Bearer token（常量时间比较）、`TVOB` 对象流（收端重算 BLAKE3）、跨机 publish/pull 的快进与完整性闸门；鉴权失败落 `auth` 事件 |
| `view` / `net::view` | `GET /v1/view` 的视图快照与 `from_height/from_root` consistency proof；客户端把上次成功视图记进 `trit-sync-v1`，下次同步前验旧前缀仍是新根的前缀，报 `remote_rollback`/`remote_equivocation`；`serve --view-key` 可签 Ed25519，客户端钉住签名者；`--no-pin` 显式降级 |
| `repo` / `journal` | 提交与查询、哈希链事件日志 |
| `preflight` | `commit()` 与 `preflight()` **共用**的唯一判决处 ⇒ 预检不会和真提交分叉 |
| `remediation` | 每条 `RepoError` → `kind` + 可执行命令（`--json` 下失败也是纯对象） |
| `tokens` | 一把 token 尺，CLI 与 MCP 共用 |
| `gate` / `witness` / `model` | 认领门（三态判决 + `ClaimSpec`）、提交见证（in-toto 形状，本体保持未签名，可选 attestation sidecar）、`Commit`/`HLC`/`Intent` |
| `worktree` / `merge` / `delta` | 扫描与稀疏物化、行级三路合并（CLI/MCP 走 `merge_audited` 留下 merge 事件）、前后缀 delta |
| `sparse` | 持久 sparse 索引：前缀 + 基准树；`status` 只扫范围内，全量检出自动清 |
| `git_bridge` / `techmap` / `status_cache` / `mcp` | Git 双向桥、技术标签索引、status 缓存、13 个工具的 stdio JSON-RPC |

## 形式化验证门（上游 K3 语义）

`verified-core` workflow 在每次 PR / push `main` 时：

1. 从 `Cargo.toml` 解析 `trit-core` 锁定的 git rev；
2. clone 主库并 checkout 该 rev，再取主库 `main` 的 `scripts/verify.py` 与 `verus/`；
3. 用 Verus 验证该 rev 的 K3 规格，并用 bridge 对拍**该 rev 的 `trit-core` 实现**。

这保证"本仓锁定的那个上游版本"满足主库证明过的 K3 代数律。验证的是锁定 rev，不是上游
最新 `main`：上游改语义而本仓没 bump rev 时门不会红；bump 之后的下一次 PR 会验证新 rev。
本地复跑见主库 `docs/engineering/VERIFICATION.md`。

## 这仓是怎么来的 / 依赖边界

从单体仓 `bfxh/trit` 的 `crates/trit-vcs` 用 `git subtree split` 搬出，**带着原来的提交历史**
（12 笔，从 M1 到写前预检那片）。三值裁决层 `trit-core` 与编排内核 `trit-orch` 不进这仓，
按 `Cargo.toml` 里的 `rev` 固定 pin 到 `bfxh/trit` —— 复制进来就等于把"哪个是正本"问错了对象。
改 pin 必须是一笔看得见的提交，不许跟着别人的 main 漂。

- 本机跑 `cargo` 需要一次性口径 `CARGO_NET_GIT_FETCH_WITH_CLI=true`（本机的全局 git 配置把
  `https://github.com/` 改写成 SSH 且挂着死代理；GitHub Actions 的默认 runner 没这个问题）。
- `scripts/agent_claims.py` 的认领表在单体仓里跟着 `trit-orch` 的测试夹具走；这仓用同名的
  `fixtures/claim_gate_cases.json` 兜住，Python 侧与 Rust 侧的语义对拍仍以 `bfxh/trit` 为准。

## 踩过的坑（留在仓里，免得再踩）

- 部分拉取曾按"整棵树"发货 ⇒ 单目录测出 49%，看着像实现错其实是判据没对齐；抽出 `bundle::manifest` 后
  export 与 pull 不可能分叉。**两处同源的坑要合并成一处，而不是各修一遍。**
- `--budget` 曾经"压进预算"是假的：丢掉 `truncation` 元数据自己占的额度才能压进去 ⇒ 现在元数据算进预算，
  且有一条"预算正好等于原读数就必须真丢一行"的判据钉住。
- 认领闸门与变异门两个后台任务在同一台机器上互抢 target 目录锁会一起挂死 ⇒ 门改成单实例 + 每条超时 +
  原子还原；超时的条目**判红而不是算抓住**。
- 拆掉"数组空了就 break"的守卫后测试永不返回，这类变异**没有断言能钉住** ⇒ 登记表里显式声明 `hang_secs`，
  单列 `HANG-KILL`，不计入"断言抓住"。
