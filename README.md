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
| 部分拉取 | 更强 | 200 文件 / 20 目录：全量 publish **162,854 B / 402 对象**，单目录 pull **8,226 B ⇒ 5.05%**；重复 pull 实传 **0 B**（22 个对象全跳过） |
| 传输断点 | 更强 | 截断的包再导入续传，结果**逐字节相同**；导入跳过目标已有对象 |
| 合并产物 | 更强 | 300 行单点争用：结构化冲突对象 **381 B** vs 两侧全文 7,780 B ⇒ **4.90%**；只差行尾空白的"伪冲突"**0** 条 |
| 写前准入 | Git 无对应面 | 未认领的提交默认拒；认领有 TTL、同名 id 判红；判决是三态（True/Unknown/False），"不知道"不等于"过" |
| 被拒之后 | 更强 | 每条判决附**能直接跑的下一步命令**：`unclaimed` 负载 329→455 元（3 条命令）、`claim_conflict` 18→88 元、`witness_required` 26→73 元 |
| 预检成本 | 有读数 | 60 文件 / 121 对象 / 9,400 字节的预检 **4.8 ms**，**写盘 0 个对象**（对象数、哈希链长度、HEAD 三样分别断言） |
| 审计 | 有面，P0 首批已落地（L2 对账；缺口与路线见 [`docs/AUDIT-STRENGTH.md`](docs/AUDIT-STRENGTH.md)） | 关键状态变更前写 `op_begin`、后写 `op_result`（含 `state_before`/`state_after`），提交门拒绝落 `gate`，策略变更走 `policy set` 并落 `policy`，合并落 `merge`，服务端鉴权失败落 `auth`，publish（含请求形状）、服务端 pull 与本地 pull 业务拒绝落 `deny`，信任表 add/revoke/rotate 落 `key`，`commit --sign-key` 落 `signature` 并由 `audit` 用信任表公钥验提交字节，`key rotate` 由旧/新两把钥双签声明并由 `audit` 复验，`audit checkpoint` 落签名 Merkle 检查点并复验前缀根/链；`trit-vcs audit status/verify` 把日志对账到 HEAD/refs/对象/认领快照/判据回执，漏账、状态漂移、开放操作会报；提交可带 `evidence`/`tags` |
| 时间 | 有面 | HLC（混合逻辑时钟）而非裸墙钟 |
| 上下文预算 | 有面 | `--budget <元>` 对所有读数生效：只丢整行、从尾部丢，`truncation` 元数据自己算进预算；ASCII 4 字 = 1 元、非 ASCII 4 元 |
| Git 生态 | 薄 | 双向桥只走第一父链：`git-export` / `git-import`（同步删除、防路径穿越、剥 `Trit-*` 尾注）；无 merge 图 / submodule / tag |

## 明确没做的（别当成已具备）

- **网络只有 v0：明文 HTTP、无 TLS、单 token**。`serve` 只该绑回环；跨机请套 SSH 隧道或反代，
  鉴权只是"同一个 Bearer token"，没有多租户、没有按路径授权，也没有证书。鉴权失败会落 `auth`
  事件（方法/路径/原因/401，不记 token）；publish 被业务规则拒绝或请求形状错误会落 `deny`（入口/原因/
  消息/请求细节，不记 token）；服务端 pull 缺 ref/未知 ref 也落 `deny`；客户端 pull 在应用回执时被拒
  （脏工作树、非快进等）也落本地 `deny`；全量 pull 在发请求前先检查工作树，脏就不下载对象；裸健康探针
  不记账，避免扫描器刷爆日志。
- `pull` 全量时会把 HEAD 与索引落到被拉的提交；**带 `--prefix` 时不动 HEAD**（否则范围外会被算成删除），
  两种形态都不删本地多余文件。
- 认领账本放在**中央仓目录**里，多个工作树共享；但账本**没有走网络**：远程克隆仍要能读到同一个
  `--central` 目录，或 `claims export` 后把快照传给 `--claims FILE`。
- v0 的 witness **不签名** ⇒ 防篡改、防绑错树，不防有人自己造一份。`commit --sign-key` 的
  Ed25519 签名是**事件 sidecar**：覆盖提交对象字节，不改变提交 id；claim/witness 仍未签名，
  检查点已有仓内签名 v0，但还没有仓外锚/一致性证明。
- sparse 索引只记**一个前缀**（没有 git 的多前缀/cone 模式）；换范围就等于换一次前缀 checkout。
- 三值逻辑只用在裁决处：全仓 `src` 实测三值 **4.5%**、二值 2.2%、中性 93.4%（`scripts/parity_scan.py`）。

## 网络 v0（跨机 + 鉴权）

没有读数的维度不写"更强"：这一节只写**边界**和**怎么用**。协议是自写的 HTTP/1.1 子集
（`GET`/`POST`、`Content-Length`、一请求一连接、拒 `chunked`），不引 HTTP 框架，理由和
"对象格式自己写"一样——多一层框架就多一层"它的行为谁保证"。

```sh
# 服务端：中央仓目录 + token 文件（token 不进 argv，16–256 字节）
trit-vcs serve --dir ./central --bind 127.0.0.1:7878 --token-file token.txt

# 客户端：发布 / 全量拉取（ref 只准快进；网络面不开放 force）
trit-vcs publish main --remote http://127.0.0.1:7878 --token-file token.txt
trit-vcs pull main --remote http://127.0.0.1:7878 --token-file token.txt
trit-vcs pull main --remote http://127.0.0.1:7878 --token-file token.txt --prefix gen/d00
```

- 服务端收发布时先逐块重算 BLAKE3 再入库，再查"tip 是提交、树闭包齐全、`merge_base(tip, current)==current`"，
  三条都过才移动 ref；退历史一律 409。
- 全量 `pull` 先判快进与暂存区脏，再物化，最后把 HEAD/索引落到被拉的提交；
  `--prefix` 只补范围内文件，不擅动 HEAD。
- 上限：对象数 100 万、单对象 32 MiB、body 256 MiB（`--max-body-mb` 可调）、连接 8（`--max-conn`）、
  读写超时 30 s（`--read-timeout`），超限回 413/503 而不是把线程堆爆。
- 已知边界：401 会先排空 ≤1 MiB 的请求体再回（更大的 body 直接关，可能被 RST）；服务端 `shutdown`
  只停 accept，不等处理线程。

## 跨仓认领账本

认领写在中央仓里（`.tritvcs/claims.json`），多个工作树共享同一张表；每次变更都追加进中央仓的
哈希链（`claim_add` / `claim_release`），不是只改一个 JSON 文件。

```sh
trit-vcs claims add --central ./central --id c1 --owner qoder:s1 --path src --ttl 900
trit-vcs claims list --central ./central --json
trit-vcs claims release --central ./central --id c1 --owner qoder:s1
trit-vcs claims export --central ./central --out claims.json
trit-vcs commit -m "…" --owner qoder:s1 --claims ./central/.tritvcs/claims.json
```

- `add` 只写合法路径（相对、无 `..`，反斜杠归一成 `/`）；别的 owner 在效且相交 ⇒ `claims_conflict` 并点名。
- 同一 id + 同一 owner 是续期；同一 id 换 owner ⇒ `claims_id_taken`；`release` 只有 owner 本人能做。
- 单写者：`claims.lock`（`create_new`），抢不到报 `claims_locked`，不静默覆盖。

## 仓库策略变更

门禁开关也走受审计的写入，不再靠手改 `policy.json` 留不下记录：

```sh
trit-vcs policy --json
trit-vcs policy set --owner qoder:s1 --require-witness --require-intent --json
```

`policy set` 的语义是**整份替换**：没带的开关归 false，不沿用旧 true。每次变更落 `op_begin` +
`policy` + `op_result`，事件里带 `session`、两个开关、`policy_hash`、`state_before`/`state_after`；
绕过 CLI 直接改文件会被 `audit` 的 `state_drift` 或下一次 `op_state_gap` 抓出来。

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

签名检查点 v0（仓内 Merkle + 检查点链，不是仓外锚）：

```sh
trit-vcs key add --key-file ~/.trit/keys/auditor.key --principal qoder:audit --role auditor --owner qoder:audit
trit-vcs audit checkpoint --key-file ~/.trit/keys/auditor.key --owner qoder:audit --json
```

`audit checkpoint` 把当前 `op_begin` 之前的事件前缀做成 Merkle 根，记录 `height`、`head`、
`previous`、`key_id` 和签名；下一个检查点用 `previous` 接住上一个检查点事件哈希。审计重算前缀根、
核对高度/前一条检查点、用信任表公钥验签，坏根、坏链、坏签名分别报
`checkpoint_merkle_mismatch` / `checkpoint_chain_mismatch` / `checkpoint_signature_invalid`。
**它不能防整条尾巴连检查点一起被删**：仓外锚、inclusion/consistency proof 仍未做。

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

## 复算

```sh
cargo run --release -p trit-vcs --example vcs_bench -- --central   # 存储 / status / 传输 / 合并 / 中央仓
cargo run --release -p trit-vcs --example agent_ergonomics         # 被拒负载与预检读数
cargo test                                                     # 16 个测试二进制 / 212 条（2026-11-24 实测）
python scripts/mutation_check.py --pkg trit-vcs                    # 150 条登记（网络 4 / 认领 2 / sparse 1）
```

最后一条在本仓就能跑（`scripts/mutation_check.py` + `scripts/mutants/` 已随拆分一起搬过来，
路径口径改成新仓根：`src/…`）。门自身的自测面在镜像仓会 SKIP 掉只对单体仓成立的 7 条夹具，并大声打 SKIP。
变异登记的口径：每条 = 一个单点文本改动 + 点名的那条测试；测试必须变红，否则算存活。

## 库面

| 模块 | 一句话 |
|---|---|
| `store` / `chunk` / `hash` | 内容寻址的对象库、CDC 分块、BLAKE3 id |
| `bundle` | `TVBD` 包 + 过滤后的**树清单** + 范围内传输（export 与 pull 共用同一条路） |
| `claims` | 中央仓里的跨仓认领账本（单写者锁、冲突点名、`add/release/list/export`，变更进哈希链） |
| `policy` | `policy set` 整份写入门禁开关，`policy` 事件记 session/开关/摘要/前后状态（手工改文件仍会被审计漂移抓到） |
| `keys` | 受审计信任表：`key add/revoke/rotate/list` 写 `.tritvcs/keys.json`，每次变更落 `key` 事件；带公钥的 add 要求 key_id 是公钥指纹，rotate 要求旧/新双签并记 `rotated_from` |
| `signing` | Ed25519 私钥文件、公钥指纹、提交签名；`commit --sign-key` 落 `signature` 事件，`audit` 用信任表公钥验提交字节 |
| `checkpoint` | 事件前缀的 Merkle 根与签名检查点；`audit checkpoint` 落 `checkpoint` 事件，`audit` 重算根、核 `previous` 链并验签 |
| `central` | 命名 ref（`.tritvcs/refs/<name>`）、`publish`（闭包 + 父链 + 只准往前推）、`pull`（稀疏物化，脏则拒；全量落 HEAD+索引） |
| `net` / `wire` / `remote` | 自写 HTTP/1.1 子集 + Bearer token（常量时间比较）、`TVOB` 对象流（收端重算 BLAKE3）、跨机 publish/pull 的快进与完整性闸门；鉴权失败落 `auth` 事件 |
| `repo` / `journal` | 提交与查询、哈希链事件日志 |
| `preflight` | `commit()` 与 `preflight()` **共用**的唯一判决处 ⇒ 预检不会和真提交分叉 |
| `remediation` | 每条 `RepoError` → `kind` + 可执行命令（`--json` 下失败也是纯对象） |
| `tokens` | 一把 token 尺，CLI 与 MCP 共用 |
| `gate` / `witness` / `model` | 认领门（三态判决 + `ClaimSpec`）、提交见证（in-toto 形状，v0 不签名）、`Commit`/`HLC`/`Intent` |
| `worktree` / `merge` / `delta` | 扫描与稀疏物化、行级三路合并（CLI/MCP 走 `merge_audited` 留下 merge 事件）、前后缀 delta |
| `sparse` | 持久 sparse 索引：前缀 + 基准树；`status` 只扫范围内，全量检出自动清 |
| `git_bridge` / `techmap` / `status_cache` / `mcp` | Git 双向桥、技术标签索引、status 缓存、13 个工具的 stdio JSON-RPC |

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
