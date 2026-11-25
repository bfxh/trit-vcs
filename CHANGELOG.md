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
  新增受审计信任表 v0：`trit-vcs key add/revoke/rotate/list` 读写 `.tritvcs/keys.json`，`add`/`revoke`/`rotate`
  走 `op_begin/op_result` 并落 `key` 事件（action/key_id/principal/role/session/keystore_hash/
  state_before/state_after）；重复 key、未知 key、已吊销 key 明确拒绝，不静默覆盖。`state_digest`
  在 `keys.json` 存在时纳入其原始字节：首次 add 的 state_before 是“文件不存在”的摘要，
  state_after 是“文件已存在”的摘要；之后手改/删 keyset 会被 `state_drift` 抓出。当前只做
  key 元数据信任（重复/未知/已吊销 key 拒绝）；信任表本身不做整表签名，验签由下面的签名层负责。
  新增 Ed25519 提交签名：`key init --out <私钥文件>` 生成 `trit-key-v1` JSON，`key add --key-file`
  只把公钥和 `ed25519:<BLAKE3(公钥)>` 指纹写进信任表；`commit --sign-key FILE` 对提交 canonical 对象字节
  做 `verify_strict` 可验的签名，落 `signature` 事件（commit/key_id/algorithm/signature/signed_at_ms/
  state_before/state_after），签名是 sidecar，不改变提交 id，也不改提交事件。`audit` 新增
  `signature_bad` / `signature_commit_missing` / `signer_untrusted` / `signer_revoked` / `signature_invalid`；
  吊销按 `signed_at_ms` 判断，吊销前的历史签名仍可验。私钥不进 argv、不进日志、不进仓库事件。
  新增密钥轮换：`key rotate --old-key-file --new-key-file --reason --owner` 让旧钥和新钥对同一份
  `trit-key-rotate-v1` 声明各签一次，旧记录按 `revoked_at_ms` 吊销，新记录继承 principal/role 并记
  `rotated_from`；`key` 事件新增 action=rotate、old_key_id、rotated_at_ms、双公钥、双签名。`audit`
  新增 `key_rotation_mismatch`，复验双签、指纹、吊销时间和信任表谱系；手改 `rotated_from` 或塞一条
  坏签名的 rotate 事件都会判红。轮换证明两把私钥参与，不把 `keys.json` 变成可信根。
  新增签名检查点 v0：`audit checkpoint --key-file --owner` 对包含当前 `op_begin`、但不含
  `checkpoint` 事件本身的事件前缀做 Merkle 根，`checkpoint` 事件记 height/head/merkle_root/previous/key_id/algorithm/signature/
  signed_at_ms；只有 auditor/release 角色能签。下一个检查点用 `previous` 接上一个检查点事件哈希。
  `audit` 新增 `checkpoint_bad` / `checkpoint_head_mismatch` / `checkpoint_merkle_mismatch` /
  `checkpoint_chain_mismatch` / `checkpoint_signature_invalid` / `checkpoint_untrusted` /
  `checkpoint_revoked` / `checkpoint_no_state` / `checkpoint_state_change`，重算前缀根、核高度和前驱、
  用信任表公钥验签。新增 `audit proof --checkpoint --event`：生成单事件 inclusion proof（兄弟路径）
  并复算。检查点仍在仓内 journal，单靠 inclusion proof 不能发现整条尾巴连检查点一起被删。
- 新增 witness 签名 attestation sidecar 与独立检查点外锚：`attest <commit> --witness FILE --key-file FILE
  --owner <宿主:会话id>` 用 `trit-attestation-v1` 绑定提交 id、原始 witness 摘要、树、实际第一父树、
  key_id、会话与签名时间；`admit --signed` 和 MCP `admit({signed:true})` 强制验签，普通 `admit` 默认
  保持未签名兼容。`policy set --require-signed-witness` 让新提交先要求 witness，并让普通准入要求有效
  attestation；旧无版本策略事件缺该字段按关闭处理，新版缺字段或显式非布尔值判红且重放按开启。
  签署与验签都限 `author`/`auditor`/`release`，拒绝签名早于信任加入时间或晚于吊销时间；同毫秒吊销不追溯。
  审计新增 `attestation_bad` /
  `attestation_revoked` / `attestation_invalid` / `attestation_duplicate` / `attestation_state_mismatch` /
  `attestation_missing`，复核事件/对象、op_begin 参数、成功 op_result、重复 sidecar、信任成员、公钥指纹、
  角色、信任时点、吊销、签名与提交/树/父树/witness 绑定；attestation 前后状态必须与 op_begin/op_result
  一致，严格策略下的无 witness 提交也判红。严格策略下提交后补签也被接受，不会因 sidecar
  晚于 commit 事件而误报。提交 id、Commit/witness 对象形状、bundle 与 journal 既有事件格式不变。
  `audit external-anchor` / `audit verify-external-anchor` 使用 `trit-external-anchor-v1`，由独立外部
  私钥签署检查点事件哈希、高度、head、Merkle 根、previous、外部 key_id 与签名时间；验证只认调用方
  明确传入且从仓外信任渠道钉住的公钥，不读仓内 `keys.json`，并重算当前前缀和到较新检查点的一致性。
  外锚文件拒绝覆盖；错误外部钥、坏签名、错摘要、删尾、换链与伪造较新检查点均拒绝。边界：仓内文件锚
  仍不是独立信任根；独立外锚的真实独立性取决于外部密钥保管与部署，不是透明日志、CA 或可信时间戳。
  测试：`src/attestation.rs` 9 条、`src/checkpoint/external.rs` 6 条、`tests/trust_cli.rs` 2 条、
  `tests/checkpoint_cli.rs` 新增 1 条，并补齐严格策略预检、审计旧策略兼容与共享状态锁接线断言；
  登记 26 条变异（签名绑定/摘要/信任时点/角色/重复/锁、严格策略、审计、CLI/MCP 与外锚信任边界）。
  本机分批复跑全部 281 条：280 条断言抓住、1 条登记死循环抓住，零存活、假杀、崩溃、超时、锁等待或无输出。
- 新增检查点间 consistency proof v0 与文件锚 v0：`audit consistency --from --to [--out]` 针对现有
  “奇数末节点复制”的 Merkle 树生成旧→新证明，`audit verify-consistency --from --to --proof` 严格
  核对 size/root/节点坐标并独立重算两侧根；坐标必须按 `(level, index)` 规范升序，重复、缺失、额外、
  越界、换位节点或坏兄弟哈希均拒绝。`audit anchor --checkpoint --out` 先核对检查点匹配当前仓库前缀，
  再把完整检查点事件包成 schema=1 文件；签名正确但 head/root 对不上的检查点拒绝导出。`audit verify-anchor` 与
  `audit verify --anchor` 复核事件哈希、检查点签名、信任/角色/吊销、同高当前事件、锚定前缀的
  head/previous/Merkle 根和到较新检查点的一致性；坏锚报 `anchor_bad` / `anchor_untrusted` / `anchor_revoked` /
  `anchor_signature_invalid` / `anchor_ahead` / `anchor_mismatch` / `anchor_consistency_failed`。
  证明与锚输出都用 `create_new` 拒绝覆盖。穷举 1–65 叶的所有旧前缀组合，并在 1 万叶、旧前缀
  4,321 叶上断言证明少于 64 个节点。文件锚只是调用方独立保管的已签检查点副本，不是独立 CA、
  透明日志或可信时间戳；只有旧锚时无法判断从未见过的后续事件是否存在，也不能抗仓库、锚副本和
  信任表被同一管理域整体改写。
- 新增认领变更 Ed25519 sidecar 签名 v0：`claims add/release --sign-key FILE` 与库面
  `add_signed/release_signed` 用 `trit-claim-sign-v1` 声明绑定 action、`op_begin` 哈希、完整
  `ClaimSpec`、操作前后状态、key_id/principal/owner 和签名时间，落独立 `claim_signature` 事件；
  `claims.json`、`ClaimSpec`、`ClaimSet` 与提交 id 均不改形状。写入前要求中央仓信任表成员、公钥/指纹
  匹配、`principal == owner`、角色 `author` 且未吊销；授权按操作时点重建，key 必须在 `op_begin` 前已有
  `key add/rotate` 信任事件，且到成功 `op_result` 前不能被吊销或轮换。
  `policy set --require-signed-claims` 可强制新的 add/release 必须签名，缺签名在写账本前报
  `claims_signature_required`；旧策略文件与历史未签名事件保持兼容。新 `policy` 事件带
  `schema: trit-policy-v1`，缺 `require_signed_claims` 会判红并按开启重放；旧无版本事件缺字段仍按关闭
  重放。`audit` 重建声明并核操作/事件顺序、完整认领字段、前后状态、成功收口、重复签名、操作时点信任/
  角色/吊销和 Ed25519 签名；签名 `state_after` 必须同时等于认领事件与 `op_result.state_after`。带公钥的
  `key add` 新事件记录公钥，历史事件缺公钥时才回退到最终 `keys.json`，两者不一致仍拒绝，新增
  `claim_signature_bad` / `claim_signature_missing` / `claim_signature_operation` /
  `claim_signature_untrusted` / `claim_signature_revoked` / `claim_signature_invalid`；审计按事件重放
  强制签名策略，并要求标记已签的认领事件在收口前确有 sidecar，不采信签名者回填的 `signed_at_ms`
  追溯授权。测试 `tests/claims_cli.rs` 从 1 条增至 7 条（签名流程与篡改矩阵拆入
  `tests/claims_cli/` 子模块，仍属同一测试二进制），覆盖签名 add/release、策略强制、
  历史未签名兼容、主体/角色/未信任/缺公钥/指纹错/操作前或操作中吊销/轮换、`op_result` 状态绑定，
  以及日志与信任表篡改。边界：签名证明中央仓账本变更历史，不认证导出的未签名 `ClaimSpec` 快照、
  跨机使用或本地信任表本身；`signed_at_ms` 仍是签名者自报时间，提交/检查点签名不能把它当可信时间戳，
  但认领授权已改为按事件顺序重建。`policy` 事件未签名，能删改它并重算整条 journal 的攻击者仍可绕过
  强制签名重放，需保留的签名检查点/文件锚才能钉住这段历史。
  测试：`src/audit.rs` / `src/audit/extra_tests.rs` 19 条、`tests/audit_cli.rs` 5 条、`tests/policy_cli.rs` 1 条、`tests/merge_cli.rs` 2 条、`tests/key_cli.rs` 4 条、`tests/checkpoint_cli.rs` 7 条、`src/keys.rs` 5 条、`src/checkpoint` 22 条、`src/signing.rs` 2 条（干净仓 L2、删日志 L0、坏 JSON 仍可审计、手改
  ref/HEAD 判红、accept 回执进链、开放操作/拒绝事件/失败操作改状态、策略变更进链与手改策略判红、合并事件与冲突后审计、错误 token 留 auth 事件、auth/deny 字段语义、非快进 publish 留 deny、publish 请求形状留 deny、脏工作树 pull 留 deny、服务端 pull 拒绝留 deny、key add/revoke 进链与手改 keyset 判红、重复/未知 key 拒绝、Ed25519 key init/add --key-file/commit --sign-key 进链与坏签名判红、key rotate 双签进链/旧钥吊销/新钥继承/二次轮换不回溯判红、抹 `rotated_from` 与坏轮换签名判红、checkpoint 双检查点链/高度与根/换根、换前驱、坏签名、无 op 链、Merkle proof 篡改判红、consistency 全前缀穷举/坏节点/坐标重排/空前缀伪造新根/大规模证明、文件锚坏签名/坏信封/同高换链/同摘要不同事件哈希/有效签名错前缀摘要/伪造新根/删尾/拒覆盖且原字节不变/陌生人/缺公钥/指纹错/角色错/签名时吊销/同毫秒不追溯/坏 JSON）；新增 40 条变异（原 19 条 + consistency 取错兄弟/折叠左右颠倒/不核兄弟坐标/空前缀不核新根/CLI 不验证明 + 锚不重算事件哈希/不验签/不核信任成员/不核公钥存在/不核指纹/不核角色/不核签名时吊销/同毫秒误追溯/不核同高事件/不核 head/不核 previous/不核 Merkle 根/不核锚定前缀摘要/不核旧到新一致性/输出覆盖已有文件 + `audit verify` 不因坏锚判红），本机 auth 2/2、policy/merge/deny/pull/keyset/signature/rotation/checkpoint/proof 各自抽跑均抓住，本轮新增 21 条 21/21 全抓；
  上一批 5 条写前/gate/失败状态变异仍保持 5/5，早先 3 条审计/锁变异仍全抓。随后认领签名新增
  29 条变异（签名门/CLI 策略/公钥指纹/主体/角色/吊销/声明绑定/事件引用/状态/成功收口/重复签名/
  缺 sidecar/策略重放/追溯信任/Ed25519 复验）；本机最小目标全量复跑 238 条：237 条断言抓住、
  1 条登记死循环抓住，零存活、假杀、超时、锁等待或无输出。本批尚未做：成功鉴权的 actor/request id。
- 新增单文件离线审计包 TVAB v1：`audit bundle --out ... --anchor ... --anchor-public-key ...` 导出完整
  journal、HEAD/index/policy/claims/keys/refs、独立外锚，以及由日志事件和当前状态独立推导的精确证据
  对象闭包；未被引用的孤立对象不进包。`audit verify-bundle ... --anchor-public-key ... --offline` 不打开
  现有仓库、不联网、不执行 witness 或 shell，先在独占临时目录重导对象并恢复封闭状态，再复验外锚、
  检查点成功收口、事件数、实际状态摘要、L2 审计和三方对象 ID 集合。merge 事件同时纳入结果树及
  ours/theirs/base 提交闭包，intent/回执/证明的 base 均按父树展开；`sparse.json` 不在历史状态摘要内，因此 TVAB v1 拒绝带 sparse 状态的
  导出与包内 sparse 部件。导出以同目录唯一临时文件写入并 `sync_all`，再用不覆盖目标的原子链接发布；
  包内 `keys.json` 只作历史状态，公钥仍须从仓外独立渠道钉住。TVAB 不改变冻结的 TVBD、提交、witness
  或 journal 格式，也不证明签者意图、可信时间、外部事实或外部私钥的真正独立保管。新增 11 条 CLI
  集成测试及容器、证据闭包、错误分类、检查点收口等库测试，登记 20 条 TVAB 变异，抽跑 20/20 全抓。
- 独立审查加固：inclusion proof 严格核叶数、事件下标、路径长度和每层节点存在性，幽灵叶与畸形路径
  拒绝；consistency proof 坐标必须规范升序且不重复；锚导出先核对当前仓库前缀；认领签名审计按
  `op_begin` 到 `op_result` 的日志顺序重建授权，拒绝操作前已吊销、操作中吊销或轮换，并核对签名状态与
  `op_result.state_after` 一致；认领、策略、信任表、提交签名、检查点、普通仓库状态写和独立审计事件
  写入共用 `claims.lock` 状态锁。公开 `append_audit`/`begin_operation`/`finish_operation` 也先抢锁，
  已持锁的内部调用走显式 `*_locked` 核心；`Repo::journal_mut` 收窄为 crate 内入口。拿不到锁报
  `state_locked` 并给出只读诊断命令，不教人删锁。新 `trit-policy-v1` 策略事件缺签名字段时审计判红且
  重放 fail-closed，显式非字符串或不受支持的 `schema` 也判红，旧无版本事件保持兼容。`key add`
  显式公钥复验 Ed25519 形状、指纹与信任表一致，历史缺字段或 `null` 仍兼容；对应四条变异均由
  断言抓住。对应变异覆盖证明边界/规范顺序/锚前缀/操作时点授权与结果
  状态/普通仓库写/公开审计入口/提交预检与中央仓 publish/pull/merge 共享状态锁，并修复旧 gate-denied
  变异锚点的歧义。提交预检与写入共用同一把状态锁；本地及服务端 publish/pull 在快进检查、物化与事件
  追加期间持有对应仓库的状态锁，merge 从 op_begin 到事件收口全程持有状态锁，避免检查点或其他写者
  插入快照与追加之间。
  281 条 Rust 变异全部声明最小 Cargo 目标（190 条库测试、91 条集成测试）；目标缺失或过滤后零测试
  直接判红，避免每条变异都重编整包。
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
  `src/accept.rs` 6 条单测 + `tests/accept_cli.rs` 4 条端到端（含"没给认领表 / 认领没覆盖 / 含元字符 ⇒
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
  `test_surface.py`（自测面防空转，递归扫描 `tests/**/*.rs` 子模块）、`docs_hygiene.py`（CHANGELOG 形状 + 盘符路径棘轮）、
  `ci_integrity.py`（workflow ↔ `required-checks.txt` ↔ GitHub 保护规则三方对账）。
  四道门共登记 32 条变异；搬运那轮 gates 面全量 101 条 ⇒ 99 断言抓住 + 2 崩溃抓住、存活 0。
  随后给 `ci_integrity`（+3）与 `repo_triage`（+2）补了认仓的刀，两道面复跑 6/6、8/8 全抓；当前脚本变异登记共 111 条。
- 治理面三件套（PR #3，squash `1ba95c3`）：`scripts/change_policy.py` 改动分级门（L0–L3 + 冻结契约行 +
  台账只防改薄）、`scripts/repo_triage.py` PR 分诊台、CI 并发取消 + 变异门按面并行。
  自测 28/28 与 22/22；两道新门登记 17 条变异，复跑全抓。

### Changed
- `CI` 的改动分级只在 PR 上执行；`push → main` 不再拿没有 PR 标签的事件重新判 L3，避免已人工批准的契约改动在合并后被重复判红。
- `trit-core` / `trit-orch` 的 git pin 从拆库提交 `2400fb9d` 显式抬到 `79542df8`（改 pin 单独一笔，不跟 main 漂）。
  取的是**升 MSRV 1.89 之前最后一笔 main**（`fc8fb6ea` 的父）：收进 `#440` 的 6 项底层安全修复
  （YARA 死循环 / pool UAF / `from_i8_unchecked` 健全性 / 同步越界 / 攻击链 DoS）、`#488` 的 5-trit 打包下沉、`#615` 的 data 面，
  同时把工具链地板留在 1.88（`cargo +1.88.0 test --workspace --locked` 全绿）。
  `trit-orch` 因此多一个 `trit-ops` 依赖；本仓 `src/` / `tests/` 零改动，194 条测试与四道门本地全绿。
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
